/*******************************************************************************
 * Copyright (c) 2015, 2018 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add duplicate record
 *                                                    detection functionality
 *                                                  - manage record sequence numbers
 *                                                    as Long values reducing the
 *                                                    need for type conversions
 *    Kai Hudalla (Bosch Software Innovations GmbH) - reduce method visibility to improve encapsulation,
 *                                                    synchronize methods to allow for concurrent access
 *    Kai Hudalla (Bosch Software Innovations GmbH) - provide access to peer's identity as a
 *                                                    java.security.Principal (fix 464812)
 *    Kai Hudalla (Bosch Software Innovations GmbH) - provide access to cipher suite's maximum
 *                                                    plaintext expansion
 *    Kai Hudalla (Bosch Software Innovations GmbH) - calculate max fragment size based on (P)MTU, explicit
 *                                                    value provided by peer and current write state
 *    Bosch Software Innovations GmbH - add accessors for current read/write state cipher names
 *                                      (fix GitHub issue #1)
 *    Achim Kraus (Bosch Software Innovations GmbH) - move creation of endpoint context
 *                                                    from DTLSConnector to DTLSSession
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - preserve creation time of session.
 *                                                    update time on set master secret.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add handshake parameter and
 *                                                    handshake parameter available to
 *                                                    process reordered handshake messages
 *    Achim Kraus (Bosch Software Innovations GmbH) - reset master secret, when
 *                                                    session resumption is refused.
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove unused isClient
 *                                                    add handshake timestamp for
 *                                                    session and endpoint context.
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace raw public key flags by
 *                                                    certificate types
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.Principal;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerName;
import org.eclipse.californium.scandium.util.ServerNames;
import org.eclipse.californium.scandium.util.ServerName.NameType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a DTLS session between two peers. Keeps track of the current and
 * pending read/write states, the current epoch and sequence number, etc.
 */
public final class DTLSSession implements Destroyable {

	/**
	 * The payload length of all headers around a DTLS handshake message payload.
	 * <ol>
	 * <li>12 bytes DTLS message header</li>
	 * <li>13 bytes DTLS record header</li>
	 * </ol>
	 * 25 bytes in total.
	 * 
	 * @since 2.5
	 */
	public static final int DTLS_HEADER_LENGTH = 
								HandshakeMessage.MESSAGE_HEADER_LENGTH_BYTES // 12 bytes DTLS handshake message headers
								+ Record.RECORD_HEADER_BYTES; // 13 bytes DTLS record headers

	/**
	 * The overall length of all headers around a DTLS handshake message payload.
	 * <ol>
	 * <li>12 bytes DTLS message header</li>
	 * <li>13 bytes DTLS record header</li>
	 * <li>8 bytes UDP header</li>
	 * <li>20 bytes IP header (Ipv4)</li>
	 * <li>36 bytes optional IP options</li>
	 * </ol>
	 * 89 bytes in total (including 36 bytes optional).
	 * @deprecated use {@link #DTLS_HEADER_LENGTH} and {@link RecordLayer#getMaxDatagramSize(boolean)} instead.
	 */
	@Deprecated
	public static final int HEADER_LENGTH = DTLS_HEADER_LENGTH + RecordLayer.IPV4_HEADER_LENGTH;

	private static final Logger LOGGER = LoggerFactory.getLogger(DTLSSession.class);
	private static final long RECEIVE_WINDOW_SIZE = 64;
	private static final long MAX_SEQUENCE_NO = 281474976710655L; // 2^48 - 1
	private static final int MAX_FRAGMENT_LENGTH_DEFAULT = 16384; // 2^14 bytes as defined by DTLS 1.2 spec, Section 4.1
	private static final int MASTER_SECRET_LENGTH = 48; // bytes

	/**
	 * This session's peer's IP address and port.
	 */
	private InetSocketAddress peer;
	private InetSocketAddress router;

	/**
	 * An arbitrary byte sequence chosen by the server to identify this session.
	 */
	private SessionId sessionIdentifier;

	/**
	 * Peer identity.
	 */
	private Principal peerIdentity;

	/**
	 * Record size limit.
	 * 
	 * @since 2.4
	 */
	private Integer recordSizeLimit;

	/**
	 * Maximum used fragment length.
	 */
	private int maxFragmentLength = MAX_FRAGMENT_LENGTH_DEFAULT;

	/**
	 * Specifies the pseudo-random function (PRF) used to generate keying
	 * material, the bulk data encryption algorithm (such as null, AES, etc.)
	 * and the MAC algorithm (such as HMAC-SHA1). It also defines cryptographic
	 * attributes such as the mac_length. (See TLS 1.2, Appendix A.6 for formal
	 * definition.)
	 */
	private CipherSuite cipherSuite = CipherSuite.TLS_NULL_WITH_NULL_NULL;

	/**
	 * Specifies the negotiated signature and hash algorithm to be used to sign
	 * the server key exchange message.
	 * 
	 * @since 2.3
	 */
	private SignatureAndHashAlgorithm signatureAndHashAlgorithm;

	private CompressionMethod compressionMethod = CompressionMethod.NULL;

	/**
	 * The 48-byte master secret shared by client and server to derive
	 * key material from.
	 */
	private SecretKey masterSecret = null;

	/**
	 * Connection id used for all outbound records.
	 */
	private ConnectionId writeConnectionId = null;
	/**
	 * Connection id used for all inbound records.
	 * 
	 * @since 2.5
	 */
	private ConnectionId readConnectionId = null;

	/**
	 * The <em>current read state</em> used for processing all inbound records.
	 */
	private DTLSConnectionState readState = DTLSConnectionState.NULL;

	/**
	 * The <em>current write state</em> used for processing all outbound records.
	 */
	private DTLSConnectionState writeState = DTLSConnectionState.NULL;

	private SecretKey clusterWriteMacKey = null;
	private SecretKey clusterReadMacKey = null;

	/**
	 * The current read epoch, incremented with every CHANGE_CIPHER_SPEC message received
	 */
	private int readEpoch = 0;
	/**
	 * The current read epoch, incremented with every CHANGE_CIPHER_SPEC message sent
	 */
	private int writeEpoch = 0;

	/**
	 * The next record sequence number per epoch.
	 */
	// We only need 2 values as we do not support DTLS re-negotiation.
	private long[] sequenceNumbers = new long[2];

	/**
	 * Save close_notify
	 */
	private int readEpochClosed;
	private long readSequenceNumberClosed;
	private boolean markedAsclosed;

	/**
	 * Indicates the type of certificate to send to the peer in a CERTIFICATE message.
	 */
	private CertificateType sendCertificateType = CertificateType.X_509;

	/**
	 * Indicates the type of certificate to expect from the peer in a CERTIFICATE message.
	 */
	private CertificateType receiveCertificateType = CertificateType.X_509;

	/**
	 * Indicates, that the handshake parameters are available.
	 * @see HandshakeParameter
	 */
	private boolean parameterAvailable = false;

	private volatile long receiveWindowUpperCurrent = -1;
	private volatile long receiveWindowLowerBoundary = 0;
	private volatile long receivedRecordsVector = 0;
	private long creationTime;
	private String hostName;
	private ServerNames serverNames;
	private boolean peerSupportsSni;

	private final String handshakeTimeTag;

	// Constructor ////////////////////////////////////////////////////

	/**
	 * Creates a session using default values for all fields.
	 *
	 * @param peerAddress
	 *            the remote address
	 */
	public DTLSSession(InetSocketAddress peerAddress) {
		this(peerAddress, 0, System.currentTimeMillis());
	}

	/**
	 * Creates a new session based on a given set of crypto params of another session
	 * that is to be resumed.
	 * <p>
	 * The newly created session will have its <em>pending state</em> initialized with
	 * the given crypto params so that it can be used during the abbreviated handshake
	 * used to resume the session.
	 *
	 * @param id The identifier of the session to be resumed.
	 * @param peerAddress
	 *            The IP address and port of the client that wants to resume the session.
	 * @param ticket
	 *            The crypto params to use for the abbreviated handshake
	 * @param initialSequenceNo
	 *            The initial record sequence number to start from
	 *            in epoch 0. When starting a new handshake with a client that
	 *            has successfully exchanged a cookie with the server, the
	 *            sequence number to use in the SERVER_HELLO record MUST be the same as
	 *            the one from the successfully validated CLIENT_HELLO record
	 *            (see <a href="http://tools.ietf.org/html/rfc6347#section-4.2.1">
	 *            section 4.2.1 of RFC 6347 (DTLS 1.2)</a> for details)
	 */
	public DTLSSession(SessionId id, InetSocketAddress peerAddress, SessionTicket ticket, long initialSequenceNo) {
		this(peerAddress, initialSequenceNo, ticket.getTimestamp());
		sessionIdentifier = id;
		masterSecret = SecretUtil.create(ticket.getMasterSecret());
		peerIdentity = ticket.getClientIdentity();
		cipherSuite = ticket.getCipherSuite();
		serverNames = ticket.getServerNames();
		compressionMethod = ticket.getCompressionMethod();
	}

	/**
	 * Creates a new session initialized with a given sequence number.
	 *
	 * @param peerAddress
	 *            the IP address and port of the peer this session is established with
	 * @param initialSequenceNo the initial record sequence number to start from
	 *            in epoch 0. When starting a new handshake with a client that
	 *            has successfully exchanged a cookie with the server, the
	 *            sequence number to use in the SERVER_HELLO record MUST be the same as
	 *            the one from the successfully validated CLIENT_HELLO record
	 *            (see <a href="http://tools.ietf.org/html/rfc6347#section-4.2.1">
	 *            section 4.2.1 of RFC 6347 (DTLS 1.2)</a> for details)
	 */
	public DTLSSession(InetSocketAddress peerAddress, long initialSequenceNo) {
		this(peerAddress, initialSequenceNo, System.currentTimeMillis());
	}

	/**
	 * Creates a new session initialized with a given sequence number.
	 *
	 * @param peerAddress
	 *            the IP address and port of the peer this session is established with
	 * @param initialSequenceNo the initial record sequence number to start from
	 *            in epoch 0. When starting a new handshake with a client that
	 *            has successfully exchanged a cookie with the server, the
	 *            sequence number to use in the SERVER_HELLO record MUST be the same as
	 *            the one from the successfully validated CLIENT_HELLO record
	 *            (see <a href="http://tools.ietf.org/html/rfc6347#section-4.2.1">
	 *            section 4.2.1 of RFC 6347 (DTLS 1.2)</a> for details)
	 * @param creationTime creation time of session. Maybe from previous session on resumption.
	 */
	public DTLSSession(InetSocketAddress peerAddress, long initialSequenceNo, long creationTime) {
		if (peerAddress == null) {
			throw new NullPointerException("Peer address must not be null");
		} else if (initialSequenceNo < 0 || initialSequenceNo > MAX_SEQUENCE_NO) {
			throw new IllegalArgumentException("Initial sequence number must be greater than 0 and less than 2^48");
		} else {
			this.creationTime = creationTime;
			this.handshakeTimeTag = Long.toString(System.currentTimeMillis());
			this.peer = peerAddress;
			this.sequenceNumbers[0]= initialSequenceNo;
		}
	}

	// Getters and Setters ////////////////////////////////////////////

	@Override
	public void destroy() throws DestroyFailedException {
		SecretUtil.destroy(masterSecret);
		masterSecret = null;
		SecretUtil.destroy(clusterWriteMacKey);
		clusterWriteMacKey = null;
		SecretUtil.destroy(clusterReadMacKey);
		clusterReadMacKey = null;
		if (readState != DTLSConnectionState.NULL) {
			readState.destroy();
			readState = DTLSConnectionState.NULL;
		}
		if (writeState != DTLSConnectionState.NULL) {
			writeState.destroy();
			writeState = DTLSConnectionState.NULL;
		}
	}

	@Override
	public boolean isDestroyed() {
		return SecretUtil.isDestroyed(masterSecret) && SecretUtil.isDestroyed(readState)
				&& SecretUtil.isDestroyed(writeState);
	}

	/**
	 * Gets this session's identifier.
	 * 
	 * @return the identifier or {@code null} if this session does not have an identifier (yet).
	 */
	public SessionId getSessionIdentifier() {
		return sessionIdentifier;
	}

	/**
	 * Sets the session identifier.
	 * 
	 * Resets the {@link #masterSecret}, if the session identifier is changed.
	 * 
	 * @param sessionIdentifier new session identifier
	 * @throws NullPointerException if the provided session identifier is
	 *             {@code null}
	 */
	void setSessionIdentifier(SessionId sessionIdentifier) {
		if (sessionIdentifier == null) {
			throw new NullPointerException("session identifier must not be null!");
		}
		if (!sessionIdentifier.equals(this.sessionIdentifier)) {
			// reset master secret
			SecretUtil.destroy(this.masterSecret);
			this.masterSecret = null;
			SecretUtil.destroy(clusterWriteMacKey);
			clusterWriteMacKey = null;
			SecretUtil.destroy(clusterReadMacKey);
			clusterReadMacKey = null;
			this.sessionIdentifier = sessionIdentifier;
		}
	}

	/**
	 * Get connection id for outbound records.
	 * 
	 * @return connection id for outbound records. {@code null}, if connection
	 *         id is not used by other peer
	 */
	public ConnectionId getWriteConnectionId() {
		return writeConnectionId;
	}

	/**
	 * Set connection id for outbound records.
	 * 
	 * @param connectionId connection id for outbound records
	 */
	void setWriteConnectionId(ConnectionId connectionId) {
		this.writeConnectionId = connectionId;
	}

	/**
	 * Get connection id for inbound records.
	 * 
	 * @return connection id for inbound records. {@code null}, if connection
	 *         id is not used for other peer
	 * @since 2.5
	 */
	public ConnectionId getReadConnectionId() {
		return readConnectionId;
	}

	/**
	 * Set connection id for inbound records.
	 * 
	 * @param connectionId connection id for inbound records
	 * @since 2.5
	 */
	void setReadConnectionId(ConnectionId connectionId) {
		this.readConnectionId = connectionId;
	}

	void setClusterMacKeys(SecretKey clusterWriteMacKey, SecretKey clusterReadMacKey  ) {
		this.clusterWriteMacKey = SecretUtil.create(clusterWriteMacKey);
		this.clusterReadMacKey = SecretUtil.create(clusterReadMacKey);
	}

	public Mac getThreadLocalClusterWriteMac() {
		if (clusterWriteMacKey != null) {
			try {
				Mac mac = cipherSuite.getThreadLocalPseudoRandomFunctionMac();
				mac.init(clusterWriteMacKey);
				return mac;
			} catch (InvalidKeyException e) {
				LOGGER.info("cluster write MAC failed!", e);
			}
		}
		return null;
	}

	public Mac getThreadLocalClusterReadMac() {
		if (clusterReadMacKey != null) {
			try {
				Mac mac = cipherSuite.getThreadLocalPseudoRandomFunctionMac();
				mac.init(clusterReadMacKey);
				return mac;
			} catch (InvalidKeyException e) {
				LOGGER.info("cluster read MAC failed!", e);
			}
		}
		return null;
	}

	/**
	 * System time of session creation in milliseconds.
	 * 
	 * @return session creation system time in milliseconds
	 * @see System#currentTimeMillis()
	 */
	public long getCreationTime() {
		return creationTime;
	}

	/**
	 * System time tag of last handshake.
	 * 
	 * @return system time in milliseconds as string of the last handshake
	 */
	public String getLastHandshakeTime() {
		return handshakeTimeTag;
	}

	/**
	 * Gets the (virtual) host name for the server that this session
	 * has been established for.
	 * 
	 * @return the host name or {@code null} if this session has not
	 *         been established for a virtual host.
	 * @see #getServerNames()
	 */
	public String getHostName() {
		return hostName;
	}

	/**
	 * Set the (virtual) host name for the server that this session has been
	 * established for.
	 * <p>
	 * Sets the {@link #setServerNames(ServerNames)} accordingly.
	 * 
	 * @param hostname the virtual host name at the peer (may be {@code null}).
	 */
	public void setHostName(String hostname) {
		this.serverNames = null;
		this.hostName = hostname;
		if (hostname != null) {
			this.serverNames = ServerNames
					.newInstance(ServerName.from(NameType.HOST_NAME, hostname.getBytes(ServerName.CHARSET)));
		}
	}

	/**
	 * Gets the server names for the server that this session
	 * has been established for.
	 * 
	 * @return server names, or {@code null}, if not used.
	 * @see #getHostName()
	 */
	public ServerNames getServerNames() {
		return serverNames;
	}

	/**
	 * Set the server names for the server that this session has been
	 * established for.
	 * <p>
	 * Sets the {@link #setHostName(String)} accordingly.
	 * 
	 * @param serverNames the server names (may be {@code null}).
	 */
	public void setServerNames(ServerNames serverNames) {
		this.hostName = null;
		this.serverNames = serverNames;
		if (serverNames != null) {
			ServerName serverName = serverNames.getServerName(NameType.HOST_NAME);
			if (serverName != null) {
				hostName = serverName.getNameAsString();
			}
		}
	}

	/**
	 * Checks whether the peer (the server) supports
	 * the Server Name Indication extension.
	 * 
	 * @return {@code true} if the server has included
	 *         an empty SNI extension in its SERVER_HELLO
	 *         message during handshake.
	 */
	public boolean isSniSupported() {
		return peerSupportsSni;
	}

	void setSniSupported(boolean flag) {
		this.peerSupportsSni = flag;
	}

	public DtlsEndpointContext getConnectionWriteContext() {
		return getConnectionContext(Integer.toString(writeEpoch));
	}

	public DtlsEndpointContext getConnectionReadContext() {
		return getConnectionContext(Integer.toString(readEpoch));
	}

	private DtlsEndpointContext getConnectionContext(String epoch) {
		String id = sessionIdentifier.isEmpty() ? "TIME:" + Long.toString(creationTime) : sessionIdentifier.toString();
		if (writeConnectionId != null && readConnectionId != null) {
			if (router != null) {
				return new DtlsEndpointContext(peer, hostName, peerIdentity, id, epoch, cipherSuite.name(),
						handshakeTimeTag, writeConnectionId.getAsString(), readConnectionId.getAsString(), "dtls-cid-router");
			} else {
				return new DtlsEndpointContext(peer, hostName, peerIdentity, id, epoch, cipherSuite.name(),
						handshakeTimeTag, writeConnectionId.getAsString(), readConnectionId.getAsString(), null);
			}
		} else {
			return new DtlsEndpointContext(peer, hostName, peerIdentity, id, epoch, cipherSuite.name(),
					handshakeTimeTag);
		}
	}

	/**
	 * Gets the cipher and MAC algorithm to be used for this session.
	 * <p>
	 * The value returned is part of the <em>pending connection state</em> which
	 * has been negotiated with the peer. This means that it is not in effect
	 * until the <em>pending</em> state becomes the <em>current</em> state using
	 * one of the {@link #setReadState(DTLSConnectionState)}
	 * or {@link #setWriteState(DTLSConnectionState)} methods.
	 * 
	 * @return the algorithms to be used
	 */
	public CipherSuite getCipherSuite() {
		return cipherSuite;
	}

	/**
	 * Sets the cipher and MAC algorithm to be used for this session.
	 * <p>
	 * The value set using this method becomes part of the <em>pending connection state</em>.
	 * This means that it will not be in effect until the <em>pending</em> state becomes the
	 * <em>current</em> state using one of the {@link #setReadState(DTLSConnectionState)}
	 * or {@link #setWriteState(DTLSConnectionState)} methods.
	 * 
	 * @param cipherSuite the algorithms to be used
	 * @throws IllegalArgumentException if the given cipher suite is <code>null</code>
	 * 	or {@link CipherSuite#TLS_NULL_WITH_NULL_NULL}
	 */
	void setCipherSuite(CipherSuite cipherSuite) {
		if (cipherSuite == null || CipherSuite.TLS_NULL_WITH_NULL_NULL == cipherSuite) {
			throw new IllegalArgumentException("Negotiated cipher suite must not be null");
		} else {
			this.cipherSuite = cipherSuite;
		}
	}

	/**
	 * Gets the algorithm to be used for reducing the size of <em>plaintext</em> data to
	 * be exchanged with a peer by means of TLS <em>APPLICATION_DATA</em> messages.
	 * <p>
	 * The value returned is part of the <em>pending connection state</em> which
	 * has been negotiated with the peer. This means that it is not in effect
	 * until the <em>pending</em> state becomes the <em>current</em> state using
	 * one of the {@link #setReadState(DTLSConnectionState)}
	 * or {@link #setWriteState(DTLSConnectionState)} methods.
	 * 
	 * @return the algorithm identifier
	 */
	CompressionMethod getCompressionMethod() {
		return compressionMethod;
	}

	/**
	 * Sets the algorithm to be used for reducing the size of <em>plaintext</em> data to
	 * be exchanged with a peer by means of TLS <em>APPLICATION_DATA</em> messages.
	 * <p>
	 * The value set using this method becomes part of the <em>pending connection state</em>.
	 * This means that it will not be in effect until the <em>pending</em> state becomes the
	 * <em>current</em> state using one of the {@link #setReadState(DTLSConnectionState)}
	 * or {@link #setWriteState(DTLSConnectionState)} methods.
	 * 
	 * @param compressionMethod the algorithm identifier
	 */
	void setCompressionMethod(CompressionMethod compressionMethod) {
		this.compressionMethod = compressionMethod;
	}

	/**
	 * Gets this session's current write epoch.
	 * 
	 * @return The epoch.
	 */
	public int getWriteEpoch() {
		return writeEpoch;
	}

	// tests only, currently not used
	void setWriteEpoch(int epoch) {
		if (epoch < 0) {
			throw new IllegalArgumentException("Write epoch must not be negative");
		} else {
			this.writeEpoch = epoch;
		}
	}

	/**
	 * Gets this session's current read epoch.
	 * 
	 * @return The epoch.
	 */
	public int getReadEpoch() {
		return readEpoch;
	}

	void setReadEpoch(int epoch) {
		if (epoch < 0) {
			throw new IllegalArgumentException("Read epoch must not be negative");
		} else {
			resetReceiveWindow();
			this.readEpoch = epoch;
		}
	}

	private void incrementReadEpoch() {
		resetReceiveWindow();
		this.readEpoch++;
	}

	private void incrementWriteEpoch() {
		this.writeEpoch++;
		// Sequence numbers are maintained separately for each epoch, with each
		// sequence_number initially being 0 for each epoch.
		this.sequenceNumbers[writeEpoch] =  0L;
	}

	/**
	 * Gets the smallest unused sequence number for outbound records
	 * for the current epoch.
	 * 
	 * @return the next sequence number
	 * @throws IllegalStateException if the maximum sequence number for the
	 *     epoch has been reached (2^48 - 1)
	 */
	public long getSequenceNumber() {
		return getSequenceNumber(writeEpoch);
	}

	/**
	 * Gets the smallest unused sequence number for outbound records
	 * for a given epoch.
	 * 
	 * @param epoch
	 *            the epoch for which to get the sequence number
	 * @return the next sequence number
	 * @throws IllegalStateException if the maximum sequence number for the
	 *     epoch has been reached (2^48 - 1)
	 */
	public long getSequenceNumber(int epoch) {
		long sequenceNumber = this.sequenceNumbers[epoch];
		if (sequenceNumber < MAX_SEQUENCE_NO) {
			this.sequenceNumbers[epoch] =  sequenceNumber + 1;
			return sequenceNumber;
		} else {
			// maximum sequence number has been reached
			// TODO force re-handshake with peer as mandated by DTLS spec
			// see section 4.1 of RFC 6347 (DTLS 1.2)
			throw new IllegalStateException("Maximum sequence number for epoch has been reached");
		}
	}

	/**
	 * Gets the current read state of the connection.
	 * <p>
	 * The information in the current read state is used to de-crypt
	 * messages received from a peer.
	 * See <a href="http://tools.ietf.org/html/rfc5246#section-6.1">
	 * RFC 5246 (TLS 1.2)</a> for details.
	 * <p>
	 * The cipher suite of the returned object will be {@link CipherSuite#TLS_NULL_WITH_NULL_NULL}
	 * if the connection's crypto params have not yet been negotiated.
	 * 
	 * @return The current read state.
	 */
	DTLSConnectionState getReadState() {
		return readState;
	}

	/**
	 * Sets the current read state of the connection.
	 * 
	 * The information in the current read state is used to de-crypt
	 * messages received from a peer.
	 * See <a href="http://tools.ietf.org/html/rfc5246#section-6.1">
	 * RFC 5246 (TLS 1.2)</a> for details.
	 * 
	 * The <em>pending</em> read state becomes the <em>current</em>
	 * read state whenever a <em>CHANGE_CIPHER_SPEC</em> message is
	 * received from a peer during a handshake.
	 * 
	 * This method also increments the read epoch.
	 * 
	 * @param readState the current read state
	 * @throws NullPointerException if the given state is <code>null</code>
	 */
	void setReadState(DTLSConnectionState readState) {
		if (readState == null) {
			throw new NullPointerException("Read state must not be null");
		}
		SecretUtil.destroy(this.readState);
		this.readState = readState;
		incrementReadEpoch();
		LOGGER.trace("Setting current read state to{}{}", StringUtil.lineSeparator(), readState);
	}

	/**
	 * Gets the name of the current read state's cipher suite.
	 * 
	 * @return the name.
	 */
	public String getReadStateCipher() {
		return readState.getCipherSuite().name();
	}

	/**
	 * Gets the current write state of the connection.
	 * <p>
	 * The information in the current write state is used to en-crypt
	 * messages sent to a peer.
	 * See <a href="http://tools.ietf.org/html/rfc5246#section-6.1">
	 * RFC 5246 (TLS 1.2)</a> for details.
	 * <p>
	 * The cipher suite of the returned object will be {@link CipherSuite#TLS_NULL_WITH_NULL_NULL}
	 * if the connection's crypto params have not yet been negotiated.
	 * 
	 * @return The current write state.
	 */
	DTLSConnectionState getWriteState() {
		return getWriteState(writeEpoch);
	}

	/**
	 * Get epoch specific write state.
	 * 
	 * @param epoch epoch of write state
	 * @return write state of provided epoch. {@code null}, if not available.
	 * @since 2.4
	 */
	DTLSConnectionState getWriteState(int epoch) {
		if (epoch == 0) {
			return DTLSConnectionState.NULL;
		} else {
			return writeState;
		}
	}

	/**
	 * Sets the current write state of the connection.
	 * 
	 * The information in the current write state is used to en-crypt
	 * messages sent to a peer.
	 * See <a href="http://tools.ietf.org/html/rfc5246#section-6.1">
	 * RFC 5246 (TLS 1.2)</a> for details.
	 * 
	 * The <em>pending</em> write state becomes the <em>current</em>
	 * write state whenever a <em>CHANGE_CIPHER_SPEC</em> message is
	 * received from a peer during a handshake.
	 * 
	 * This method also increments the write epoch and resets the session's
	 * sequence number counter to zero.
	 * 
	 * @param writeState the current write state
	 * @throws NullPointerException if the given state is <code>null</code>
	 */
	void setWriteState(DTLSConnectionState writeState) {
		if (writeState == null) {
			throw new NullPointerException("Write state must not be null");
		}
		SecretUtil.destroy(this.writeState);
		this.writeState = writeState;
		incrementWriteEpoch();
		LOGGER.trace("Setting current write state to{}{}", StringUtil.lineSeparator(), writeState);
	}

	/**
	 * Gets the name of the current write state's cipher suite.
	 * 
	 * @return the name.
	 */
	public String getWriteStateCipher() {
		return writeState.getCipherSuite().name();
	}

	/**
	 * Set parameter available. Enables {@link #getParameter()} to return the
	 * handshake parameter.
	 */
	public void setParameterAvailable() {
		parameterAvailable = true;
	}

	/**
	 * Return the handshake parameter, if set available.
	 * 
	 * @return the handshake parameter, or {@code null}, if
	 *         {@link #setParameterAvailable()} wasn't called before.
	 */
	public HandshakeParameter getParameter() {
		if (parameterAvailable) {
			return new HandshakeParameter(cipherSuite.getKeyExchange(), receiveCertificateType);
		}
		return null;
	}

	final KeyExchangeAlgorithm getKeyExchange() {
		if (cipherSuite == null) {
			throw new IllegalStateException("Cipher suite has not been set (yet)");
		} else {
			return cipherSuite.getKeyExchange();
		}
	}

	/**
	 * Gets the master secret used for resumption handshakes.
	 * 
	 * @return the secret, or {@code null}, if it has not yet been created or
	 *         the session doesn't support resumption
	 */
	SecretKey getMasterSecret() {
		return SecretUtil.create(masterSecret);
	}

	/**
	 * Sets the master secret to be use on session resumptions.
	 * 
	 * Once the master secret has been set, it cannot be changed without
	 * changing the session id ahead. If the session id is empty, the session
	 * doesn't support resumption and therefore the master secret is not set.
	 * 
	 * @param masterSecret the secret, copied on set
	 * @throws NullPointerException if the master secret is {@code null}
	 * @throws IllegalArgumentException if the secret is not exactly 48 bytes
	 *             (see
	 *             <a href="http://tools.ietf.org/html/rfc5246#section-8.1"> RFC
	 *             5246 (TLS 1.2), section 8.1</a>)
	 * @throws IllegalStateException if the master secret is already set
	 */
	void setMasterSecret(SecretKey masterSecret) {
		// don't overwrite the master secret, once it has been set in this session
		if (this.masterSecret == null) {
			if (!sessionIdentifier.isEmpty()) {
				if (masterSecret == null) {
					throw new NullPointerException("Master secret must not be null");
				}
				// get length
				byte[] secret = masterSecret.getEncoded();
				// clear secret immediately, only length is required
				Bytes.clear(secret);
				if (secret.length != MASTER_SECRET_LENGTH) {
					throw new IllegalArgumentException(
							String.format("Master secret must consist of of exactly %d bytes but has %d bytes",
									MASTER_SECRET_LENGTH, secret.length));
				}
				this.masterSecret = SecretUtil.create(masterSecret);
			}
			this.creationTime = System.currentTimeMillis();
		} else {
			throw new IllegalStateException("master secret already available!");
		}
	}

	/**
	 * Get maximum expansion of cipher suite.
	 * 
	 * @return maximum expansion of cipher suite.
	 * @see CipherSuite#getMaxCiphertextExpansion()
	 * @since 2.4
	 */
	public int getMaxCiphertextExpansion() {
		if (cipherSuite == null) {
			throw new IllegalStateException("Missing cipher suite.");
		}
		return cipherSuite.getMaxCiphertextExpansion();
	}

	/**
	 * Sets the maximum amount of unencrypted payload data that can be received and processed by
	 * this session's peer in a single DTLS record.
	 * <p>
	 * The value of this property corresponds directly to the <em>DTLSPlaintext.length</em> field
	 * as defined in <a href="http://tools.ietf.org/html/rfc6347#section-4.3.1">DTLS 1.2 spec,
	 * Section 4.3.1</a>.
	 * <p>
	 * The default value of this property is 2^14 bytes.
	 * <p>
	 * This method checks if a fragment of the given maximum length can be transmitted in a single
	 * datagram without the need for IP fragmentation. If not the given length is reduced to the
	 * maximum value for which this is possible.
	 * 
	 * @param length the maximum length in bytes
	 * @throws IllegalArgumentException if the given length is &lt; 0 or &gt; 2^14
	 */
	void setMaxFragmentLength(int length) {
		if (length < 0 || length > MAX_FRAGMENT_LENGTH_DEFAULT) {
			throw new IllegalArgumentException("Max. fragment length must be in range [0..." + MAX_FRAGMENT_LENGTH_DEFAULT + "]");
		} else {
			this.maxFragmentLength = length;
		}
	}

	/**
	 * Gets the maximum amount of unencrypted payload data that can be sent to this session's
	 * peer in a single DTLS record created under this session's <em>current write state</em>.
	 * <p>
	 * The value of this property serves as an upper boundary for the <em>DTLSPlaintext.length</em>
	 * field defined in <a href="http://tools.ietf.org/html/rfc6347#section-4.3.1">DTLS 1.2 spec,
	 * Section 4.3.1</a>. This means that an application can assume that any message containing at
	 * most as many bytes as indicated by this method, will be delivered to the peer in a single
	 * unfragmented IP datagram.
	 * 
	 * @return the maximum length in bytes
	 */
	public int getMaxFragmentLength() {
		return this.maxFragmentLength;
	}

	/**
	 * Sets the negotiated record size limit for this session.
	 * 
	 * @param limit record size limit
	 * @throws IllegalArgumentException if the record size limit is not in range
	 * @see RecordSizeLimitExtension#ensureInRange(int)
	 * @since 2.4
	 */
	void setRecordSizeLimit(int limit) {
		this.recordSizeLimit = RecordSizeLimitExtension.ensureInRange(limit);
	}

	/**
	 * Gets the negotiated record size limit
	 * 
	 * @return negotiated record size limit, or {@code null}, if not negotiated
	 * @since 2.4
	 */
	public Integer getRecordSizeLimit() {
		return this.recordSizeLimit;
	}

	/**
	 * Gets effective fragment limit.
	 * 
	 * Either {@link #recordSizeLimit}, if received, or
	 * {@link #maxFragmentLength}.
	 * 
	 * @return effective fragment limit
	 * @since 2.4
	 */
	public int getEffectiveFragmentLimit() {
		if (this.recordSizeLimit != null) {
			return this.recordSizeLimit;
		} else {
			return this.maxFragmentLength;
		}
	}

	CertificateType sendCertificateType() {
		return sendCertificateType;
	}

	void setSendCertificateType(CertificateType sendCertificateType) {
		this.sendCertificateType = sendCertificateType;
	}

	CertificateType receiveCertificateType() {
		return receiveCertificateType;
	}

	void setReceiveCertificateType(CertificateType receiveCertificateType) {
		this.receiveCertificateType = receiveCertificateType;
	}

	/**
	 * Gets the negotiated signature and hash algorithm to be used to sign the
	 * server key exchange message.
	 * 
	 * @return negotiated signature and hash algorithm
	 * 
	 * @since 2.3
	 */
	public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm() {
		return signatureAndHashAlgorithm;
	}

	/**
	 * Set the negotiated signature and hash algorithm to be used to sign the
	 * server key exchange message.
	 * 
	 * @param signatureAndHashAlgorithm negotiated signature and hash algorithm
	 * 
	 * @since 2.3
	 */
	void setSignatureAndHashAlgorithm(SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
		this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
	}

	/**
	 * Gets the IP address and socket of this session's peer.
	 * 
	 * @return The peer's address.
	 */
	public InetSocketAddress getPeer() {
		return peer;
	}

	public void setPeer(InetSocketAddress peer) {
		this.peer = peer;
	}

	/**
	 * Get router address.
	 * 
	 * @return router address. {@code null}, if no router is used.
	 * @since 2.5
	 */
	public InetSocketAddress getRouter() {
		return router;
	}

	/**
	 * Set router address.
	 * 
	 * @param router router address
	 * @since 2.5
	 */
	public void setRouter(InetSocketAddress router) {
		this.router = router;
	}

	/**
	 * Gets the authenticated peer's identity.
	 * 
	 * @return the identity or <code>null</code> if the peer has not been
	 *            authenticated
	 */
	public Principal getPeerIdentity() {
		return peerIdentity;
	}

	/**
	 * Sets the authenticated peer's identity.
	 * 
	 * @param the identity
	 * @throws NullPointerException if the identity is <code>null</code>
	 */
	void setPeerIdentity(Principal peerIdentity) {
		if (peerIdentity == null) {
			throw new NullPointerException("Peer identity must not be null");
		}
		this.peerIdentity = peerIdentity;
	}

	/**
	 * Checks whether a given record can be processed within the context of this
	 * session.
	 * 
	 * This is the case if
	 * <ul>
	 * <li>the record is from the same epoch as session's current read
	 * epoch</li>
	 * <li>the record has not been received before</li>
	 * <li>if marked as closed, the record's sequence number is not after the
	 * close notify's sequence number</li>
	 * </ul>
	 * 
	 * @param epoch the record's epoch
	 * @param sequenceNo the record's sequence number
	 * @param useWindowOnly {@code true} use only message window for filter. For
	 *            message too old for the message window {@code true} is
	 *            returned.
	 * @return {@code true} if the record satisfies the conditions above
	 * @since 2.3 support marked as closed
	 * @deprecated use {@link #isRecordProcessable(long, long, int)} instead
	 */
	@Deprecated
	public boolean isRecordProcessable(long epoch, long sequenceNo, boolean useWindowOnly) {
		return isRecordProcessable(epoch, sequenceNo, useWindowOnly ? -1 : 0);
	}

	/**
	 * Checks whether a given record can be processed within the context of this
	 * session.
	 * 
	 * This is the case if
	 * <ul>
	 * <li>the record is from the same epoch as session's current read
	 * epoch</li>
	 * <li>the record has not been received before</li>
	 * <li>if marked as closed, the record's sequence number is not after the
	 * close notify's sequence number</li>
	 * </ul>
	 * 
	 * @param epoch the record's epoch
	 * @param sequenceNo the record's sequence number
	 * @param useExtendedWindow this value will be subtracted from to lower
	 *            receive window boundary. A value of {@code -1} will set that
	 *            calculated value to {@code 0}. Messages between lower receive
	 *            window boundary and that calculated value will pass the
	 *            filter, for other messages the filter is applied.
	 * @return {@code true} if the record satisfies the conditions above
	 * @since 2.4
	 */
	public boolean isRecordProcessable(long epoch, long sequenceNo, int useExtendedWindow) {
		if (epoch < getReadEpoch()) {
			// record is from a previous epoch
			// discard record as proposed in DTLS 1.2
			// http://tools.ietf.org/html/rfc6347#section-4.1
			return false;
		} else if (epoch > getReadEpoch()) {
			// record is from future epoch
			// discard record as allowed in DTLS 1.2
			// http://tools.ietf.org/html/rfc6347#section-4.1
			return false;
		} else if (sequenceNo < receiveWindowLowerBoundary) {
			// record lies out of receive window's "left" edge discard
			if (useExtendedWindow < 0) {
				// within extended window => pass
				return true;
			} else {
				// within extended window? => pass
				return sequenceNo > receiveWindowLowerBoundary - useExtendedWindow;
			}
		} else if (markedAsclosed) {
			if (epoch > readEpochClosed) {
				// record after close
				return false;
			} else if (epoch == readEpochClosed && sequenceNo >= readSequenceNumberClosed) {
				// record after close
				return false;
			}
			// otherwise, check for duplicate
		}
		return !isDuplicate(sequenceNo);
	}

	/**
	 * Checks whether a given record has already been received during the
	 * current epoch.
	 * 
	 * The check is done based on a <em>sliding window</em> as described in
	 * <a href="http://tools.ietf.org/html/rfc6347#section-4.1.2.6">
	 * section 4.1.2.6 of the DTLS 1.2 spec</a>.
	 * 
	 * @param sequenceNo the record's sequence number
	 * @return <code>true</code> if the record has already been received
	 */
	boolean isDuplicate(long sequenceNo) {
		if (sequenceNo > receiveWindowUpperCurrent) {
			return false;
		} else {
			
			// determine (zero based) index of record's sequence number within receive window
			long idx = sequenceNo - receiveWindowLowerBoundary;
			// create bit mask for probing the bit representing position "idx" 
			long bitMask = 1L << idx;
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug(
						"Checking sequence no [{}] using bit mask [{}] against received records [{}] with lower boundary [{}]",
						sequenceNo, Long.toBinaryString(bitMask), Long.toBinaryString(receivedRecordsVector),
						receiveWindowLowerBoundary);
			}
			return (receivedRecordsVector & bitMask) == bitMask;
		}
	}

	/**
	 * Marks a record as having been received so that it can be detected as a
	 * duplicate if it is received again, e.g. if a client re-transmits the
	 * record because it runs into a timeout.
	 * 
	 * The record is marked as received only, if it belongs to this session's
	 * current read epoch as indicated by {@link #getReadEpoch()}.
	 * 
	 * @param epoch the record's epoch
	 * @param sequenceNo the record's sequence number
	 * @return {@code true}, if the epoch/sequenceNo is newer than the current
	 *         newest. {@code false}, if not.
	 */
	public boolean markRecordAsRead(long epoch, long sequenceNo) {
		if (epoch == getReadEpoch()) {
			boolean newest = sequenceNo > receiveWindowUpperCurrent;
			if (newest) {
				receiveWindowUpperCurrent = sequenceNo;
				long lowerBoundary = Math.max(0, sequenceNo - RECEIVE_WINDOW_SIZE + 1);
				long incr = lowerBoundary - receiveWindowLowerBoundary;
				if (incr > 0) {
					// slide receive window to the right
					receivedRecordsVector = receivedRecordsVector >>> incr;
					receiveWindowLowerBoundary = lowerBoundary;
				}
			}
			long bitMask = 1L << (sequenceNo - receiveWindowLowerBoundary);
			// mark sequence number as "received" in receive window
			receivedRecordsVector |= bitMask;
			LOGGER.debug("Updated receive window with sequence number [{}]: new upper boundary [{}], new bit vector [{}]",
					sequenceNo, receiveWindowUpperCurrent, Long.toBinaryString(receivedRecordsVector));
			return newest;
		} else {
			return epoch > getReadEpoch();
		}
	}

	/**
	 * Session is marked as close.
	 * 
	 * @return {@code true}, if marked as closed, {@code false}, otherwise.
	 * @since 2.3
	 */
	public boolean isMarkedAsClosed() {
		return markedAsclosed;
	}

	/**
	 * Mark as closed. If a session is marked as closed, no records should be
	 * sent and no received newer records should be processed.
	 * 
	 * @param epoch epoch of close notify
	 * @param sequenceNo sequence number of close notify
	 * @see #isMarkedAsClosed()
	 * @since 2.3
	 */
	public void markCloseNotiy(int epoch, long sequenceNo) {
		markedAsclosed = true;
		readEpochClosed = epoch;
		readSequenceNumberClosed = sequenceNo;
	}

	/**
	 * Re-initializes the receive window to detect duplicates for a new epoch.
	 * 
	 * The receive window is reset to sequence number zero and all
	 * information about received records is cleared.
	 */
	private void resetReceiveWindow() {
		receivedRecordsVector = 0;
		receiveWindowUpperCurrent = -1;
		receiveWindowLowerBoundary = 0;
	}

	/**
	 * Get a session ticket representing this session's <em>current</em>
	 * connection state.
	 * 
	 * @return The ticket. Or {@code null}, if the session id is empty and
	 *         doesn't support resumption.
	 * @throws IllegalStateException if this session does not have its current
	 *             connection state set yet.
	 */
	public SessionTicket getSessionTicket() {
		DTLSConnectionState writeState = getWriteState();
		if (!writeState.hasValidCipherSuite()) {
			throw new IllegalStateException("session has no valid crypto params, not fully negotiated yet?");
		}
		else if (sessionIdentifier.isEmpty()) {
			return null;
		}
		return new SessionTicket(
				ProtocolVersion.VERSION_DTLS_1_2,
				writeState.getCipherSuite(),
				writeState.getCompressionMethod(),
				masterSecret,
				getServerNames(),
				getPeerIdentity(),
				creationTime);
	}
}
