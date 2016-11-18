/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;

/**
 * Represents a DTLS session between two peers. Keeps track of the current and
 * pending read/write states, the current epoch and sequence number, etc.
 */
public final class DTLSSession {

	/**
	 * The overall length of all headers around a DTLS handshake message payload.
	 * <p>
	 * <ol>
	 * <li>12 bytes DTLS message header</li>
	 * <li>13 bytes DTLS record header</li>
	 * <li>8 bytes UDP header</li>
	 * <li>20 bytes IP header</li>
	 * </ol>
	 * <p>
	 * 53 bytes in total.
	 */
	public static final int HEADER_LENGTH = 12 // bytes DTLS message headers
								+ 13 // bytes DTLS record headers
								+ 8 // bytes UDP headers
								+ 20; // bytes IP headers
	private static final Logger LOGGER = Logger.getLogger(DTLSSession.class.getName());
	private static final long RECEIVE_WINDOW_SIZE = 64;
	private static final long MAX_SEQUENCE_NO = 281474976710655L; // 2^48 - 1
	private static final int MAX_FRAGMENT_LENGTH_DEFAULT = 16384; // 2^14 bytes as defined by DTLS 1.2 spec, Section 4.1
	private static final int MAX_TRANSMISSION_UNIT_DEFAULT = 1400; // a little less than standard ethernet MTU (1500)
	private static final int MASTER_SECRET_LENGTH = 48; // bytes

	/**
	 * This session's peer's IP address and port.
	 */
	private InetSocketAddress peer = null;

	/**
	 * An arbitrary byte sequence chosen by the server to identify this session.
	 */
	private SessionId sessionIdentifier = null;

	private Principal peerIdentity;

	private int maxFragmentLength = MAX_FRAGMENT_LENGTH_DEFAULT;
	private int maxTransmissionUnit = MAX_TRANSMISSION_UNIT_DEFAULT;

	/**
	 * Specifies the pseudo-random function (PRF) used to generate keying
	 * material, the bulk data encryption algorithm (such as null, AES, etc.)
	 * and the MAC algorithm (such as HMAC-SHA1). It also defines cryptographic
	 * attributes such as the mac_length. (See TLS 1.2, Appendix A.6 for formal
	 * definition.)
	 */
	private CipherSuite cipherSuite = CipherSuite.TLS_NULL_WITH_NULL_NULL;

	private CompressionMethod compressionMethod = CompressionMethod.NULL;

	/**
	 * The 48-byte master secret shared by client and server to derive
	 * key material from.
	 */
	private byte[] masterSecret = null;

	/**
	 * Indicates whether this object represents the <em>client</em> or the <em>server</em>
	 * side of the connection. The <em>client</em> side is the one initiating the handshake.
	 */
	private final boolean isClient;

	/**
	 * The <em>current read state</em> used for processing all inbound records.
	 */
	private DTLSConnectionState readState = new DTLSConnectionState();

	/**
	 * The <em>current write state</em> used for processing all outbound records.
	 */
	private DTLSConnectionState writeState = new DTLSConnectionState();

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
	private Map<Integer, Long> sequenceNumbers = new HashMap<>();

	/**
	 * Indicates the type of certificate to send to the peer in a CERTIFICATE message.
	 * If <code>true</code> send a RawPublicKey, a full X.509 certificate chain otherwise.
	 */
	private boolean sendRawPublicKey = false;

	/**
	 * Indicates the type of certificate to expect from the peer in a CERTIFICATE message.
	 * If <code>true</code> expect a RawPublicKey, a full X.509 certificate chain otherwise.
	 */
	private boolean receiveRawPublicKey = false;

	private volatile long receiveWindowUpperBoundary = RECEIVE_WINDOW_SIZE - 1;
	private volatile long receiveWindowLowerBoundary = 0;
	private volatile long receivedRecordsVector = 0;
	private long creationTime;

	// Constructor ////////////////////////////////////////////////////

	/**
	 * Creates a session using default values for all fields.
	 *
	 * @param peerAddress
	 *            the remote address
	 * @param isClient
	 *            whether the entity represents a client or a server.
	 */
	public DTLSSession(InetSocketAddress peerAddress, boolean isClient) {
		this(peerAddress, isClient, 0);
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
	public DTLSSession(SessionId id, InetSocketAddress peerAddress, SessionTicket ticket, long initialSequenceNo){
		this(peerAddress, false, initialSequenceNo);
		sessionIdentifier = id;
		masterSecret = ticket.getMasterSecret();
		peerIdentity = ticket.getClientIdentity();
		cipherSuite = ticket.getCipherSuite();
		compressionMethod = ticket.getCompressionMethod();
	}

	/**
	 * Creates a new session initialized with a given sequence number.
	 *
	 * @param peerAddress
	 *            the IP address and port of the peer this session is established with
	 * @param isClient
	 *            indicates whether this session has been established playing the client or server side
	 * @param initialSequenceNo the initial record sequence number to start from
	 *            in epoch 0. When starting a new handshake with a client that
	 *            has successfully exchanged a cookie with the server, the
	 *            sequence number to use in the SERVER_HELLO record MUST be the same as
	 *            the one from the successfully validated CLIENT_HELLO record
	 *            (see <a href="http://tools.ietf.org/html/rfc6347#section-4.2.1">
	 *            section 4.2.1 of RFC 6347 (DTLS 1.2)</a> for details)
	 */
	public DTLSSession(InetSocketAddress peerAddress, boolean isClient, long initialSequenceNo) {
		if (peerAddress == null) {
			throw new NullPointerException("Peer address must not be null");
		} else if (initialSequenceNo < 0 || initialSequenceNo > MAX_SEQUENCE_NO) {
			throw new IllegalArgumentException("Initial sequence number must be greater than 0 and less than 2^48");
		} else {
			this.creationTime = System.currentTimeMillis();
			this.peer = peerAddress;
			this.isClient = isClient;
			this.sequenceNumbers.put(0, initialSequenceNo);
		}
	}

	// Getters and Setters ////////////////////////////////////////////

	/**
	 * Gets this session's identifier.
	 * 
	 * @return the identifier or {@code null} if this session does not have an identifier (yet).
	 */
	public SessionId getSessionIdentifier() {
		return sessionIdentifier;
	}

	void setSessionIdentifier(SessionId sessionIdentifier) {
		this.sessionIdentifier = sessionIdentifier;
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
	CipherSuite getCipherSuite() {
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

	boolean isClient() {
		return this.isClient;
	}

	/**
	 * Gets this session's current write epoch.
	 * 
	 * @return The epoch.
	 */
	public int getWriteEpoch() {
		return writeEpoch;
	}

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

	private synchronized void incrementReadEpoch() {
		resetReceiveWindow();
		this.readEpoch++;
	}

	private synchronized void incrementWriteEpoch() {
		this.writeEpoch++;
		// Sequence numbers are maintained separately for each epoch, with each
		// sequence_number initially being 0 for each epoch.
		this.sequenceNumbers.put(writeEpoch, 0L);
	}

	/**
	 * Gets the smallest unused sequence number for outbound records
	 * for the current epoch.
	 * 
	 * @return the next sequence number
	 * @throws IllegalStateException if the maximum sequence number for the
	 *     epoch has been reached (2^48 - 1)
	 */
	public synchronized long getSequenceNumber() {
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
	public synchronized long getSequenceNumber(int epoch) {
		long sequenceNumber = this.sequenceNumbers.get(epoch);
		if (sequenceNumber < MAX_SEQUENCE_NO) {
			this.sequenceNumbers.put(epoch, sequenceNumber + 1);
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
	synchronized DTLSConnectionState getReadState() {
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
	synchronized void setReadState(DTLSConnectionState readState) {
		if (readState == null) {
			throw new NullPointerException("Read state must not be null");
		}
		this.readState = readState;
		incrementReadEpoch();
		LOGGER.log(Level.FINEST, "Setting current read state to\n{0}", readState);
	}

	/**
	 * Gets the name of the current read state's cipher suite.
	 * 
	 * @return the name.
	 */
	public synchronized String getReadStateCipher() {
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
	synchronized DTLSConnectionState getWriteState() {
		return writeState;
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
	synchronized void setWriteState(DTLSConnectionState writeState) {
		if (writeState == null) {
			throw new NullPointerException("Write state must not be null");
		}
		this.writeState = writeState;
		incrementWriteEpoch();
		// re-calculate maximum fragment length based on cipher suite from updated write state
		determineMaxFragmentLength(maxFragmentLength);
		LOGGER.log(Level.FINEST, "Setting current write state to\n{0}", writeState);
	}

	/**
	 * Gets the name of the current write state's cipher suite.
	 * 
	 * @return the name.
	 */
	synchronized public String getWriteStateCipher() {
		return writeState.getCipherSuite().name();
	}

	final KeyExchangeAlgorithm getKeyExchange() {
		if (cipherSuite == null) {
			throw new IllegalStateException("Cipher suite has not been set (yet)");
		} else {
			return cipherSuite.getKeyExchange();
		}
	}

	/**
	 * Gets the master secret used for encrypting application layer data
	 * exchanged in this session.
	 * 
	 * @return the secret or <code>null</code> if it has not yet been
	 * created
	 */
	byte[] getMasterSecret() {
		return masterSecret;
	}

	/**
	 * Sets the master secret to use for encrypting application layer data
	 * exchanged in this session.
	 * 
	 * Once the master secret has been set, it cannot be changed.
	 * 
	 * @param masterSecret the secret
	 * @throws NullPointerException if the secret is <code>null</code>
	 * @throws IllegalArgumentException if the secret is not exactly 48 bytes
	 * (see <a href="http://tools.ietf.org/html/rfc5246#section-8.1">
	 * RFC 5246 (TLS 1.2), section 8.1</a>) 
	 */
	void setMasterSecret(final byte[] masterSecret) {
		// don't overwrite the master secret, once it has been set in this session
		if (this.masterSecret == null) {
			if (masterSecret == null) {
				throw new NullPointerException("Master secret must not be null");
			} else if (masterSecret.length != MASTER_SECRET_LENGTH) {
				throw new IllegalArgumentException(String.format(
						"Master secret must consist of of exactly %d bytes but has %d bytes",
						MASTER_SECRET_LENGTH, masterSecret.length));
			} else {
				this.masterSecret = Arrays.copyOf(masterSecret, masterSecret.length);
			}
		}
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
			throw new IllegalArgumentException("Max. fragment length must be > 0 and < " + MAX_FRAGMENT_LENGTH_DEFAULT);
		} else {
			determineMaxFragmentLength(length);
		}
	}

	/**
	 * Gets the maximum size of a UDP datagram that can be sent to this session's peer without IP fragmentation.
	 *  
	 * @return the maximum size in bytes
	 */
	public int getMaxDatagramSize() {
		return this.maxFragmentLength + writeState.getMaxCiphertextExpansion() + HEADER_LENGTH;
	}

	/**
	 * Sets the maximum size of an IP packet that can be transmitted unfragmented to this
	 * session's peer (PMTU).
	 * <p>
	 * The given value is used to derive the maximum amount of unencrypted data that can
	 * be sent to the peer in a single DTLS record.
	 * 
	 * @param mtu the maximum size in bytes
	 * @throws IllegalArgumentException if the given value is &lt; 60
	 * @see #getMaxFragmentLength()
	 */
	void setMaxTransmissionUnit(int mtu) {
		if (mtu < 60) {
			throw new IllegalArgumentException("MTU must be at least 60 bytes");
		} else {
			LOGGER.log(Level.FINER, "Setting MTU for peer [{0}] to {1} bytes",
					new Object[]{peer, mtu});
			this.maxTransmissionUnit = mtu;
			determineMaxFragmentLength(mtu);
		}
	}

	private void determineMaxFragmentLength(int maxProcessableFragmentLength) {
		int maxDatagramSize = maxProcessableFragmentLength + writeState.getMaxCiphertextExpansion() + HEADER_LENGTH;
		if (maxDatagramSize <= maxTransmissionUnit) {
			this.maxFragmentLength = maxProcessableFragmentLength;
		} else {
			this.maxFragmentLength = maxTransmissionUnit - HEADER_LENGTH - writeState.getMaxCiphertextExpansion();
		}
		LOGGER.log(Level.FINER, "Setting maximum fragment length for peer [{0}] to {1} bytes",
				new Object[]{peer, this.maxFragmentLength});
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

	boolean sendRawPublicKey() {
		return sendRawPublicKey;
	}

	void setSendRawPublicKey(boolean sendRawPublicKey) {
		this.sendRawPublicKey = sendRawPublicKey;
	}

	boolean receiveRawPublicKey() {
		return receiveRawPublicKey;
	}

	void setReceiveRawPublicKey(boolean receiveRawPublicKey) {
		this.receiveRawPublicKey = receiveRawPublicKey;
	}

	/**
	 * Gets the IP address and socket of this session's peer.
	 * 
	 * @return The peer's address.
	 */
	public InetSocketAddress getPeer() {
		return peer;
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
	 * * Checks whether a given record can be processed within the context
	 * of this session.
	 * 
	 * This is the case if
	 * <ul>
	 * <li>the record is from the same epoch as session's current read epoch</li>
	 * <li>the record has not been received before</li>
	 * </ul>
	 *  
	 * @param epoch the record's epoch
	 * @param sequenceNo the record's sequence number
	 * @return <code>true</code> if the record satisfies the conditions above
	 */
	public boolean isRecordProcessable(long epoch, long sequenceNo) {
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
		} else {
			synchronized (this) {
				if (sequenceNo < receiveWindowLowerBoundary) {
					// record lies out of receive window's "left" edge
					// discard
					return false;
				} else {
					return !isDuplicate(sequenceNo);
				}
			}
		}
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
	synchronized boolean isDuplicate(long sequenceNo) {
		if (sequenceNo > receiveWindowUpperBoundary) {
			return false;
		} else {
			
			// determine (zero based) index of record's sequence number within receive window
			long idx = sequenceNo - receiveWindowLowerBoundary;
			// create bit mask for probing the bit representing position "idx" 
			long bitMask = 1L << idx;
			if (LOGGER.isLoggable(Level.FINER)) {
				LOGGER.log(Level.FINER,
						"Checking sequence no [{0}] using bit mask [{1}] against received records [{2}] with lower boundary [{3}]",
						new Object[]{sequenceNo, Long.toBinaryString(bitMask), Long.toBinaryString(receivedRecordsVector),
						receiveWindowLowerBoundary});
			}
			return (receivedRecordsVector & bitMask) == bitMask;
		}
	}

	/**
	 * Marks a record as having been received so that it can be detected
	 * as a duplicate if it is received again, e.g. if a client re-transmits
	 * the record because it runs into a timeout.
	 * 
	 * The record is marked as received only if it belongs to this session's
	 * current read epoch as indicated by {@link #getReadEpoch()}.
	 * 
	 * @param epoch the record's epoch
	 * @param sequenceNo the record's sequence number
	 */
	public synchronized void markRecordAsRead(long epoch, long sequenceNo) {

		if (epoch == getReadEpoch()) {
			if (sequenceNo > receiveWindowUpperBoundary) {
				long incr = sequenceNo - receiveWindowUpperBoundary;
				receiveWindowUpperBoundary = sequenceNo;
				// slide receive window to the right
				receivedRecordsVector = receivedRecordsVector >>> incr;
				receiveWindowLowerBoundary = Math.max(0, receiveWindowUpperBoundary - RECEIVE_WINDOW_SIZE + 1);
			}
			long bitMask = 1L << (sequenceNo - receiveWindowLowerBoundary);
			// mark sequence number as "received" in receive window
			receivedRecordsVector |= bitMask;
			LOGGER.log(Level.FINER, "Updated receive window with sequence number [{0}]: new upper boundary [{1}], new bit vector [{2}]",
					new Object[]{sequenceNo, receiveWindowUpperBoundary, Long.toBinaryString(receivedRecordsVector)});
		}
	}

	/**
	 * Re-initializes the receive window to detect duplicates for a new epoch.
	 * 
	 * The receive window is reset to sequence number zero and all
	 * information about received records is cleared.
	 */
	private synchronized void resetReceiveWindow() {
		receivedRecordsVector = 0;
		receiveWindowUpperBoundary = RECEIVE_WINDOW_SIZE - 1;
		receiveWindowLowerBoundary = 0;
	}

	/**
	 * Gets a session ticket representing this session's <em>current</em> connection state.
	 * 
	 * @return The ticket.
	 * @throws IllegalStateException if this session does not have its current connection state set yet.
	 */
	public SessionTicket getSessionTicket() {
		if (getWriteState().hasValidCipherSuite()) {
			return new SessionTicket(
					new ProtocolVersion(),
					getWriteState().getCipherSuite(),
					getWriteState().getCompressionMethod(),
					getMasterSecret(),
					getPeerIdentity(),
					System.currentTimeMillis());
		} else {
			throw new IllegalStateException("session has no valid crypto params, not fully negotiated yet?");
		}
	}
}
