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

import java.security.GeneralSecurityException;
import java.security.Principal;
import java.util.Objects;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.SerializationUtil;
import org.eclipse.californium.elements.util.WipAPI;
import org.eclipse.californium.scandium.auth.PrincipalSerializer;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction.Label;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.util.SecretSerializationUtil;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerName;
import org.eclipse.californium.scandium.util.ServerName.NameType;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * Represents a DTLS session between two peers.
 * 
 * Keeps track of the negotiated parameter.
 */
public final class DTLSSession implements Destroyable {

	// 2^14 bytes as defined by DTLS 1.2 spec, Section 4.1
	private static final int MAX_FRAGMENT_LENGTH_DEFAULT = 16384;

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

	/**
	 * Specifies the negotiated ec-group to be used for the ECDHE key exchange
	 * message.
	 * 
	 * @since 3.0
	 */
	private SupportedGroup ecGroup;

	private CompressionMethod compressionMethod = CompressionMethod.NULL;

	/**
	 * Use extended master secret.
	 * 
	 * See <a href="https://tools.ietf.org/html/rfc7627">RFC 7627</a>.
	 * 
	 * @since 3.0
	 */
	private boolean extendedMasterSecret;

	/**
	 * The 48-byte master secret shared by client and server to derive key
	 * material from. Only set for resumable sessions!
	 */
	private SecretKey masterSecret = null;

	/**
	 * Indicates the type of certificate to send to the peer in a CERTIFICATE
	 * message.
	 */
	private CertificateType sendCertificateType = CertificateType.X_509;

	/**
	 * Indicates the type of certificate to expect from the peer in a
	 * CERTIFICATE message.
	 */
	private CertificateType receiveCertificateType = CertificateType.X_509;

	private long creationTime;
	private String hostName;
	private ServerNames serverNames;
	private boolean peerSupportsSni;

	// Constructor ////////////////////////////////////////////////////

	/**
	 * Creates a session using default values for all fields.
	 */
	public DTLSSession() {
		creationTime = System.currentTimeMillis();
	}

	/**
	 * Creates a session using default values for all fields, except the
	 * {@link #hostName} and {@link #serverNames}.
	 * 
	 * @param hostname, or {@code null}, if not used.
	 * @see #setHostName(String)
	 * @since 3.0
	 */
	public DTLSSession(String hostname) {
		creationTime = System.currentTimeMillis();
		setHostName(hostname);
	}

	/**
	 * Creates a new session based on a given set of crypto parameter of another
	 * session that is to be resumed.
	 * <p>
	 * The newly created session will have its <em>pending state</em>
	 * initialized with the given crypto parameter so that it can be used during
	 * the abbreviated handshake used to resume the session.
	 *
	 * @param id The identifier of the session to be resumed.
	 * @param ticket The crypto parameter to use for the abbreviated handshake
	 */
	public DTLSSession(SessionId id, SessionTicket ticket) {
		creationTime = ticket.getTimestamp();
		sessionIdentifier = id;
		masterSecret = SecretUtil.create(ticket.getMasterSecret());
		peerIdentity = ticket.getClientIdentity();
		cipherSuite = ticket.getCipherSuite();
		compressionMethod = ticket.getCompressionMethod();
		extendedMasterSecret = ticket.useExtendedMasterSecret();
		setServerNames(ticket.getServerNames());
	}

	/**
	 * Creates a new session based on a given set of crypto parameter of another
	 * session that is to be resumed.
	 * 
	 * @param session session to resume
	 */
	public DTLSSession(DTLSSession session) {
		creationTime = session.getCreationTime();
		sessionIdentifier = session.getSessionIdentifier();
		masterSecret = session.getMasterSecret();
		peerIdentity = session.getPeerIdentity();
		cipherSuite = session.getCipherSuite();
		compressionMethod = session.getCompressionMethod();
		extendedMasterSecret = session.useExtendedMasterSecret();
		setServerNames(session.getServerNames());
	}

	// Getters and Setters ////////////////////////////////////////////

	@Override
	public void destroy() throws DestroyFailedException {
		SecretUtil.destroy(masterSecret);
		masterSecret = null;
		extendedMasterSecret = false;
		cipherSuite = CipherSuite.TLS_NULL_WITH_NULL_NULL;
		compressionMethod = CompressionMethod.NULL;
		signatureAndHashAlgorithm = null;
		ecGroup = null;
		peerIdentity = null;
		sendCertificateType = CertificateType.X_509;
		receiveCertificateType = CertificateType.X_509;
	}

	@Override
	public boolean isDestroyed() {
		return SecretUtil.isDestroyed(masterSecret);
	}

	/**
	 * Gets this session's identifier.
	 * 
	 * @return the identifier or {@code null} if this session does not have an
	 *         identifier (yet).
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
			this.sessionIdentifier = sessionIdentifier;
		} else {
			throw new IllegalArgumentException("no new session identifier?");
		}
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
	 * Gets the (virtual) host name for the server that this session has been
	 * established for.
	 * 
	 * @return the host name or {@code null} if this session has not been
	 *         established for a virtual host.
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
	 * Gets the server names for the server that this session has been
	 * established for.
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
	 * Checks whether the peer (the server) supports the Server Name Indication
	 * extension.
	 * 
	 * @return {@code true} if the server has included an empty SNI extension in
	 *         its SERVER_HELLO message during handshake.
	 */
	public boolean isSniSupported() {
		return peerSupportsSni;
	}

	/**
	 * Enable/disable SNI support.
	 * 
	 * @param flag {@code true} to enable, {@code false}, to disable.
	 */
	void setSniSupported(boolean flag) {
		this.peerSupportsSni = flag;
	}

	/**
	 * Add entries of DTLS session.
	 * 
	 * @param attributes attributes to add the entries
	 */
	public void addEndpintContext(MapBasedEndpointContext.Attributes attributes) {
		Bytes id = sessionIdentifier.isEmpty() ? new Bytes(("TIME:" + Long.toString(creationTime)).getBytes())
				: sessionIdentifier;
		attributes.add(DtlsEndpointContext.KEY_SESSION_ID, id);
		attributes.add(DtlsEndpointContext.KEY_CIPHER, cipherSuite.name());
	}

	/**
	 * Gets the cipher suite to be used for this session.
	 * <p>
	 * 
	 * @return the cipher suite to be used
	 */
	public CipherSuite getCipherSuite() {
		return cipherSuite;
	}

	/**
	 * Sets the cipher suite to be used for this session.
	 * <p>
	 * 
	 * @param cipherSuite the cipher suite to be used
	 * @throws IllegalArgumentException if the given cipher suite is
	 *             {@code null} or {@link CipherSuite#TLS_NULL_WITH_NULL_NULL}
	 */
	void setCipherSuite(CipherSuite cipherSuite) {
		if (cipherSuite == null || CipherSuite.TLS_NULL_WITH_NULL_NULL == cipherSuite) {
			throw new IllegalArgumentException("Negotiated cipher suite must not be null");
		} else {
			this.cipherSuite = cipherSuite;
		}
	}

	/**
	 * Gets the algorithm to be used for reducing the size of <em>plaintext</em>
	 * data to be exchanged with a peer by means of TLS
	 * <em>APPLICATION_DATA</em> messages.
	 * <p>
	 * The value returned is part of the <em>pending connection state</em> which
	 * has been negotiated with the peer. This means that it is not in effect
	 * until the <em>pending</em> state becomes the <em>current</em> state.
	 * 
	 * @return the algorithm identifier
	 */
	public CompressionMethod getCompressionMethod() {
		return compressionMethod;
	}

	/**
	 * Sets the algorithm to be used for reducing the size of <em>plaintext</em>
	 * data to be exchanged with a peer by means of TLS
	 * <em>APPLICATION_DATA</em> messages.
	 * <p>
	 * The value set using this method becomes part of the <em>pending
	 * connection state</em>. This means that it will not be in effect until the
	 * <em>pending</em> state becomes the <em>current</em> state.
	 * 
	 * @param compressionMethod the algorithm identifier
	 */
	void setCompressionMethod(CompressionMethod compressionMethod) {
		this.compressionMethod = compressionMethod;
	}

	final KeyExchangeAlgorithm getKeyExchange() {
		if (cipherSuite == null) {
			throw new IllegalStateException("Cipher suite has not been set (yet)");
		} else {
			return cipherSuite.getKeyExchange();
		}
	}

	/**
	 * Set use extended master secret.
	 * 
	 * See <a href="https://tools.ietf.org/html/rfc7627">RFC 7627</a>.
	 * 
	 * @param enable {@code true}, to enable the use of the extended master
	 *            secret, {@code false}, if the master secret (RFC 5246) is
	 *            used.
	 * @since 3.0
	 */
	public void setExtendedMasterSecret(boolean enable) {
		extendedMasterSecret = enable;
	}

	/**
	 * Gets use extended master secret.
	 * 
	 * See <a href="https://tools.ietf.org/html/rfc7627">RFC 7627</a>.
	 * 
	 * @return {@code true}, to enable the use of the extended master secret,
	 *         {@code false}, if the master secret (RFC 5246) is used.
	 * @since 3.0
	 */
	public boolean useExtendedMasterSecret() {
		return extendedMasterSecret;
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
		// don't overwrite the master secret, once it has been set in this
		// session
		if (this.masterSecret == null) {
			if (!sessionIdentifier.isEmpty()) {
				if (masterSecret == null) {
					throw new NullPointerException("Master secret must not be null");
				}
				// get length
				byte[] secret = masterSecret.getEncoded();
				// clear secret immediately, only length is required
				Bytes.clear(secret);
				if (secret.length != Label.MASTER_SECRET_LABEL.length()) {
					throw new IllegalArgumentException(
							String.format("Master secret must consist of of exactly %d bytes but has %d bytes",
									Label.MASTER_SECRET_LABEL.length(), secret.length));
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
	 * Sets the maximum amount of unencrypted payload data that can be received
	 * and processed by this session's peer in a single DTLS record.
	 * <p>
	 * The value of this property corresponds directly to the
	 * <em>DTLSPlaintext.length</em> field as defined in
	 * <a href="http://tools.ietf.org/html/rfc6347#section-4.3.1">DTLS 1.2 spec,
	 * Section 4.3.1</a>.
	 * <p>
	 * The default value of this property is 2^14 bytes.
	 * <p>
	 * This method checks if a fragment of the given maximum length can be
	 * transmitted in a single datagram without the need for IP fragmentation.
	 * If not the given length is reduced to the maximum value for which this is
	 * possible.
	 * 
	 * @param length the maximum length in bytes
	 * @throws IllegalArgumentException if the given length is &lt; 0 or &gt;
	 *             2^14
	 */
	void setMaxFragmentLength(int length) {
		if (length < 0 || length > MAX_FRAGMENT_LENGTH_DEFAULT) {
			throw new IllegalArgumentException(
					"Max. fragment length must be in range [0..." + MAX_FRAGMENT_LENGTH_DEFAULT + "]");
		} else {
			this.maxFragmentLength = length;
		}
	}

	/**
	 * Gets the maximum amount of unencrypted payload data that can be sent to
	 * this session's peer in a single DTLS record created under this session's
	 * <em>current write state</em>.
	 * <p>
	 * The value of this property serves as an upper boundary for the
	 * <em>DTLSPlaintext.length</em> field defined in
	 * <a href="http://tools.ietf.org/html/rfc6347#section-4.3.1">DTLS 1.2 spec,
	 * Section 4.3.1</a>. This means that an application can assume that any
	 * message containing at most as many bytes as indicated by this method,
	 * will be delivered to the peer in a single unfragmented IP datagram.
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
	 * Gets the negotiated ec-group to be used for the ECDHE key exchange
	 * message.
	 * 
	 * @return negotiated ec-group
	 * 
	 * @since 3.0
	 */
	public SupportedGroup getEcGroup() {
		return ecGroup;
	}

	/**
	 * Sets the negotiated ec-group to be used for the ECDHE key exchange
	 * 
	 * @param ecGroup negotiated ec-group
	 * 
	 * @since 3.0
	 */
	void setEcGroup(SupportedGroup ecGroup) {
		this.ecGroup = ecGroup;
	}

	/**
	 * Gets the authenticated peer's identity.
	 * 
	 * @return the identity or {@code null}, if the peer has not been
	 *         authenticated
	 */
	public Principal getPeerIdentity() {
		return peerIdentity;
	}

	/**
	 * Sets the authenticated peer's identity.
	 * 
	 * @param the identity
	 * @throws NullPointerException if the identity is {@code null}
	 */
	void setPeerIdentity(Principal peerIdentity) {
		if (peerIdentity == null) {
			throw new NullPointerException("Peer identity must not be null");
		}
		this.peerIdentity = peerIdentity;
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
		SecretKey masterSecret = this.masterSecret;
		if (SecretUtil.isDestroyed(masterSecret)) {
			throw new IllegalStateException("session has no valid crypto params, not fully negotiated yet?");
		} else if (sessionIdentifier.isEmpty()) {
			return null;
		}
		return new SessionTicket(ProtocolVersion.VERSION_DTLS_1_2, cipherSuite, compressionMethod, extendedMasterSecret,
				masterSecret, getServerNames(), getPeerIdentity(), creationTime);
	}

	@Override
	public int hashCode() {
		return sessionIdentifier == null ? (int) creationTime : sessionIdentifier.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		} else if (obj == null) {
			return false;
		} else if (getClass() != obj.getClass()) {
			return false;
		}
		DTLSSession other = (DTLSSession) obj;
		if (!SecretUtil.equals(masterSecret, other.masterSecret)) {
			return false;
		}
		if (!Bytes.equals(sessionIdentifier, other.sessionIdentifier)) {
			return false;
		}
		if (cipherSuite != other.cipherSuite) {
			return false;
		}
		if (compressionMethod != other.compressionMethod) {
			return false;
		}
		if (extendedMasterSecret != other.extendedMasterSecret) {
			return false;
		}
		if (peerSupportsSni != other.peerSupportsSni) {
			return false;
		}
		if (sendCertificateType != other.sendCertificateType) {
			return false;
		}
		if (receiveCertificateType != other.receiveCertificateType) {
			return false;
		}
		if (ecGroup != other.ecGroup) {
			return false;
		}
		if (creationTime != other.creationTime) {
			return false;
		}
		if (!Objects.equals(signatureAndHashAlgorithm, other.signatureAndHashAlgorithm)) {
			return false;
		}
		if (!Objects.equals(serverNames, other.serverNames)) {
			return false;
		}
		if (!Objects.equals(recordSizeLimit, other.recordSizeLimit)) {
			return false;
		}
		if (!Objects.equals(peerIdentity, other.peerIdentity)) {
			return false;
		}
		return true;
	}

	/**
	 * Version number for serialization.
	 */
	private static final int VERSION = 2;

	/**
	 * Write dtls session state.
	 * 
	 * Note: the stream will contain not encrypted critical credentials. It is
	 * required to protect this data before exporting it. The encoding of the
	 * content may also change in the future.
	 * 
	 * @param writer writer for dtls session state
	 * @since 3.0
	 */
	@WipAPI
	public void write(DatagramWriter writer) {
		int position = SerializationUtil.writeStartItem(writer, VERSION, Short.SIZE);
		writer.writeLong(creationTime, Long.SIZE);
		if (serverNames == null) {
			writer.write(0, Byte.SIZE);
		} else {
			writer.write(1, Byte.SIZE);
			serverNames.encode(writer);
		}
		if (recordSizeLimit != null) {
			writer.write(recordSizeLimit, Short.SIZE);
		} else {
			writer.write(0xffff, Short.SIZE);
		}
		writer.write(maxFragmentLength, Short.SIZE);
		writer.writeVarBytes(sessionIdentifier, Byte.SIZE);
		writer.write(cipherSuite.getCode(), Short.SIZE);
		writer.write(compressionMethod.getCode(), Byte.SIZE);
		writer.write(sendCertificateType.getCode(), Byte.SIZE);
		writer.write(receiveCertificateType.getCode(), Byte.SIZE);
		writer.write(extendedMasterSecret ? 1 : 0, Byte.SIZE);
		SecretSerializationUtil.write(writer, masterSecret);
		if (signatureAndHashAlgorithm == null) {
			writer.write(0, Byte.SIZE);
		} else {
			writer.write(1, Byte.SIZE);
			writer.write(signatureAndHashAlgorithm.getHash().getCode(), Byte.SIZE);
			writer.write(signatureAndHashAlgorithm.getSignature().getCode(), Byte.SIZE);
		}
		if (ecGroup == null) {
			writer.write(0, Byte.SIZE);
		} else {
			writer.write(1, Byte.SIZE);
			writer.write(ecGroup.getId(), Short.SIZE);
		}
		if (peerIdentity == null) {
			writer.write(0, Byte.SIZE);
		} else {
			writer.write(1, Byte.SIZE);
			PrincipalSerializer.serialize(peerIdentity, writer);
		}
		SerializationUtil.writeFinishedItem(writer, position, Short.SIZE);
	}

	/**
	 * Read dtls session state.
	 * 
	 * Note: the stream will contain not encrypted critical credentials. The
	 * encoding of the content may also change in the future.
	 * 
	 * @param reader reader with dtls session state.
	 * @return read dtls session.
	 * @throws IllegalArgumentException if version differs or the data is
	 *             erroneous
	 * @since 3.0
	 */
	@WipAPI
	public static DTLSSession fromReader(DatagramReader reader) {
		int length = SerializationUtil.readStartItem(reader, VERSION, Short.SIZE);
		if (0 < length) {
			DatagramReader rangeReader = reader.createRangeReader(length);
			return new DTLSSession(rangeReader);
		} else {
			return null;
		}
	}

	/**
	 * Create instance from reader.
	 * 
	 * @param reader reader with dtls session state.
	 * @throws IllegalArgumentException if version differs or the data is
	 *             erroneous
	 * @since 3.0
	 */
	private DTLSSession(DatagramReader reader) {
		creationTime = reader.readLong(Long.SIZE);
		if (reader.readNextByte() == 1) {
			serverNames = ServerNames.newInstance();
			try {
				serverNames.decode(reader);
				ServerName serverName = serverNames.getServerName(NameType.HOST_NAME);
				if (serverName != null) {
					hostName = serverName.getNameAsString();
				}
			} catch (IllegalArgumentException e) {
				serverNames = null;
			}
		}
		int size = reader.read(Short.SIZE);
		if (size < 0xffff) {
			recordSizeLimit = size;
		}
		size = reader.read(Short.SIZE);
		maxFragmentLength = size;
		byte[] data = reader.readVarBytes(Byte.SIZE);
		if (data != null) {
			sessionIdentifier = new SessionId(data);
		}
		int code = reader.read(Short.SIZE);
		cipherSuite = CipherSuite.getTypeByCode(code);
		if (cipherSuite == null) {
			throw new IllegalArgumentException("unknown cipher suite 0x" + Integer.toHexString(code) + "!");
		}
		code = reader.read(Byte.SIZE);
		compressionMethod = CompressionMethod.getMethodByCode(code);
		if (compressionMethod == null) {
			throw new IllegalArgumentException("unknown compression method 0x" + Integer.toHexString(code) + "!");
		}
		code = reader.read(Byte.SIZE);
		sendCertificateType = CertificateType.getTypeFromCode(code);
		if (sendCertificateType == null) {
			throw new IllegalArgumentException("unknown send certificate type 0x" + Integer.toHexString(code) + "!");
		}
		code = reader.read(Byte.SIZE);
		receiveCertificateType = CertificateType.getTypeFromCode(code);
		if (receiveCertificateType == null) {
			throw new IllegalArgumentException("unknown send certificate type 0x" + Integer.toHexString(code) + "!");
		}
		extendedMasterSecret = (reader.read(Byte.SIZE) == 1);
		masterSecret = SecretSerializationUtil.readSecretKey(reader);
		if (reader.readNextByte() == 1) {
			int hashId = reader.read(Byte.SIZE);
			int signatureId = reader.read(Byte.SIZE);
			signatureAndHashAlgorithm = new SignatureAndHashAlgorithm(hashId, signatureId);
		}
		if (reader.readNextByte() == 1) {
			int groupId = reader.read(Short.SIZE);
			ecGroup = SupportedGroup.fromId(groupId);
			if (ecGroup == null) {
				throw new IllegalArgumentException("unknown ec-group 0x" + Integer.toHexString(groupId) + "!");
			}
		}
		if (reader.readNextByte() == 1) {
			try {
				peerIdentity = PrincipalSerializer.deserialize(reader);
			} catch (GeneralSecurityException e) {
				throw new IllegalArgumentException("principal failure", e);
			}
		}
		reader.assertFinished("dtls-session");
	}
}
