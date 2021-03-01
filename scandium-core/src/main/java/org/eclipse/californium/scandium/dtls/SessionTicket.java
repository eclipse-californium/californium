/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - use create time milliseconds
 *                                                    for timestamp. Convert it to 
 *                                                    seconds, when encoded, and
 *                                                    back to milliseconds, when
 *                                                    decoded.
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.GeneralSecurityException;
import java.security.Principal;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.auth.PrincipalSerializer;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.SecretSerializationUtil;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * A container for a session's crypto parameters that are required for resuming
 * the session by means of an abbreviated handshake.
 */
public final class SessionTicket implements Destroyable {

	/**
	 * Version number for serialization.
	 */
	private static final int VERSION = 2;

	private final int hashCode;
	private final ProtocolVersion protocolVersion;
	private final SecretKey masterSecret;
	private final CipherSuite cipherSuite;
	private final CompressionMethod compressionMethod;
	private final SignatureAndHashAlgorithm signatureAndHashAlgorithm;
	private final SupportedGroup ecGroup;
	private final boolean extendedMasterSecret;
	private final ServerNames serverNames;
	private final Principal clientIdentity;
	private final CertificateType sendCertificateType;
	private final CertificateType receiveCertificateType;
	private final Integer recordSizeLimit;
	private final int maxFragmentLength;
	private final long timestampMillis;

	/**
	 * Creates a ticket from a dtls session.
	 * 
	 * @param session dtls session
	 * @throws NullPointerException if the session is {@code null}
	 * @since 3.0
	 */
	SessionTicket(DTLSSession session) {
		if (session == null) {
			throw new NullPointerException("Session must not be null");
		}
		this.protocolVersion = session.getProtocolVersion();
		this.extendedMasterSecret = session.useExtendedMasterSecret();
		this.masterSecret = session.getMasterSecret();
		this.cipherSuite = session.getCipherSuite();
		this.compressionMethod = session.getCompressionMethod();
		this.signatureAndHashAlgorithm = session.getSignatureAndHashAlgorithm();
		this.ecGroup = session.getEcGroup();
		this.serverNames = session.getServerNames();
		this.clientIdentity = session.getPeerIdentity();
		this.sendCertificateType = session.sendCertificateType();
		this.receiveCertificateType = session.receiveCertificateType();
		this.recordSizeLimit = session.getRecordSizeLimit();
		this.maxFragmentLength = session.getMaxFragmentLength();
		this.timestampMillis = session.getCreationTime();
		// the master secret is intended to be unique
		// therefore the hash code only consider that master secret
		this.hashCode = this.masterSecret.hashCode();
	}

	/**
	 * Creates a ticket from a reader.
	 * 
	 * @param source datagram reader
	 * @since 3.0
	 */
	private SessionTicket(DatagramReader source) {
		// protocol_version
		int major = source.read(Byte.SIZE);
		int minor = source.read(Byte.SIZE);
		protocolVersion = ProtocolVersion.valueOf(major, minor);

		// cipher_suite
		cipherSuite = CipherSuite.getTypeByCode(source.read(CipherSuite.CIPHER_SUITE_BITS));
		if (cipherSuite == null) {
			throw new IllegalArgumentException("cipher suite could not be read");
		}

		// compression_method
		compressionMethod = CompressionMethod.getMethodByCode(source.read(CompressionMethod.COMPRESSION_METHOD_BITS));
		if (compressionMethod == null) {
			throw new IllegalArgumentException("compression method could not be read");
		}

		extendedMasterSecret = (source.read(Byte.SIZE) == 1);

		// master_secret
		masterSecret = SecretSerializationUtil.readSecretKey(source);

		// client_identity
		try {
			clientIdentity = PrincipalSerializer.deserialize(source);
		} catch (GeneralSecurityException e) {
			throw new IllegalArgumentException("principal could not be read", e);
		}

		// timestamp
		timestampMillis = TimeUnit.SECONDS.toMillis(source.readLong(Integer.SIZE));

		sendCertificateType = CertificateType.getTypeFromCode(source.read(Byte.SIZE));

		receiveCertificateType = CertificateType.getTypeFromCode(source.read(Byte.SIZE));

		maxFragmentLength = source.read(Short.SIZE);

		if (source.read(Byte.SIZE) == 1) {
			recordSizeLimit = source.read(Short.SIZE);
		} else {
			recordSizeLimit = null;
		}

		if (source.read(Byte.SIZE) == 1) {
			int hashId = source.read(Byte.SIZE);
			int signatureId = source.read(Byte.SIZE);
			signatureAndHashAlgorithm = new SignatureAndHashAlgorithm(hashId, signatureId);
		} else {
			signatureAndHashAlgorithm = null;
		}

		if (source.read(Byte.SIZE) == 1) {
			int id = source.read(Short.SIZE);
			ecGroup = SupportedGroup.fromId(id);
		} else {
			ecGroup = null;
		}

		ServerNames serverNames = null;
		if (source.read(Byte.SIZE) == 1) {
			serverNames = ServerNames.newInstance();
			try {
				serverNames.decode(source);
			} catch (IllegalArgumentException e) {
				serverNames = null;
			}
		}
		this.serverNames = serverNames;

		this.hashCode = this.masterSecret.hashCode();
	}

	/**
	 * Serializes this session into a plain text <em>session ticket</em> similar
	 * to the structure defined in
	 * <a href="https://tools.ietf.org/html/rfc5077">RFC 5077</a>.
	 * 
	 * <pre>
	 * struct {
	 *   uint8 VERSION;
	 *   ProtocolVersion protocol_version;
	 *   CipherSuite cipher_suite;
	 *   CompressionMethod compression_method;
	 *   uint8 extendedMasterSecret;
	 *   opaque master_secret[48];
	 *   ClientIdentity client_identity;
	 *   uint32 timestamp;
	 *   uint8 send certificate type; *
	 *   uint8 receive certificate type; *
	 *   uint16 max fragment length; *
	 *   uint8 record size use; *
	 *   uint16 record size; **
	 *   uint8 server_names use; *
	 *   ServerNames server_names; **
	 * } StatePlaintext;
	 * </pre>
	 * <p>
	 * (The server names are added to be able to check provided server names on
	 * session resumption with the server names provided on the full handshake
	 * of the session)
	 * <p>
	 * This method is useful for e.g. sharing the session with other nodes by
	 * means of a cache server or database so that a client can resume a session
	 * on another node if this node fails.
	 * <p>
	 * The timestampMillis are encoded in seconds. encode and decode therefore
	 * lose the milliseconds precision.
	 * 
	 * @param writer The writer to serialize to.
	 */
	public void encode(final DatagramWriter writer) {
		writer.write(VERSION, Byte.SIZE);
		writer.write(protocolVersion.getMajor(), Byte.SIZE);
		writer.write(protocolVersion.getMinor(), Byte.SIZE);

		// cipher_suite
		writer.write(cipherSuite.getCode(), CipherSuite.CIPHER_SUITE_BITS);

		// compression_method
		writer.write(compressionMethod.getCode(), CompressionMethod.COMPRESSION_METHOD_BITS);

		// extended master secret
		writer.write(extendedMasterSecret ? 1 : 0, Byte.SIZE);

		// master_secret
		SecretSerializationUtil.write(writer, masterSecret);

		// client_identity
		PrincipalSerializer.serialize(clientIdentity, writer);

		// timestamp
		writer.writeLong(TimeUnit.MILLISECONDS.toSeconds(timestampMillis), Integer.SIZE);

		// send certificate type
		writer.write(sendCertificateType.getCode(), Byte.SIZE);

		// receive certificate type
		writer.write(receiveCertificateType.getCode(), Byte.SIZE);

		// max fragment length
		writer.write(maxFragmentLength, Short.SIZE);

		if (recordSizeLimit == null) {
			writer.write(0, Byte.SIZE);
		} else {
			writer.write(1, Byte.SIZE);
			// record size limit
			writer.write(recordSizeLimit, Short.SIZE);
		}

		// signatureAndHashAlgorithm
		if (signatureAndHashAlgorithm == null) {
			writer.write(0, Byte.SIZE);
		} else {
			writer.write(1, Byte.SIZE);
			writer.write(signatureAndHashAlgorithm.getHash().getCode(), Byte.SIZE);
			writer.write(signatureAndHashAlgorithm.getSignature().getCode(), Byte.SIZE);
		}

		// ec group
		if (ecGroup == null) {
			writer.write(0, Byte.SIZE);
		} else {
			writer.write(1, Byte.SIZE);
			writer.write(ecGroup.getId(), Short.SIZE);
		}

		// server names
		if (serverNames == null) {
			writer.write(0, Byte.SIZE);
		} else {
			writer.write(1, Byte.SIZE);
			serverNames.encode(writer);
		}
	}

	/**
	 * Creates a session from a byte array containing the binary encoding of a
	 * plain text <em>session ticket</em> that has been created by
	 * {@link #encode(DatagramWriter)}.
	 * <p>
	 * This method is useful for e.g. sharing the write state with other nodes
	 * by means of a cache server or database so that a client can resume a
	 * session on another node if this node fails.
	 * 
	 * @param source The encoded session ticket.
	 * @return The session object created from the ticket. Note that the session
	 *         contains <em>pending</em> state information only and thus
	 *         requires an abbreviated handshake to take place in order to
	 *         create <em>current</em> read and write state. Returns
	 *         {@code null} if the session ticket is not encoded according to
	 *         the structure defined by {@link #encode(DatagramWriter)}.
	 * @throws NullPointerException if source is {@code null}
	 * @throws IllegalArgumentException if read data version doesn't match
	 */
	public static SessionTicket decode(final DatagramReader source) {

		if (source == null) {
			throw new NullPointerException("reader must not be null");
		}

		int version = source.read(Byte.SIZE);
		if (version != VERSION) {
			throw new IllegalArgumentException("Version mismatch! " + VERSION + " is required, not " + version);
		}

		try {
			return new SessionTicket(source);
		} catch (IllegalArgumentException ex) {
			return null;
		}
	}

	@Override
	public int hashCode() {
		return hashCode;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SessionTicket other = (SessionTicket) obj;
		// the master secret is intended to be unique
		// therefore check it first, the other compares
		// are more or less for validation
		if (hashCode != other.hashCode) {
			return false;
		}
		// the SecretKeySpec equals seems to leak the others secret ;-(.
		if (!SecretUtil.equals(masterSecret, other.masterSecret)) {
			return false;
		}
		if (!protocolVersion.equals(other.protocolVersion)) {
			return false;
		}
		if (!cipherSuite.equals(other.cipherSuite)) {
			return false;
		}
		if (!compressionMethod.equals(other.compressionMethod)) {
			return false;
		}
		if (!clientIdentity.equals(other.clientIdentity)) {
			return false;
		}
		return timestampMillis == other.timestampMillis;
	}

	@Override
	public void destroy() throws DestroyFailedException {
		SecretUtil.destroy(masterSecret);
	}

	@Override
	public boolean isDestroyed() {
		return SecretUtil.isDestroyed(masterSecret);
	}

	/**
	 * Gets the protocol version.
	 * 
	 * @return the protocol version
	 */
	public final ProtocolVersion getProtocolVersion() {
		return protocolVersion;
	}

	/**
	 * Gets the master secret.
	 * 
	 * @return the master secret
	 */
	public final SecretKey getMasterSecret() {
		return SecretUtil.create(masterSecret);
	}

	/**
	 * Gets the cipher suite.
	 * 
	 * @return the cipher suite
	 */
	public final CipherSuite getCipherSuite() {
		return cipherSuite;
	}

	/**
	 * Gets the compression method.
	 * 
	 * @return the compression method
	 */
	public final CompressionMethod getCompressionMethod() {
		return compressionMethod;
	}
	/**
	 * Gets the negotiated signature and hash algorithm to be used to sign the
	 * server key exchange message.
	 * 
	 * @return negotiated signature and hash algorithm
	 * @since 3.0
	 */
	public final SignatureAndHashAlgorithm getSignatureAndHashAlgorithm() {
		return signatureAndHashAlgorithm;
	}

	/**
	 * Gets the negotiated ec-group to be used for the ECDHE key exchange
	 * message.
	 * 
	 * @return negotiated ec-group
	 * @since 3.0
	 */
	public final SupportedGroup getEcGroup() {
		return ecGroup;
	}

	/**
	 * Gets the extended master secret usage.
	 * 
	 * @return the extended master secret usage.
	 * @since 3.0
	 */
	public final boolean useExtendedMasterSecret() {
		return extendedMasterSecret;
	}

	/**
	 * Gets the server names.
	 * 
	 * @return the server names, or {@code null}, if not available.
	 */
	public final ServerNames getServerNames() {
		return serverNames;
	}

	/**
	 * Gets the client's identity.
	 * 
	 * @return the principal of client's identity, or {@code null}, if not
	 *         available.
	 */
	public final Principal getClientIdentity() {
		return clientIdentity;
	}

	public final int getMaxFragmentLength() {
		return maxFragmentLength;
	}

	public final Integer getRecordSizeLimit() {
		return recordSizeLimit;
	}

	public final CertificateType getSendCertificateType() {
		return sendCertificateType;
	}

	public final CertificateType getReceiveCertificateType() {
		return receiveCertificateType;
	}

	/**
	 * Gets the timestamp in milliseconds.
	 * 
	 * @return the timestamp
	 * @see System#currentTimeMillis()
	 */
	public final long getTimestamp() {
		return timestampMillis;
	}
}
