/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.auth.PrincipalSerializer;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

/**
 * A container for a session's crypto parameters that are required for resuming the
 * session by means of an abbreviated handshake.
 */
public final class SessionTicket {

	private final int hashCode;
	private final ProtocolVersion protocolVersion;
	private final byte[] masterSecret;
	private final CipherSuite cipherSuite;
	private final CompressionMethod compressionMethod;
	private final Principal clientIdentity;
	private final long timestampMillis;

	/**
	 * Creates a ticket from a set of crypto params.
	 * 
	 * @param protocolVersion
	 * @param cipherSuite
	 * @param compressionMethod
	 * @param masterSecret
	 * @param clientIdentity
	 * @param timestampMillis timestamp of session creation.
	 */
	SessionTicket(
			final ProtocolVersion protocolVersion,
			final CipherSuite cipherSuite,
			final CompressionMethod compressionMethod,
			final byte[] masterSecret,
			final Principal clientIdentity,
			final long timestampMillis) {

		if (protocolVersion == null) {
			throw new NullPointerException("Protcol version must not be null");
		} else if (cipherSuite == null) {
			throw new NullPointerException("Cipher suite must not be null");
		} else if (compressionMethod == null) {
			throw new NullPointerException("Compression method must not be null");
		} else if (masterSecret == null) {
			throw new NullPointerException("Master secret must not be null");
		} else {
			this.protocolVersion = protocolVersion;
			this.masterSecret = masterSecret;
			this.cipherSuite = cipherSuite;
			this.compressionMethod = compressionMethod;
			this.clientIdentity = clientIdentity;
			this.timestampMillis = timestampMillis;
			// the master secret is intended to be unique
			// therefore the hash code only consider that master secret
			this.hashCode = Arrays.hashCode(masterSecret);
		}
	}

	/**
	 * Serializes this session into a plain text <em>session ticket</em> following
	 * the structure defined in <a href="https://tools.ietf.org/html/rfc5077">RFC 5077</a>.
	 * <pre>
	 * struct {
	 *   ProtocolVersion protocol_version;
	 *   CipherSuite cipher_suite;
	 *   CompressionMethod compression_method;
	 *   opaque master_secret[48];
	 *   ClientIdentity client_identity;
	 *   uint32 timestamp;
	 * } StatePlaintext;
	 * </pre>
	 * <p>
	 * This method is useful for e.g. sharing the session with other nodes by means
	 * of a cache server or database so that a client can resume a session on another
	 * node if this node fails.
	 * <p>
	 * The timestampMillis are encoded in seconds.
	 * 
	 * @param writer The writer to serialize to.
	 */
	public void encode(final DatagramWriter writer) {

		writer.write(protocolVersion.getMajor(), 8);
		writer.write(protocolVersion.getMinor(), 8);

		// cipher_suite
		writer.write(cipherSuite.getCode(), CipherSuite.CIPHER_SUITE_BITS);

		// compression_method
		writer.write(compressionMethod.getCode(), CompressionMethod.COMPRESSION_METHOD_BITS);

		// master_secret
		writer.writeBytes(masterSecret);

		// client_identity
		PrincipalSerializer.serialize(clientIdentity, writer);

		// timestamp
		writer.writeLong(TimeUnit.MILLISECONDS.toSeconds(timestampMillis), 32);
	}

	/**
	 * Creates a session from a byte array containing the binary encoding of a plain text <em>session ticket</em>
	 * that has been created by {@link #encode(DatagramWriter)}.
	 * <p>
	 * This method is useful for e.g. sharing the write state with other nodes by means
	 * of a cache server or database so that a client can resume a session on another
	 * node if this node fails.
	 * 
	 * @param source The encoded session ticket.
	 * @return The session object created from the ticket. Note that the session contains <em>pending</em>
	 *         state information only and thus requires an abbreviated handshake to take place in order to
	 *         create <em>current</em> read and write state. Returns {@code null} if the  session ticket is
	 *         not encoded according to the structure defined by {@link #encode(DatagramWriter)}.
	 */
	public static SessionTicket decode(final DatagramReader source) {

		if (source == null) {
			throw new NullPointerException("reader must not be null");
		}

		// protocol_version
		int major = source.read(8);
		int minor = source.read(8);
		ProtocolVersion ver = new ProtocolVersion(major, minor);

		// cipher_suite
		CipherSuite cipherSuite = CipherSuite.getTypeByCode(source.read(CipherSuite.CIPHER_SUITE_BITS));
		if (cipherSuite == null) {
			return null;
		}

		// compression_method
		CompressionMethod compressionMethod = CompressionMethod.getMethodByCode(source.read(CompressionMethod.COMPRESSION_METHOD_BITS));
		if (compressionMethod == null) {
			return null;
		}

		// master_secret
		byte[] masterSecret = source.readBytes(48);

		// client_identity
		Principal identity = null;
		try {
			identity = PrincipalSerializer.deserialize(source);
		} catch (GeneralSecurityException e) {
			return null;
		}

		// timestamp
		long timestampMillis = TimeUnit.SECONDS.toMillis(source.readLong(32));

		// assemble session
		return new SessionTicket(ver, cipherSuite, compressionMethod, masterSecret, identity, timestampMillis);
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
		if (!Arrays.equals(masterSecret, other.masterSecret)) {
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

	/**
	 * @return the protocolVersion
	 */
	public final ProtocolVersion getProtocolVersion() {
		return protocolVersion;
	}

	
	/**
	 * @return the masterSecret
	 */
	public final byte[] getMasterSecret() {
		return masterSecret;
	}

	
	/**
	 * @return the cipherSuite
	 */
	public final CipherSuite getCipherSuite() {
		return cipherSuite;
	}

	
	/**
	 * @return the compressionMethod
	 */
	public final CompressionMethod getCompressionMethod() {
		return compressionMethod;
	}

	
	/**
	 * @return the clientIdentity
	 */
	public final Principal getClientIdentity() {
		return clientIdentity;
	}

	
	/**
	 * @return the timestamp
	 */
	public final long getTimestamp() {
		return timestampMillis;
	}
}
