/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fixes & additions
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessors for certificate types
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for peer address
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.HelloExtension.ExtensionType;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

/**
 * A TLS handshake message sent by a server in response to a {@link ClientHello}
 * message received from a client.
 * 
 * The server will send this message in response to a {@link ClientHello}
 * message when it was able to find an acceptable set of algorithms. If it
 * cannot find such a match, it will respond with a handshake failure alert. See
 * <a href="http://tools.ietf.org/html/rfc5246#section-7.4.1.3">RFC 5246</a> for
 * further details.
 */
public final class ServerHello extends HandshakeMessage {

	// DTLS-specific constants ///////////////////////////////////////////

	private static final int VERSION_BITS = 8; // for major and minor each

	private static final int RANDOM_BYTES = 32;

	private static final int SESSION_ID_LENGTH_BITS = 8;

	private static final int CIPHER_SUITE_BITS = 16;

	private static final int COMPRESSION_METHOD_BITS = 8;

	// Members ///////////////////////////////////////////////////////////

	/**
	 * This field will contain the lower of that suggested by the client in the
	 * {@link ClientHello} and the highest supported by the server.
	 */
	private final ProtocolVersion serverVersion;

	/**
	 * This structure is generated by the server and MUST be independently
	 * generated from the {@link ClientHello}.random.
	 */
	private final Random random;

	/**
	 * This is the identity of the session corresponding to this connection.
	 */
	private final SessionId sessionId;

	/**
	 * The single {@link CipherSuite} selected by the server from the list in
	 * {@link ClientHello}.cipher_suites.
	 */
	private final CipherSuite cipherSuite;

	/**
	 * The single compression algorithm selected by the server from the list in
	 * ClientHello.compression_methods.
	 */
	private final CompressionMethod compressionMethod;

	/**
	 * A list of extensions. Note that only extensions offered by the client can
	 * appear in the server's list.
	 */
	private final HelloExtensions extensions;

	// Constructor ////////////////////////////////////////////////////

	/**
	 * Constructs a full <em>ServerHello</em> message.
	 * See <a href="http://tools.ietf.org/html/rfc5246#section-7.4.1.3">
	 * RFC 5246 (TLS 1.2), Section 7.4.1.3. Server Hello</a> for details.
	 * 
	 * @param version
	 *            the negotiated version (highest supported by server).
	 * @param random
	 *            the server's random.
	 * @param sessionId
	 *            the new session's identifier.
	 * @param cipherSuite
	 *            the negotiated cipher suite.
	 * @param compressionMethod
	 *            the negotiated compression method.
	 * @param extensions
	 *            a list of extensions supported by the client (may be <code>null</code>).
	 * @throws NullPointerException if any of the mandatory parameters is <code>null</code>
	 */
	public ServerHello(ProtocolVersion version, Random random, SessionId sessionId,
			CipherSuite cipherSuite, CompressionMethod compressionMethod, HelloExtensions extensions) {
		if (version == null) {
			throw new NullPointerException("Negotiated protocol version must not be null");
		}
		if (random == null) {
			throw new NullPointerException("ServerHello message must contain a random");
		}
		if (sessionId == null) {
			throw new NullPointerException("ServerHello must be associated with a session ID");
		}
		if (cipherSuite == null) {
			throw new NullPointerException("Negotiated cipher suite must not be null");
		}
		if (compressionMethod == null) {
			throw new NullPointerException("Negotiated compression method must not be null");
		}
		this.serverVersion = version;
		this.random = random;
		this.sessionId = sessionId;
		this.cipherSuite = cipherSuite;
		this.compressionMethod = compressionMethod;
		this.extensions = extensions;
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	public byte[] fragmentToByteArray() {
		DatagramWriter writer = new DatagramWriter();

		writer.write(serverVersion.getMajor(), VERSION_BITS);
		writer.write(serverVersion.getMinor(), VERSION_BITS);

		writer.writeBytes(random.getBytes());

		writer.writeVarBytes(sessionId, SESSION_ID_LENGTH_BITS);

		writer.write(cipherSuite.getCode(), CIPHER_SUITE_BITS);
		writer.write(compressionMethod.getCode(), COMPRESSION_METHOD_BITS);

		if (extensions != null) {
			writer.writeBytes(extensions.toByteArray());
		}

		return writer.toByteArray();
	}

	/**
	 * Creates a <em>Server Hello</em> object from its binary encoding as used on
	 * the wire.
	 * 
	 * @param reader reader for the binary encoding of the message.
	 * @return the object representation
	 * @throws HandshakeException if the cipher suite code selected by the server is either
	 *           unknown, i.e. not defined in {@link CipherSuite} at all, or
	 *           {@link CipherSuite#TLS_NULL_WITH_NULL_NULL}
	 */
	public static HandshakeMessage fromReader(DatagramReader reader) throws HandshakeException {

		int major = reader.read(VERSION_BITS);
		int minor = reader.read(VERSION_BITS);
		ProtocolVersion version = ProtocolVersion.valueOf(major, minor);

		Random random = new Random(reader.readBytes(RANDOM_BYTES));

		SessionId sessionId = new SessionId(reader.readVarBytes(SESSION_ID_LENGTH_BITS));

		int code = reader.read(CIPHER_SUITE_BITS);
		CipherSuite cipherSuite = CipherSuite.getTypeByCode(code);
		if (cipherSuite == null) {
			throw new HandshakeException(
					String.format("Server selected unknown cipher suite [%s]", Integer.toHexString(code)),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE));
		} else if ( cipherSuite == CipherSuite.TLS_NULL_WITH_NULL_NULL) {
			throw new HandshakeException("Server tries to negotiate NULL cipher suite",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE));
		}
		CompressionMethod compressionMethod = CompressionMethod.getMethodByCode(reader.read(COMPRESSION_METHOD_BITS));

		HelloExtensions extensions = null;
		if (reader.bytesAvailable()) {
			extensions = HelloExtensions.fromReader(reader);
		}

		return new ServerHello(version, random, sessionId, cipherSuite, compressionMethod, extensions);
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.SERVER_HELLO;
	}

	@Override
	public int getMessageLength() {

		/*
		 * if no extensions set, empty; otherwise 2 bytes for field length and
		 * then the length of the extensions. See
		 * http://tools.ietf.org/html/rfc5246#section-7.4.1.2
		 */
		int extensionsLength = (extensions == null || extensions.isEmpty()) ?
				0 : (2 + extensions.getLength());

		/*
		 * fixed sizes: version (2) + random (32) + session ID length (1) +
		 * cipher suit (2) + compression method (1) = 38, variable sizes: session
		 * ID
		 */

		return 38 + sessionId.length() + extensionsLength;
	}

	/**
	 * Gets the DTLS version the server is willing to use.
	 * 
	 * @return The DTLS version.
	 */
	public ProtocolVersion getServerVersion() {
		return serverVersion;
	}

	/**
	 * Gets the server's random value to use for generating the key material.
	 * 
	 * @return The random value.
	 */
	public Random getRandom() {
		return random;
	}

	/**
	 * Gets the identifier the server has created for the session being negotiated.
	 * 
	 * @return The session identifier.
	 */
	public SessionId getSessionId() {
		return sessionId;
	}

	/**
	 * Gets the cipher suite the server has chosen for the session being negotiated.
	 * 
	 * @return The cipher suite.
	 */
	public CipherSuite getCipherSuite() {
		return cipherSuite;
	}

	/**
	 * Gets the compression method the server has chosen for the session being negotiated.
	 * 
	 * @return The compression method.
	 */
	public CompressionMethod getCompressionMethod() {
		return compressionMethod;
	}

	/**
	 * Gets the server hello extensions the server has included in this message.
	 * 
	 * @return The extensions or {@code null} if no extensions are used.
	 */
	public HelloExtensions getExtensions() {
		return extensions;
	}

	/**
	 * Gets the type of certificate the server expects the client to send in
	 * its <em>Certificate</em> message.
	 * 
	 * @return the certificate type
	 */
	CertificateType getClientCertificateType() {
		return getCertificateType(ExtensionType.CLIENT_CERT_TYPE);
	}

	/**
	 * Gets the type of certificate the server will send to the client in
	 * its <em>Certificate</em> message.
	 * 
	 * @return the certificate type
	 */
	CertificateType getServerCertificateType() {
		return getCertificateType(ExtensionType.SERVER_CERT_TYPE);
	}

	/**
	 * Gets the type of certificate for the provided extension type.
	 * 
	 * @param type extension type. Either {@link ExtensionType#SERVER_CERT_TYPE} or {@link ExtensionType#CLIENT_CERT_TYPE}
	 * @return the certificate type
	 */
	CertificateType getCertificateType(ExtensionType type) {
		// default type is always X.509
		CertificateType result = CertificateType.X_509;
		if (extensions != null) {
			CertificateTypeExtension certificateExtension = (CertificateTypeExtension)
					extensions.getExtension(type);
			if (certificateExtension != null && !certificateExtension.getCertificateTypes().isEmpty()) {
				result = certificateExtension.getCertificateTypes().get(0);
			}
		}
		return result;
	}

	/**
	 * Gets the <em>MaxFragmentLength</em> extension data from this message.
	 * 
	 * @return the extension data or <code>null</code> if this message does not contain the
	 *          <em>MaxFragmentLength</em> extension.
	 */
	MaxFragmentLengthExtension getMaxFragmentLength() {
		if (extensions != null) {
			return (MaxFragmentLengthExtension) extensions.getExtension(ExtensionType.MAX_FRAGMENT_LENGTH);
		} else {
			return null;
		}
	}

	/**
	 * Gets the <em>RecordSizeLimit</em> extension data from this message.
	 * 
	 * @return the extension data or {@code null}, if this message does not contain the
	 *          <em>RecordSizeLimit</em> extension.
	 * @since 2.4
	 */
	RecordSizeLimitExtension getRecordSizeLimit() {
		if (extensions != null) {
			return (RecordSizeLimitExtension) extensions.getExtension(ExtensionType.RECORD_SIZE_LIMIT);
		} else {
			return null;
		}
	}

	/**
	 * Gets the <em>Point Formats</em> extension data from this message.
	 * 
	 * @return the extension data or <code>null</code> if this message does not contain the
	 *          <em>SupportedPointFormats</em> extension.
	 */
	SupportedPointFormatsExtension getSupportedPointFormatsExtension() {
		if (extensions != null) {
			return (SupportedPointFormatsExtension) extensions.getExtension(ExtensionType.EC_POINT_FORMATS);
		} else {
			return null;
		}
	}

	/**
	 * Gets the <em>connection id</em> extension data from this message.
	 * 
	 * @return the extension data or <code>null</code> if this message does not contain the
	 *          <em>connection id</em> extension.
	 */
	public ConnectionIdExtension getConnectionIdExtension() {
		if (extensions != null) {
			return (ConnectionIdExtension) extensions.getExtension(ExtensionType.CONNECTION_ID);
		} else {
			return null;
		}
	}

	/**
	 * Checks whether <em>server_name</em> extension is present in this message.
	 * <p>
	 * During a handshake it is sufficient to check for the mere presence of the
	 * extension because when included in a <em>SERVER_HELLO</em> the extension data will be empty.
	 * 
	 * @return {@code true} if the extension is present.
	 */
	boolean hasServerNameExtension() {
		return extensions != null && extensions.getExtension(ExtensionType.SERVER_NAME) != null;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString());
		sb.append("\t\tServer Version: ").append(serverVersion.getMajor()).append(", ").append(serverVersion.getMinor());
		sb.append(StringUtil.lineSeparator()).append("\t\tRandom:").append(random);
		sb.append(StringUtil.lineSeparator()).append("\t\tSession ID Length: ").append(sessionId.length());
		if (sessionId.length() > 0) {
			sb.append(StringUtil.lineSeparator()).append("\t\tSession ID: ").append(sessionId);
		}
		sb.append(StringUtil.lineSeparator()).append("\t\tCipher Suite: ").append(cipherSuite);
		sb.append(StringUtil.lineSeparator()).append("\t\tCompression Method: ").append(compressionMethod);

		if (extensions != null) {
			sb.append(StringUtil.lineSeparator()).append(extensions);
		}

		return sb.toString();
	}

}
