/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for peer address
 *    Kai Hudalla (Bosch Software Innovations GmbH) - make sure that sessionId is always
 *                                                    initialized properly
 *    Achim Kraus (Bosch Software Innovations GmbH) - add EC extensions only, 
 *                                                    if ECC-based cipher suites are used.
 *                                                    replace add cipher suite with
 *                                                    list in constructor parameters
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.crypto.Mac;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.NoPublicAPI;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.HelloExtension.ExtensionType;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.CertificateKeyAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.util.ListUtils;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * When a client first connects to a server, it is required to send the
 * ClientHello as its first message. The client can also send a ClientHello in
 * response to a {@link HelloRequest} or on its own initiative in order to
 * re-negotiate the security parameters in an existing connection. See
 * <a href="https://tools.ietf.org/html/rfc5246#section-7.4.1.2" target=
 * "_blank">RFC 5246</a>.
 */
@NoPublicAPI
public final class ClientHello extends HelloHandshakeMessage {

	private static final int COOKIE_LENGTH_BITS = 8;

	private static final int CIPHER_SUITES_LENGTH_BITS = 16;

	private static final int COMPRESSION_METHODS_LENGTH_BITS = 8;

	/** The cookie used to prevent flooding attacks (potentially empty). */
	private byte[] cookie;

	/**
	 * This is a list of the cryptographic options supported by the client, with
	 * the client's first preference first.
	 */
	private final List<CipherSuite> supportedCipherSuites;

	/**
	 * This is a list of the compression methods supported by the client, sorted
	 * by client preference.
	 */
	private final List<CompressionMethod> compressionMethods;

	/**
	 * Creates a <em>Client Hello</em> message to be sent to a server.
	 * 
	 * @param version the protocol version to use
	 * @param supportedCipherSuites the list of the supported cipher suites in
	 *            order of the client’s preference (favorite choice first)
	 * @param supportedSignatureAndHashAlgorithms the list of the supported
	 *            signature and hash algorithms
	 * @param supportedClientCertificateTypes the list of certificate types
	 *            supported by the client
	 * @param supportedServerCertificateTypes the list of certificate types
	 *            supported by the server
	 * @param supportedGroups the list of the supported groups (curves) in order
	 *            of the client’s preference (favorite choice first)
	 * @since 2.3
	 */
	public ClientHello(ProtocolVersion version, List<CipherSuite> supportedCipherSuites,
			List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms,
			List<CertificateType> supportedClientCertificateTypes,
			List<CertificateType> supportedServerCertificateTypes, List<SupportedGroup> supportedGroups) {

		this(version, SessionId.emptySessionId(), supportedCipherSuites, supportedSignatureAndHashAlgorithms,
				supportedClientCertificateTypes, supportedServerCertificateTypes, supportedGroups);
	}

	/**
	 * Creates a <em>Client Hello</em> message to be used for resuming an
	 * existing DTLS session.
	 * 
	 * @param version the protocol version to use
	 * @param session the (already existing) DTLS session to resume
	 * @param supportedSignatureAndHashAlgorithms the list of the supported
	 *            signature and hash algorithms
	 * @param supportedClientCertificateTypes the list of certificate types
	 *            supported by the client
	 * @param supportedServerCertificateTypes the list of certificate types
	 *            supported by the server
	 * @param supportedGroups the list of the supported groups (curves) in order
	 *            of the client’s preference (favorite choice first)
	 * @since 2.3
	 */
	public ClientHello(ProtocolVersion version, DTLSSession session,
			List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms,
			List<CertificateType> supportedClientCertificateTypes,
			List<CertificateType> supportedServerCertificateTypes, List<SupportedGroup> supportedGroups) {

		this(version, session.getSessionIdentifier(), Arrays.asList(session.getCipherSuite()),
				supportedSignatureAndHashAlgorithms, supportedClientCertificateTypes, supportedServerCertificateTypes,
				supportedGroups);
		addCompressionMethod(session.getCompressionMethod());
	}

	private ClientHello(ProtocolVersion version, SessionId sessionId, List<CipherSuite> supportedCipherSuites,
			List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms,
			List<CertificateType> supportedClientCertificateTypes,
			List<CertificateType> supportedServerCertificateTypes, List<SupportedGroup> supportedGroups) {
		super(version, sessionId);

		this.cookie = Bytes.EMPTY;
		this.supportedCipherSuites = new ArrayList<>();
		if (supportedCipherSuites != null) {
			this.supportedCipherSuites.addAll(supportedCipherSuites);
		}
		this.compressionMethods = new ArrayList<>();
		// we only need to include elliptic_curves and point_format extensions
		// if the client supports at least one ECC based cipher suite
		if (CipherSuite.containsEccBasedCipherSuite(supportedCipherSuites)) {
			// the supported groups
			addExtension(new SupportedEllipticCurvesExtension(supportedGroups));

			// the supported point formats
			addExtension(SupportedPointFormatsExtension.DEFAULT_POINT_FORMATS_EXTENSION);
		}

		// the supported signature and hash algorithms
		if (!supportedSignatureAndHashAlgorithms.isEmpty()) {
			if (useCertificateTypeRawPublicKeyOnly(supportedClientCertificateTypes)
					&& useCertificateTypeRawPublicKeyOnly(supportedServerCertificateTypes)) {
				List<CertificateKeyAlgorithm> certificateKeyAlgorithms = CipherSuite
						.getCertificateKeyAlgorithms(supportedCipherSuites);
				supportedSignatureAndHashAlgorithms = SignatureAndHashAlgorithm.getCompatibleSignatureAlgorithms(
						supportedSignatureAndHashAlgorithms, certificateKeyAlgorithms);
			}
			addExtension(new SignatureAlgorithmsExtension(supportedSignatureAndHashAlgorithms));
		}

		if (CipherSuite.containsCipherSuiteRequiringCertExchange(supportedCipherSuites)) {
			// the certificate types the client is able to provide to the server
			if (useCertificateTypeExtension(supportedClientCertificateTypes)) {
				CertificateTypeExtension clientCertificateType = new ClientCertificateTypeExtension(
						supportedClientCertificateTypes);
				addExtension(clientCertificateType);
			}

			// the type of certificates the client is able to process when
			// provided
			// by the server
			if (useCertificateTypeExtension(supportedServerCertificateTypes)) {
				CertificateTypeExtension serverCertificateType = new ServerCertificateTypeExtension(
						supportedServerCertificateTypes);
				addExtension(serverCertificateType);
			}
		}
	}

	private ClientHello(DatagramReader reader) throws HandshakeException {
		super(reader);
		cookie = reader.readVarBytes(COOKIE_LENGTH_BITS);

		int cipherSuitesLength = reader.read(CIPHER_SUITES_LENGTH_BITS);
		DatagramReader rangeReader = reader.createRangeReader(cipherSuitesLength);
		supportedCipherSuites = CipherSuite.listFromReader(rangeReader);

		int compressionMethodsLength = reader.read(COMPRESSION_METHODS_LENGTH_BITS);
		rangeReader = reader.createRangeReader(compressionMethodsLength);
		compressionMethods = CompressionMethod.listFromReader(rangeReader);

		extensions.readFrom(reader);
		ServerNameExtension extension = getServerNameExtension();
		if (extension != null && extension.getServerNames() == null) {
			throw new HandshakeException("ClientHello message contains empty ServerNameExtension",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.DECODE_ERROR));
		}
	}

	/**
	 * Check, if certificate type extension is used.
	 * 
	 * If missing, or only contains X_509, don't send the extension.
	 * 
	 * @param supportedCertificateTypes list of certificate types
	 * @return {@code true}, if extension must be used, {@code false}, otherwise
	 */
	private boolean useCertificateTypeExtension(List<CertificateType> supportedCertificateTypes) {
		if (supportedCertificateTypes != null && !supportedCertificateTypes.isEmpty()) {
			return supportedCertificateTypes.size() > 1 || !supportedCertificateTypes.contains(CertificateType.X_509);
		}
		return false;
	}

	/**
	 * Check, if only raw public key certificates are used.
	 * 
	 * @param supportedCertificateTypes list of certificate types
	 * @return {@code true}, if only raw public key is used, {@code false},
	 *         otherwise
	 */
	private boolean useCertificateTypeRawPublicKeyOnly(List<CertificateType> supportedCertificateTypes) {
		if (supportedCertificateTypes != null && supportedCertificateTypes.size() == 1) {
			return supportedCertificateTypes.contains(CertificateType.RAW_PUBLIC_KEY);
		}
		return false;
	}

	@Override
	public byte[] fragmentToByteArray() {

		DatagramWriter writer = new DatagramWriter();
		writeHeader(writer);

		writer.writeVarBytes(cookie, COOKIE_LENGTH_BITS);

		writer.write(supportedCipherSuites.size() * CipherSuite.CIPHER_SUITE_BITS / Byte.SIZE,
				CIPHER_SUITES_LENGTH_BITS);
		CipherSuite.listToWriter(writer, supportedCipherSuites);

		writer.write(compressionMethods.size(), COMPRESSION_METHODS_LENGTH_BITS);
		CompressionMethod.listToWriter(writer, compressionMethods);

		extensions.writeTo(writer);

		return writer.toByteArray();
	}

	/**
	 * Creates a new ClientHello instance from its byte representation.
	 * 
	 * @param reader reader with the binary encoding of the message.
	 * @return the ClientHello object
	 * @throws HandshakeException if any of the extensions included in the
	 *             message is of an unsupported type
	 */
	public static ClientHello fromReader(DatagramReader reader) throws HandshakeException {
		return new ClientHello(reader);
	}

	@Override
	public String toString(int indent) {
		StringBuilder sb = new StringBuilder(super.toString(indent));
		String indentation = StringUtil.indentation(indent + 1);
		String indentation2 = StringUtil.indentation(indent + 2);
		sb.append(indentation).append("Cookie Length: ").append(cookie.length).append(" bytes")
				.append(StringUtil.lineSeparator());
		if (cookie.length > 0) {
			sb.append(indentation).append("Cookie: ").append(StringUtil.byteArray2HexString(cookie))
					.append(StringUtil.lineSeparator());
		}
		sb.append(indentation).append("Cipher Suites (").append(supportedCipherSuites.size()).append(" suites, ")
				.append(supportedCipherSuites.size() * CipherSuite.CIPHER_SUITE_BITS / Byte.SIZE).append(" bytes)")
				.append(StringUtil.lineSeparator());
		for (CipherSuite cipher : supportedCipherSuites) {
			sb.append(indentation2).append("Cipher Suite: ").append(cipher).append(StringUtil.lineSeparator());
		}
		sb.append(indentation).append("Compression Methods (").append(compressionMethods.size()).append(" methods, ")
				.append(compressionMethods.size()).append(" bytes)").append(StringUtil.lineSeparator());
		for (CompressionMethod method : compressionMethods) {
			sb.append(indentation2).append("Compression Method: ").append(method).append(StringUtil.lineSeparator());
		}
		sb.append(extensions.toString(indent + 1));
		return sb.toString();
	}

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.CLIENT_HELLO;
	}

	@Override
	public int getMessageLength() {

		// fixed sizes: version (2) + random (32) + session ID length (1) +
		// cookie length (1) + cipher suites length (2) + compression methods
		// length (1) = 39
		// variable sizes: session ID, supported cipher suites, compression
		// methods + extensions
		return 39 + sessionId.length() + cookie.length
				+ supportedCipherSuites.size() * CipherSuite.CIPHER_SUITE_BITS / Byte.SIZE + compressionMethods.size()
				+ extensions.getLength();
	}

	/**
	 * Get cookie.
	 * 
	 * @return cookie, or {@link Bytes#EMPTY}, if no cookie is available.
	 */
	public byte[] getCookie() {
		return cookie;
	}

	/**
	 * Checks, whether this message contains a cookie.
	 * 
	 * @return {@code true}, if the message contains a non-empty cookie
	 * @see #getCookie()
	 * @since 3.0
	 */
	public boolean hasCookie() {
		return cookie.length > 0;
	}

	/**
	 * Set received cookie.
	 * 
	 * Adjust fragment length.
	 * 
	 * @param cookie received cookie
	 * @throws NullPointerException if cookie is {@code null}
	 * @throws IllegalArgumentException if cookie is empty
	 */
	public void setCookie(byte[] cookie) {
		if (cookie == null) {
			throw new NullPointerException("cookie must not be null!");
		} else if (cookie.length == 0) {
			throw new IllegalArgumentException("cookie must not be empty!");
		}
		this.cookie = Arrays.copyOf(cookie, cookie.length);
		fragmentChanged();
	}

	/**
	 * Update hmac for cookie generation.
	 * 
	 * @param hmac initialized hmac*
	 * @since 3.11 use no {@link HelloExtensions} for the cookie, use only the
	 *        parameter values (version, random, session_id, cipher_suites,
	 *        compression_method). Considering DTLS 1.3 clients, which may vary
	 *        additional data, including more in the cookie will cause "endless
	 *        retries" instead of abort the handshake with an alert.
	 */
	public void updateForCookie(Mac hmac) {
		byte[] rawMessage = toByteArray();
		int head = sessionId.length() + RANDOM_BYTES
				+ (VERSION_BITS + VERSION_BITS + SESSION_ID_LENGTH_BITS) / Byte.SIZE;
		int tail = head + COOKIE_LENGTH_BITS / Byte.SIZE + MESSAGE_HEADER_LENGTH_BYTES;
		if (cookie != null) {
			tail += cookie.length;
		}
		int tailLength = (CIPHER_SUITES_LENGTH_BITS + CIPHER_SUITES_LENGTH_BITS
				+ supportedCipherSuites.size() * CipherSuite.CIPHER_SUITE_BITS
				+ compressionMethods.size() * CompressionMethod.COMPRESSION_METHOD_BITS) / Byte.SIZE;

		hmac.update(rawMessage, MESSAGE_HEADER_LENGTH_BYTES, head);
		hmac.update(rawMessage, tail, tailLength);
	}

	/**
	 * Get proposed cipher suites.
	 * 
	 * @return list of proposed cipher suites.
	 */
	public List<CipherSuite> getCipherSuites() {
		return Collections.unmodifiableList(supportedCipherSuites);
	}

	/**
	 * Get list of common cipher suites.
	 * 
	 * List of cipher suites shared by client and server.
	 * 
	 * @param serverCipherSuite server's cipher suites.
	 * @return list of common cipher suites
	 * @since 3.0
	 */
	public List<CipherSuite> getCommonCipherSuites(List<CipherSuite> serverCipherSuite) {
		return CipherSuite.preselectCipherSuites(serverCipherSuite, supportedCipherSuites);
	}

	/**
	 * Get compression methods.
	 * 
	 * @return unmodifiable list of compression methods. Only
	 *         {@link CompressionMethod#NULL} is supported.
	 */
	public List<CompressionMethod> getCompressionMethods() {
		return Collections.unmodifiableList(compressionMethods);
	}

	/**
	 * Set compression methods.
	 * 
	 * @param compressionMethods list of compression methods. Only
	 *            {@link CompressionMethod#NULL} is supported.
	 */
	public void setCompressionMethods(List<CompressionMethod> compressionMethods) {
		ListUtils.addIfAbsent(this.compressionMethods, compressionMethods);
	}

	/**
	 * Add compression method.
	 * 
	 * @param compressionMethod compression method. Only
	 *            {@link CompressionMethod#NULL} is supported.
	 */
	public void addCompressionMethod(CompressionMethod compressionMethod) {
		ListUtils.addIfAbsent(compressionMethods, compressionMethod);
	}

	/**
	 * Gets the <em>Server Names</em> of the extension data from this message.
	 * 
	 * @return the server names, or {@code null}, if this message does not
	 *         contain the <em>Server Name Indication</em> extension.
	 */
	public ServerNames getServerNames() {
		ServerNameExtension extension = getServerNameExtension();
		return extension == null ? null : extension.getServerNames();
	}

	/**
	 * Gets the supported elliptic curves.
	 * 
	 * @return the client's supported elliptic curves extension if available,
	 *         otherwise {@code null}.
	 */
	public SupportedEllipticCurvesExtension getSupportedEllipticCurvesExtension() {
		return extensions.getExtension(ExtensionType.ELLIPTIC_CURVES);
	}

	/**
	 * Checks, if either the {@link RenegotiationInfoExtension} or the
	 * {@link CipherSuite#TLS_EMPTY_RENEGOTIATION_INFO_SCSV} is available.
	 * 
	 * Californium doesn't support renegotiation at all, but RFC5746 requests to
	 * update to a minimal version of RFC 5746.
	 * 
	 * See <a href="https://tools.ietf.org/html/rfc5746" target="_blank">RFC
	 * 5746</a> for additional details.
	 * 
	 * @return {@code true}, if available, {@code false}, if not.
	 * @since 3.8
	 */
	public boolean hasRenegotiationInfo() {
		return hasRenegotiationInfoExtension()
				|| supportedCipherSuites.contains(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
	}

}
