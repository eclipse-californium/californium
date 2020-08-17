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

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.NoPublicAPI;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.HelloExtension.ExtensionType;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;

/**
 * When a client first connects to a server, it is required to send the
 * ClientHello as its first message. The client can also send a ClientHello in
 * response to a {@link HelloRequest} or on its own initiative in order to
 * re-negotiate the security parameters in an existing connection. See
 * <a href="http://tools.ietf.org/html/rfc5246#section-7.4.1.2">RFC 5246</a>.
 */
@NoPublicAPI
public final class ClientHello extends HandshakeMessage {

	// DTLS-specific constants ///////////////////////////////////////////

	private static final int VERSION_BITS = 8; // for major and minor each

	private static final int RANDOM_BYTES = 32;

	private static final int SESSION_ID_LENGTH_BITS = 8;

	private static final int COOKIE_LENGTH = 8;

	private static final int CIPHER_SUITS_LENGTH_BITS = 16;

	private static final int COMPRESSION_METHODS_LENGTH_BITS = 8;

	// Members ///////////////////////////////////////////////////////////

	/**
	 * The version of the DTLS protocol by which the client wishes to
	 * communicate during this session.
	 */
	private ProtocolVersion clientVersion;

	/** A client-generated random structure. */
	private Random random;

	/** The ID of a session the client wishes to use for this connection. */
	private SessionId sessionId;

	/** The cookie used to prevent flooding attacks (potentially empty). */
	private byte[] cookie;

	/**
	 * This is a list of the cryptographic options supported by the client, with
	 * the client's first preference first.
	 */
	private List<CipherSuite> supportedCipherSuites = new ArrayList<>();

	/**
	 * This is a list of the compression methods supported by the client, sorted
	 * by client preference.
	 */
	private List<CompressionMethod> compressionMethods = new ArrayList<>();

	/**
	 * Clients MAY request extended functionality from servers by sending data
	 * in the extensions field.
	 */
	private HelloExtensions extensions = new HelloExtensions();

	// Constructors ///////////////////////////////////////////////////////////

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
	 * @param supportedGroups the list of the supported groups (curves) in order of
	 *            the client’s preference (favorite choice first)
	 * @param peerAddress the IP address and port of the peer this message has
	 *            been received from or should be sent to
	 * @since 2.3
	 */
	public ClientHello(
			ProtocolVersion version,
			List<CipherSuite> supportedCipherSuites,
			List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms,
			List<CertificateType> supportedClientCertificateTypes,
			List<CertificateType> supportedServerCertificateTypes,
			List<SupportedGroup> supportedGroups,
			InetSocketAddress peerAddress) {

		this(version, null, supportedCipherSuites, supportedSignatureAndHashAlgorithms, supportedClientCertificateTypes,
				supportedServerCertificateTypes, supportedGroups, peerAddress);
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
	 * @param supportedGroups the list of the supported groups (curves) in order of
	 *            the client’s preference (favorite choice first)
	 * @since 2.3
	 */
	public ClientHello(
			ProtocolVersion version,
			DTLSSession session,
			List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms,
			List<CertificateType> supportedClientCertificateTypes,
			List<CertificateType> supportedServerCertificateTypes,
			List<SupportedGroup> supportedGroups) {

		this(version, session.getSessionIdentifier(), Arrays.asList(session.getCipherSuite()),
				supportedSignatureAndHashAlgorithms, supportedClientCertificateTypes, supportedServerCertificateTypes,
				supportedGroups, session.getPeer());
		addCompressionMethod(session.getWriteState().getCompressionMethod());
	}

	private ClientHello(
			ProtocolVersion version,
			SessionId sessionId,
			List<CipherSuite> supportedCipherSuites,
			List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms,
			List<CertificateType> supportedClientCertificateTypes,
			List<CertificateType> supportedServerCertificateTypes,
			List<SupportedGroup> supportedGroups,
			InetSocketAddress peerAddress) {

		this(peerAddress);
		this.clientVersion = version;
		this.random = new Random();
		this.cookie = Bytes.EMPTY;
		if (sessionId != null) {
			this.sessionId = sessionId;
		} else {
			this.sessionId = SessionId.emptySessionId();
		}
		if (supportedCipherSuites != null) {
			this.supportedCipherSuites.addAll(supportedCipherSuites);
		}

		// we only need to include elliptic_curves and point_format extensions
		// if the client supports at least one ECC based cipher suite
		if (CipherSuite.containsEccBasedCipherSuite(supportedCipherSuites)) {
			// the supported groups
			this.extensions.addExtension(new SupportedEllipticCurvesExtension(supportedGroups));

			// the supported point formats
			this.extensions.addExtension(SupportedPointFormatsExtension.DEFAULT_POINT_FORMATS_EXTENSION);
		}

		// the supported signature and hash algorithms
		if (!supportedSignatureAndHashAlgorithms.isEmpty()) {
			if (useCertificateTypeRawPublicKeyOnly(supportedClientCertificateTypes)
					&& useCertificateTypeRawPublicKeyOnly(supportedServerCertificateTypes)) {
				supportedSignatureAndHashAlgorithms = SignatureAndHashAlgorithm
						.getEcdsaCompatibleSignatureAlgorithms(supportedSignatureAndHashAlgorithms);
			}
			this.extensions.addExtension(new SignatureAlgorithmsExtension(supportedSignatureAndHashAlgorithms));
		}

		// the certificate types the client is able to provide to the server
		if (useCertificateTypeExtension(supportedClientCertificateTypes)) {
			CertificateTypeExtension clientCertificateType = new ClientCertificateTypeExtension(supportedClientCertificateTypes);
			this.extensions.addExtension(clientCertificateType);
		}

		// the type of certificates the client is able to process when provided
		// by the server
		if (useCertificateTypeExtension(supportedServerCertificateTypes)) {
			CertificateTypeExtension serverCertificateType = new ServerCertificateTypeExtension(supportedServerCertificateTypes);
			this.extensions.addExtension(serverCertificateType);
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

	private ClientHello(InetSocketAddress peerAddress) {
		super(peerAddress);
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	public byte[] fragmentToByteArray() {

		DatagramWriter writer = new DatagramWriter();

		writer.write(clientVersion.getMajor(), VERSION_BITS);
		writer.write(clientVersion.getMinor(), VERSION_BITS);

		writer.writeBytes(random.getBytes());

		writer.write(sessionId.length(), SESSION_ID_LENGTH_BITS);
		writer.writeBytes(sessionId.getBytes());

		writer.write(cookie.length, COOKIE_LENGTH);
		writer.writeBytes(cookie);

		writer.write(supportedCipherSuites.size() * 2, CIPHER_SUITS_LENGTH_BITS);
		writer.writeBytes(CipherSuite.listToByteArray(supportedCipherSuites));

		writer.write(compressionMethods.size(), COMPRESSION_METHODS_LENGTH_BITS);
		writer.writeBytes(CompressionMethod.listToByteArray(compressionMethods));

		if (extensions != null) {
			writer.writeBytes(extensions.toByteArray());
		}

		return writer.toByteArray();
	}

	/**
	 * Creates a new ClientHello instance from its byte representation.
	 * 
	 * @param reader 
	 *            reader with the binary encoding of the message.
	 * @param peerAddress
	 *            the IP address and port of the peer this message has been
	 *            received from or should be sent to
	 * @return the ClientHello object
	 * @throws HandshakeException
	 *             if any of the extensions included in the message is of an
	 *             unsupported type
	 */
	public static ClientHello fromReader(DatagramReader reader, InetSocketAddress peerAddress)
			throws HandshakeException {
		ClientHello result = new ClientHello(peerAddress);

		int major = reader.read(VERSION_BITS);
		int minor = reader.read(VERSION_BITS);
		result.clientVersion = ProtocolVersion.valueOf(major, minor);

		result.random = new Random(reader.readBytes(RANDOM_BYTES));

		int sessionIdLength = reader.read(SESSION_ID_LENGTH_BITS);
		result.sessionId = new SessionId(reader.readBytes(sessionIdLength));

		int cookieLength = reader.read(COOKIE_LENGTH);
		result.cookie = reader.readBytes(cookieLength);

		int cipherSuitesLength = reader.read(CIPHER_SUITS_LENGTH_BITS);
		DatagramReader rangeReader = reader.createRangeReader(cipherSuitesLength);
		result.supportedCipherSuites = CipherSuite.listFromReader(rangeReader);

		int compressionMethodsLength = reader.read(COMPRESSION_METHODS_LENGTH_BITS);
		rangeReader = reader.createRangeReader(compressionMethodsLength);
		result.compressionMethods = CompressionMethod.listFromReader(rangeReader);

		if (reader.bytesAvailable()) {
			result.extensions = HelloExtensions.fromReader(reader, peerAddress);
		}
		return result;

	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.CLIENT_HELLO;
	}

	@Override
	public int getMessageLength() {

		// if no extensions set, empty; otherwise 2 bytes for field length and
		// then the length of the extensions. See
		// http://tools.ietf.org/html/rfc5246#section-7.4.1.2
		int extensionsLength = (extensions == null || extensions.isEmpty()) ? 0 : (2 + extensions.getLength());

		// fixed sizes: version (2) + random (32) + session ID length (1) +
		// cookie length (1) + cipher suites length (2) + compression methods
		// length (1) = 39
		return 39 + sessionId.length() + cookie.length + supportedCipherSuites.size() * 2 + compressionMethods.size()
				+ extensionsLength;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString());
		sb.append("\t\tVersion: ").append(clientVersion.getMajor()).append(", ").append(clientVersion.getMinor());
		sb.append(StringUtil.lineSeparator()).append("\t\tRandom:").append(StringUtil.lineSeparator()).append(random);
		sb.append("\t\tSession ID Length: ").append(sessionId.length());
		if (sessionId.length() > 0) {
			sb.append(StringUtil.lineSeparator()).append("\t\tSession ID: ").append(sessionId);
		}
		sb.append(StringUtil.lineSeparator()).append("\t\tCookie Length: ").append(cookie.length);
		if (cookie.length > 0) {
			sb.append(StringUtil.lineSeparator()).append("\t\tCookie: ").append(StringUtil.byteArray2HexString(cookie));
		}
		sb.append(StringUtil.lineSeparator()).append("\t\tCipher Suites Length: ").append(supportedCipherSuites.size() * 2);
		sb.append(StringUtil.lineSeparator()).append("\t\tCipher Suites (").append(supportedCipherSuites.size()).append(" suites)");
		for (CipherSuite cipher : supportedCipherSuites) {
			sb.append(StringUtil.lineSeparator()).append("\t\t\tCipher Suite: ").append(cipher);
		}
		sb.append(StringUtil.lineSeparator()).append("\t\tCompression Methods Length: ").append(compressionMethods.size());
		sb.append(StringUtil.lineSeparator()).append("\t\tCompression Methods (").append(compressionMethods.size()).append(" method)");
		for (CompressionMethod method : compressionMethods) {
			sb.append(StringUtil.lineSeparator()).append("\t\t\tCompression Method: ").append(method);
		}
		if (extensions != null) {
			sb.append(StringUtil.lineSeparator()).append(extensions);
		}

		return sb.toString();
	}

	// Getters and Setters ////////////////////////////////////////////

	public ProtocolVersion getClientVersion() {
		return clientVersion;
	}

	public Random getRandom() {
		return random;
	}

	public SessionId getSessionId() {
		return sessionId;
	}

	/**
	 * Checks whether this message contains a session ID.
	 * 
	 * @return <code>true</code> if the message contains a non-null session ID with length &gt; 0
	 */
	public boolean hasSessionId() {
		return sessionId != null && sessionId.length() > 0;
	}

	void setSessionId(SessionId sessionId) {
		this.sessionId = sessionId;
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

	public List<CipherSuite> getCipherSuites() {
		return Collections.unmodifiableList(supportedCipherSuites);
	}

	public List<CompressionMethod> getCompressionMethods() {
		return Collections.unmodifiableList(compressionMethods);
	}

	public void setCompressionMethods(List<CompressionMethod> compressionMethods) {
		this.compressionMethods.addAll(compressionMethods);
	}

	public void addCompressionMethod(CompressionMethod compressionMethod) {
		if (compressionMethods == null) {
			compressionMethods = new ArrayList<CompressionMethod>();
		}
		compressionMethods.add(compressionMethod);
	}

	void addExtension(HelloExtension extension) {
		if (extensions != null) {
			extensions.addExtension(extension);
		}
	}

	/**
	 * Gets the client hello extensions the client has included in this message.
	 * 
	 * @return The extensions or {@code null} if no extensions are used.
	 */
	public HelloExtensions getExtensions() {
		return extensions;
	}

	/**
	 * Gets the supported elliptic curves.
	 * 
	 * @return the client's supported elliptic curves extension if available,
	 *         otherwise <code>null</code>.
	 */
	public SupportedEllipticCurvesExtension getSupportedEllipticCurvesExtension() {
		if (extensions != null) {
			return (SupportedEllipticCurvesExtension) extensions.getExtension(ExtensionType.ELLIPTIC_CURVES);
		} else {
			return null;
		}
	}

	/**
	 * Gets the supported point formats.
	 * 
	 * @return the client's supported point formats extension if available,
	 *         otherwise <code>null</code>.
	 */
	public SupportedPointFormatsExtension getSupportedPointFormatsExtension() {
		if (extensions != null) {
			return (SupportedPointFormatsExtension) extensions.getExtension(ExtensionType.EC_POINT_FORMATS);
		} else {
			return null;
		}
	}

	/**
	 * 
	 * @return the client's certificate type extension if available, otherwise
	 *         <code>null</code>.
	 */
	public ClientCertificateTypeExtension getClientCertificateTypeExtension() {
		if (extensions != null) {
			return (ClientCertificateTypeExtension) extensions.getExtension(ExtensionType.CLIENT_CERT_TYPE);
		} else {
			return null;
		}
	}

	/**
	 * 
	 * @return the client's certificate type extension if available, otherwise
	 *         <code>null</code>.
	 */
	public ServerCertificateTypeExtension getServerCertificateTypeExtension() {
		if (extensions != null) {
			return (ServerCertificateTypeExtension) extensions.getExtension(ExtensionType.SERVER_CERT_TYPE);
		} else {
			return null;
		}
	}

	/**
	 * Gets the <em>Signature and Hash Algorithms</em> extension data from this message.
	 * 
	 * @return the extension data or <code>null</code> if this message does not contain the
	 *          <em>SignatureAlgorithms</em> extension.
	 * 
	 * @since 2.3
	 */
	public SignatureAlgorithmsExtension getSupportedSignatureAlgorithms() {
		if (extensions != null) {
			return (SignatureAlgorithmsExtension) extensions.getExtension(ExtensionType.SIGNATURE_ALGORITHMS);
		} else {
			return null;
		}
	}

	/**
	 * Gets the <em>MaximumFragmentLength</em> extension data from this message.
	 * 
	 * @return the extension data or <code>null</code> if this message does not contain the
	 *          <em>MaximumFragmentLength</em> extension.
	 */
	public MaxFragmentLengthExtension getMaxFragmentLengthExtension() {
		if (extensions != null) {
			return (MaxFragmentLengthExtension) extensions.getExtension(ExtensionType.MAX_FRAGMENT_LENGTH);
		} else {
			return null;
		}
	}

	/**
	 * Gets the <em>RecordSizeLimit</em> extension data from this message.
	 * 
	 * @return the extension data or <code>null</code> if this message does not contain the
	 *          <em>RecordSizeLimit</em> extension.
	 * @since 2.4
	 */
	public RecordSizeLimitExtension getRecordSizeLimitExtension() {
		if (extensions != null) {
			return (RecordSizeLimitExtension) extensions.getExtension(ExtensionType.RECORD_SIZE_LIMIT);
		} else {
			return null;
		}
	}

	/**
	 * Gets the <em>Server Name Indication</em> extension data from this message.
	 * 
	 * @return the extension data or <code>null</code> if this message does not contain the
	 *          <em>Server Name Indication</em> extension.
	 */
	public ServerNameExtension getServerNameExtension() {
		if (extensions != null) {
			return (ServerNameExtension) extensions.getExtension(ExtensionType.SERVER_NAME);
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
}
