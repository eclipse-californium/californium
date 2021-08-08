/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.util.List;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.NoPublicAPI;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.HelloExtension.ExtensionType;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * Common base for {@link ClientHello} and {@link ServerHello}.
 * 
 * @since 3.0
 */
@NoPublicAPI
public abstract class HelloHandshakeMessage extends HandshakeMessage {

	protected static final int VERSION_BITS = 8; // for major and minor each

	protected static final int RANDOM_BYTES = 32;

	protected static final int SESSION_ID_LENGTH_BITS = 8;

	/**
	 * The version of the DTLS protocol.
	 */
	protected final ProtocolVersion protocolVersion;

	/** A generated random structure. */
	protected final Random random;

	/** The ID of a session the client wishes to use for this connection. */
	protected final SessionId sessionId;

	/**
	 * Clients MAY request extended functionality from servers by sending data
	 * in the extensions field.
	 */
	protected final HelloExtensions extensions = new HelloExtensions();

	protected HelloHandshakeMessage(ProtocolVersion version, SessionId sessionId) {
		if (version == null) {
			throw new NullPointerException("Negotiated protocol version must not be null");
		}
		if (sessionId == null) {
			throw new NullPointerException("ServerHello must be associated with a session ID");
		}
		this.protocolVersion = version;
		this.sessionId = sessionId;
		this.random = new Random();
	}

	protected HelloHandshakeMessage(ProtocolVersion version, SessionId sessionId,
			List<CipherSuite> supportedCipherSuites,
			List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms,
			List<CertificateType> supportedClientCertificateTypes,
			List<CertificateType> supportedServerCertificateTypes,
			List<SupportedGroup> supportedGroups) {
		this(version, sessionId);

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
				supportedSignatureAndHashAlgorithms = SignatureAndHashAlgorithm
						.getEcdsaCompatibleSignatureAlgorithms(supportedSignatureAndHashAlgorithms);
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

	protected HelloHandshakeMessage(DatagramReader reader) throws HandshakeException {
		int major = reader.read(VERSION_BITS);
		int minor = reader.read(VERSION_BITS);
		protocolVersion = ProtocolVersion.valueOf(major, minor);

		random = new Random(reader.readBytes(RANDOM_BYTES));

		sessionId = new SessionId(reader.readVarBytes(SESSION_ID_LENGTH_BITS));
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

	protected void writeHeader(DatagramWriter writer) {

		writer.write(protocolVersion.getMajor(), VERSION_BITS);
		writer.write(protocolVersion.getMinor(), VERSION_BITS);

		writer.writeBytes(random.getBytes());

		writer.writeVarBytes(sessionId, SESSION_ID_LENGTH_BITS);
	}

	@Override
	public String toString(int indent) {
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString(indent));
		String indentation = StringUtil.indentation(indent + 1);
		sb.append(indentation).append("Version: ").append(protocolVersion.getMajor()).append(", ").append(protocolVersion.getMinor()).append(StringUtil.lineSeparator());
		sb.append(indentation).append("Random:").append(StringUtil.lineSeparator());
		sb.append(random.toString(indent + 2));
		sb.append(indentation).append("Session ID Length: ").append(sessionId.length()).append(" bytes").append(StringUtil.lineSeparator());
		if (sessionId.length() > 0) {
			sb.append(indentation).append("Session ID: ").append(sessionId).append(StringUtil.lineSeparator());
		}
		return sb.toString();
	}

	/**
	 * Get protocol version.
	 * 
	 * @return protocol version.
	 */
	public ProtocolVersion getProtocolVersion() {
		return protocolVersion;
	}

	/**
	 * Get client random
	 * 
	 * @return client random
	 */
	public Random getRandom() {
		return random;
	}

	/**
	 * Get session id.
	 * 
	 * @return session id. May be empty.
	 * @see #hasSessionId()
	 */
	public SessionId getSessionId() {
		return sessionId;
	}

	/**
	 * Checks, whether this message contains a session ID.
	 * 
	 * @return {@code true}, if the message contains a non-empty session ID
	 * @see #getSessionId()
	 */
	public boolean hasSessionId() {
		return !sessionId.isEmpty();
	}

	/**
	 * Add hello extension.
	 * 
	 * @param extension hello extension to add
	 */
	void addExtension(HelloExtension extension) {
		extensions.addExtension(extension);
	}

	/**
	 * Gets the client hello extensions the client has included in this message.
	 * 
	 * @return The extensions. May be empty, if no extensions are used.
	 */
	public HelloExtensions getExtensions() {
		return extensions;
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
	 * Gets the supported point formats.
	 * 
	 * @return the client's supported point formats extension if available,
	 *         otherwise {@code null}.
	 */
	public SupportedPointFormatsExtension getSupportedPointFormatsExtension() {
		return extensions.getExtension(ExtensionType.EC_POINT_FORMATS);
	}

	/**
	 * Gets the client's certificate type extension.
	 * 
	 * @return the client's certificate type extension if available, otherwise
	 *         {@code null}.
	 */
	public ClientCertificateTypeExtension getClientCertificateTypeExtension() {
		return extensions.getExtension(ExtensionType.CLIENT_CERT_TYPE);
	}

	/**
	 * Gets the servers's certificate type extension.
	 * 
	 * @return the servers's certificate type extension if available, otherwise
	 *         {@code null}.
	 */
	public ServerCertificateTypeExtension getServerCertificateTypeExtension() {
		return extensions.getExtension(ExtensionType.SERVER_CERT_TYPE);
	}

	/**
	 * Gets the <em>Signature and Hash Algorithms</em> extension data from this
	 * message.
	 * 
	 * @return the extension data or {@code null}, if this message does not
	 *         contain the <em>SignatureAlgorithms</em> extension.
	 */
	public SignatureAlgorithmsExtension getSupportedSignatureAlgorithmsExtension() {
		return (SignatureAlgorithmsExtension) extensions.getExtension(ExtensionType.SIGNATURE_ALGORITHMS);
	}

	/**
	 * Gets the <em>MaximumFragmentLength</em> extension data from this message.
	 * 
	 * @return the extension data or {@code null}, if this message does not
	 *         contain the <em>MaximumFragmentLength</em> extension.
	 */
	public MaxFragmentLengthExtension getMaxFragmentLengthExtension() {
		return extensions.getExtension(ExtensionType.MAX_FRAGMENT_LENGTH);
	}

	/**
	 * Gets the <em>RecordSizeLimit</em> extension data from this message.
	 * 
	 * @return the extension data or {@code null}, if this message does not
	 *         contain the <em>RecordSizeLimit</em> extension.
	 */
	public RecordSizeLimitExtension getRecordSizeLimitExtension() {
		return extensions.getExtension(ExtensionType.RECORD_SIZE_LIMIT);
	}

	/**
	 * Gets the <em>Server Name Indication</em> extension data from this
	 * message.
	 * 
	 * @return the extension data or {@code null}, if this message does not
	 *         contain the <em>Server Name Indication</em> extension.
	 */
	public ServerNameExtension getServerNameExtension() {
		return extensions.getExtension(ExtensionType.SERVER_NAME);
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
	 * Gets the <em>connection id</em> extension data from this message.
	 * 
	 * @return the extension data or {@code null}, if this message does not
	 *         contain the <em>connection id</em> extension.
	 */
	public ConnectionIdExtension getConnectionIdExtension() {
		return extensions.getExtension(ExtensionType.CONNECTION_ID);
	}

	/**
	 * Checks whether <em>ExtendedMasterSecret</em> extension is present in this
	 * message.
	 * 
	 * @return {@code true}, if the <em>ExtendedMasterSecret</em> extension is
	 *         present, {@code false}, otherwise
	 */
	public boolean hasExtendedMasterSecretExtension() {
		return extensions.getExtension(ExtensionType.EXTENDED_MASTER_SECRET) != null;
	}

}
