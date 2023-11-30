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
 *    Kai Hudalla (Bosch Software Innovtions GmbH) - small improvements
 *    Kai Hudalla (Bosch Software Innovations GmbH) - store peer's identity in session as a
 *                                                    java.security.Principal (fix 464812)
 *    Kai Hudalla (Bosch Software Innovations GmbH) - notify SessionListener about start and completion
 *                                                    of handshake
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix 475112: only prefer RawPublicKey from server
 *                                                    if no trust store has been configured
 *    Kai Hudalla (Bosch Software Innovations GmbH) - consolidate and fix record buffering and message re-assembly
 *    Kai Hudalla (Bosch Software Innovations GmbH) - replace Handshaker's compressionMethod and cipherSuite
 *                                                    properties with corresponding properties in DTLSSession
 *    Kai Hudalla (Bosch Software Innovations GmbH) - derive max fragment length from network MTU
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use SessionListener to trigger sending of pending
 *                                                    APPLICATION messages
 *    Achim Kraus (Bosch Software Innovations GmbH) - use isSendRawKey also for
 *                                                    supportedServerCertificateTypes
 *    Ludwig Seitz (RISE SICS) - Updated calls to verifyCertificate() after refactoring
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - add certificate types only,
 *                                                    if certificates are used
 *    Achim Kraus (Bosch Software Innovations GmbH) - issue #549
 *                                                    trustStore := null, disable x.509
 *                                                    trustStore := [], enable x.509, trust all
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix usage of literal address
 *                                                    with enabled sni
 *    Vikram (University of Rostock) - added ECDHE_PSK mode
 *    Achim Kraus (Bosch Software Innovations GmbH) - add handshake parameter available to
 *                                                    process reordered handshake messages
 *    Achim Kraus (Bosch Software Innovations GmbH) - add dtls flight number
 *    Achim Kraus (Bosch Software Innovations GmbH) - redesign DTLSFlight and RecordLayer
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;

import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.util.NoPublicAPI;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConfig.DtlsSecureRenegotiation;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.HelloExtension.ExtensionType;
import org.eclipse.californium.scandium.dtls.MaxFragmentLengthExtension.Length;
import org.eclipse.californium.scandium.dtls.SupportedPointFormatsExtension.ECPointFormat;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ClientHandshaker does the protocol handshaking from the point of view of a
 * client. It is driven by handshake messages as delivered by the parent
 * {@link Handshaker} class. The message flow is depicted in
 * <a href="https://tools.ietf.org/html/rfc6347#page-21" target= "_blank">Figure
 * 1</a>.
 * 
 * <pre>
 *   Client                                          Server
 *   ------                                          ------
 *
 *   ClientHello             --------&gt;                           Flight 1
 *
 *                           &lt;--------   HelloVerifyRequest      Flight 2
 *
 *   ClientHello             --------&gt;                           Flight 3
 *
 *                                              ServerHello    \
 *                                             Certificate*     \
 *                                       ServerKeyExchange*      Flight 4
 *                                      CertificateRequest*     /
 *                           &lt;--------      ServerHelloDone    /
 *
 *   Certificate*                                              \
 *   ClientKeyExchange                                          \
 *   CertificateVerify*                                          Flight 5
 *   [ChangeCipherSpec]                                         /
 *   Finished                --------&gt;                         /
 *
 *                                       [ChangeCipherSpec]    \ Flight 6
 *                           &lt;--------             Finished    /
 * </pre>
 * 
 * <p>
 * This implementation offers a probing mode.
 * 
 * If a mobile peer doesn't get a ACK or response that may have two different
 * causes:
 * </p>
 * 
 * <ol>
 * <li>server has lost session (association)</li>
 * <li>connectivity is lost</li>
 * </ol>
 * 
 * <p>
 * The second is sometime hard to detect; the peer's state is connected, but
 * effectively it's not working. In that case, after some retransmissions, the
 * peer starts a handshake. Without the probing mode starting a handshake
 * removes on the client the session. If the handshake timesout (though the
 * connection is not working), the peer still requires a new handshake after the
 * connectivity is established again.
 * 
 * With probing mode, the handshake starts without removing the session. If some
 * data is received, the session is removed and the handshake gets completed. If
 * no data is received, the peer assumes, that the connectivity is lost (even if
 * it's own state indicates connectivity) and just timesout the request. If the
 * connectivity is established again, just a new request could be send without a
 * handshake.
 * </p>
 */
@NoPublicAPI
public class ClientHandshaker extends Handshaker {

	/**
	 * @since 3.10
	 */
	private final Logger LOGGER = LoggerFactory.getLogger(getClass());

	protected static final HandshakeState[] INIT = {
			new HandshakeState(HandshakeType.HELLO_VERIFY_REQUEST, true),
			new HandshakeState(HandshakeType.SERVER_HELLO) };

	protected static final HandshakeState[] SEVER_CERTIFICATE = {
			new HandshakeState(HandshakeType.CERTIFICATE),
			new HandshakeState(HandshakeType.SERVER_KEY_EXCHANGE),
			new HandshakeState(HandshakeType.CERTIFICATE_REQUEST, true),
			new HandshakeState(HandshakeType.SERVER_HELLO_DONE),
			new HandshakeState(ContentType.CHANGE_CIPHER_SPEC),
			new HandshakeState(HandshakeType.FINISHED) };

	private static final HandshakeState[] NO_SEVER_CERTIFICATE = {
			new HandshakeState(HandshakeType.SERVER_KEY_EXCHANGE, true),
			new HandshakeState(HandshakeType.SERVER_HELLO_DONE),
			new HandshakeState(ContentType.CHANGE_CIPHER_SPEC),
			new HandshakeState(HandshakeType.FINISHED) };

	private ProtocolVersion maxProtocolVersion = ProtocolVersion.VERSION_DTLS_1_2;

	/**
	 * Indicates probing for this handshake.
	 */
	private boolean probe;

	/**
	 * Indicates received server hello done.
	 * 
	 * @since 3.0
	 */
	private boolean receivedServerHelloDone;

	/**
	 * The server's key exchange message
	 * 
	 * @since 2.3
	 */
	private ECDHServerKeyExchange serverKeyExchange;

	/**
	 * The client's hello handshake message.
	 * 
	 * Store it, to add the cookie in the second flight.
	 */
	protected ClientHello clientHello;

	/**
	 * The client's flight 5.
	 * 
	 * @since 3.0
	 */
	protected DTLSFlight flight5;

	/**
	 * the supported cipher suites ordered by preference
	 * 
	 * @since 2.3
	 */
	private final List<CipherSuite> supportedCipherSuites;

	/**
	 * Secure renegotiation mode.
	 * 
	 * Californium doesn't support renegotiation at all, but RFC5746 requests to
	 * update to a minimal version.
	 * 
	 * See <a href="https://tools.ietf.org/html/rfc5746" target="_blank">RFC
	 * 5746</a> for additional details.
	 * 
	 * @since 3.8
	 */
	private final DtlsSecureRenegotiation secureRenegotiation;

	/**
	 * the supported groups (curves) ordered by preference
	 * 
	 * @since 2.3
	 */
	protected final List<SupportedGroup> supportedGroups;

	/**
	 * Maximum fragment length.
	 */
	protected final Length maxFragmentLength;
	/**
	 * Truncate certificate path.
	 */
	protected final boolean truncateCertificatePath;

	/**
	 * The certificate types this peer supports for client authentication.
	 */
	protected final List<CertificateType> supportedClientCertificateTypes;

	/**
	 * The list of the signature and hash algorithms supported by the client
	 * ordered by preference.
	 * 
	 * @since 2.3
	 */
	protected final List<SignatureAndHashAlgorithm> supportedSignatureAlgorithms;

	/**
	 * The certificate types this peer supports for server authentication.
	 */
	protected final List<CertificateType> supportedServerCertificateTypes;

	/**
	 * Use the deprecated CID extension before version 9 of <a href=
	 * "https://datatracker.ietf.org/doc/draft-ietf-tls-dtls-connection-id/"
	 * target="_blank">Draft dtls-connection-id</a>.
	 * 
	 * @since 3.0
	 */
	private final Integer useDeprecatedCid;
	/**
	 * Verify the server certificate's subject.
	 * 
	 * @see DtlsConfig#DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT
	 * @since 3.0
	 */
	private final boolean verifyServerCertificatesSubject;

	/**
	 * The server's {@link CertificateRequest}. Optional.
	 */
	private CertificateRequest certificateRequest;

	/**
	 * The hash of all received handshake messages sent in the finished message.
	 */
	protected byte[] handshakeHash;

	/**
	 * Creates a new handshaker for negotiating a DTLS session with a server.
	 * 
	 * @param hostname destination hostname (since 3.0). May be {@code null}.
	 * @param recordLayer the object to use for sending flights to the peer.
	 * @param timer scheduled executor for flight retransmission (since 2.4).
	 * @param connection the connection related with the session.
	 * @param config the DTLS configuration.
	 * @param probe {@code true} enable probing for this handshake,
	 *            {@code false}, not probing handshake.
	 * @throws NullPointerException if any of the provided parameter is
	 *             {@code null}, except the hostname.
	 */
	@SuppressWarnings("deprecation")
	public ClientHandshaker(String hostname, RecordLayer recordLayer, ScheduledExecutorService timer,
			Connection connection, DtlsConnectorConfig config, boolean probe) {
		super(0, 0, recordLayer, timer, connection, config);

		List<CipherSuite> cipherSuites = config.getSupportedCipherSuites();
		boolean scsv = cipherSuites.contains(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
		DtlsSecureRenegotiation secureRenegotiation = config.get(DtlsConfig.DTLS_SECURE_RENEGOTIATION);

		if (scsv && secureRenegotiation == DtlsSecureRenegotiation.NONE) {
			secureRenegotiation = DtlsSecureRenegotiation.WANTED;
		} else if (!scsv && secureRenegotiation != DtlsSecureRenegotiation.NONE) {
			cipherSuites = new ArrayList<>(cipherSuites);
			cipherSuites.add(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
		}
		this.secureRenegotiation = secureRenegotiation;
		this.supportedCipherSuites = cipherSuites;
		this.supportedGroups = config.getSupportedGroups();
		this.maxFragmentLength = config.get(DtlsConfig.DTLS_MAX_FRAGMENT_LENGTH);
		this.truncateCertificatePath = config.get(DtlsConfig.DTLS_TRUNCATE_CLIENT_CERTIFICATE_PATH);
		this.supportedServerCertificateTypes = config.getTrustCertificateTypes();
		this.supportedClientCertificateTypes = config.getIdentityCertificateTypes();
		this.supportedSignatureAlgorithms = config.getSupportedSignatureAlgorithms();
		this.useDeprecatedCid = config.get(DtlsConfig.DTLS_USE_DEPRECATED_CID);
		this.verifyServerCertificatesSubject = config.get(DtlsConfig.DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT);
		this.probe = probe;
		getSession().setHostName(hostname);
	}

	@Override
	protected boolean isClient() {
		return true;
	}

	@Override
	protected void doProcessMessage(HandshakeMessage message) throws HandshakeException {

		switch (message.getMessageType()) {

		case HELLO_VERIFY_REQUEST:
			receivedHelloVerifyRequest((HelloVerifyRequest) message);
			break;

		case SERVER_HELLO:
			receivedServerHello((ServerHello) message);
			break;

		case CERTIFICATE:
			receivedServerCertificate((CertificateMessage) message);
			break;

		case SERVER_KEY_EXCHANGE:

			switch (getSession().getKeyExchange()) {
			case EC_DIFFIE_HELLMAN:
				receivedEcdhSignedServerKeyExchange((EcdhSignedServerKeyExchange) message);
				break;

			case PSK:
				// server hint is not supported! Therefore no processing is done
				break;

			case ECDHE_PSK:
				serverKeyExchange = (EcdhPskServerKeyExchange) message;
				break;

			default:
				throw new HandshakeException(
						String.format("Unsupported key exchange algorithm %s", getSession().getKeyExchange().name()),
						new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE));
			}
			break;

		case CERTIFICATE_REQUEST:
			receivedCertificateRequest((CertificateRequest) message);
			break;

		case SERVER_HELLO_DONE:
			receivedServerHelloDone();
			break;

		case FINISHED:
			receivedServerFinished((Finished) message);
			break;

		default:
			throw new HandshakeException(String.format("Received unexpected handshake message [%s] from peer %s",
					message.getMessageType(), peerToLog),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE));
		}
	}

	/**
	 * Called when the client received the server's finished message. If the
	 * data can be verified, encrypted application data can be sent.
	 * 
	 * @param message the {@link Finished} message.
	 * @throws HandshakeException if the server's finished is not valid or could
	 *             not be processed
	 */
	private void receivedServerFinished(Finished message) throws HandshakeException {
		verifyFinished(message, handshakeHash);
		contextEstablished();
		handshakeCompleted();
	}

	/**
	 * A {@link HelloVerifyRequest} is sent by the server upon the arrival of
	 * the client's {@link ClientHello}. It is sent by the server to prevent
	 * flooding of a client. The client answers with the same
	 * {@link ClientHello} as before with the additional cookie.
	 * 
	 * @param message the server's {@link HelloVerifyRequest}.
	 */
	protected void receivedHelloVerifyRequest(HelloVerifyRequest message) {
		// HelloVerifyRequest and messages before
		// are not included in the handshake hash
		handshakeMessages.clear();

		if (CipherSuite.containsEccBasedCipherSuite(clientHello.getCipherSuites())) {
			expectEcc();
		}
		clientHello.setCookie(message.getCookie());

		flightNumber = 3;
		DTLSFlight flight = createFlight();
		wrapMessage(flight, clientHello);
		sendFlight(flight);
		// the cookie may have changed
		setExpectedStates(INIT);
	}

	/**
	 * Stores the negotiated security parameters received with the
	 * {@link ServerHello}.
	 * 
	 * @param message the {@link ServerHello} message.
	 * @throws HandshakeException if the ServerHello message cannot be
	 *             processed, e.g. because the server selected an unknown or
	 *             unsupported cipher suite
	 */
	protected void receivedServerHello(ServerHello message) throws HandshakeException {
		// store the negotiated values

		ProtocolVersion usedProtocol = message.getProtocolVersion();
		if (!usedProtocol.equals(ProtocolVersion.VERSION_DTLS_1_2)) {
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.PROTOCOL_VERSION);
			throw new HandshakeException("The client only supports DTLS v1.2, not " + usedProtocol + "!", alert);
		}

		serverRandom = message.getRandom();
		DTLSSession session = getSession();
		session.setSessionIdentifier(message.getSessionId());
		session.setProtocolVersion(usedProtocol);
		CipherSuite cipherSuite = message.getCipherSuite();
		if (!supportedCipherSuites.contains(cipherSuite)) {
			throw new HandshakeException("Server wants to use not supported cipher suite " + cipherSuite,
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER));
		}
		session.setCipherSuite(cipherSuite);
		CompressionMethod compressionMethod = message.getCompressionMethod();
		if (compressionMethod != CompressionMethod.NULL) {
			throw new HandshakeException("Server wants to use not supported compression method " + compressionMethod,
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER));
		}
		session.setCompressionMethod(message.getCompressionMethod());
		verifyServerHelloExtensions(message);
		if (supportsConnectionId()) {
			receivedConnectionIdExtension(message.getConnectionIdExtension());
		}
		if (message.hasExtendedMasterSecretExtension()) {
			session.setExtendedMasterSecret(true);
		} else if (extendedMasterSecretMode == ExtendedMasterSecretMode.REQUIRED) {
			throw new HandshakeException("Extended Master Secret required!",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE));
		}
		session.setSniSupported(message.getServerNameExtension() != null);
		setExpectedStates(cipherSuite.requiresServerCertificateMessage() ? SEVER_CERTIFICATE : NO_SEVER_CERTIFICATE);
	}

	protected void receivedConnectionIdExtension(ConnectionIdExtension extension) throws HandshakeException {
		if (extension != null) {
			ConnectionId connectionId = extension.getConnectionId();
			DTLSContext context = getDtlsContext();
			context.setWriteConnectionId(connectionId);
			context.setReadConnectionId(getReadConnectionId());
			context.setDeprecatedCid(extension.useDeprecatedCid());
		}
	}

	/**
	 * Verify the server hello extensions matching the client's hello
	 * extensions.
	 * 
	 * @param message server hello message with the server's hello extensions.
	 * @throws HandshakeException if the server send extensions, which are not
	 *             initiated by the client or not supported by the client.
	 */
	protected void verifyServerHelloExtensions(ServerHello message) throws HandshakeException {
		boolean hasRenegotiationInfoExtension = false;
		HelloExtensions serverExtensions = message.getExtensions();
		if (serverExtensions != null && !serverExtensions.isEmpty()) {
			HelloExtensions clientExtensions = clientHello.getExtensions();
			if (clientExtensions == null || clientExtensions.isEmpty()) {
				throw new HandshakeException("Server wants extensions, but client not!",
						new AlertMessage(AlertLevel.FATAL, AlertDescription.UNSUPPORTED_EXTENSION));
			} else {
				for (HelloExtension serverExtension : serverExtensions.getExtensions()) {
					if (clientExtensions.getExtension(serverExtension.getType()) == null) {
						if (serverExtension.getType() == HelloExtension.ExtensionType.RENEGOTIATION_INFO) {
							hasRenegotiationInfoExtension = true;
							if (secureRenegotiation != DtlsSecureRenegotiation.NONE) {
								continue;
							}
						}
						throw new HandshakeException(
								"Server wants " + serverExtension.getType() + ", but client didn't propose it!",
								new AlertMessage(AlertLevel.FATAL, AlertDescription.UNSUPPORTED_EXTENSION));
					}
				}
			}
		}

		SupportedPointFormatsExtension pointFormatsExtension = message.getSupportedPointFormatsExtension();
		if (pointFormatsExtension != null && !pointFormatsExtension.contains(ECPointFormat.UNCOMPRESSED)) {
			throw new HandshakeException("Server wants to use only not supported EC point formats!",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER));
		}

		DTLSSession session = getSession();
		RecordSizeLimitExtension recordSizeLimitExt = message.getRecordSizeLimitExtension();
		if (recordSizeLimitExt != null) {
			session.setRecordSizeLimit(recordSizeLimitExt.getRecordSizeLimit());
		}

		MaxFragmentLengthExtension maxFragmentLengthExtension = message.getMaxFragmentLengthExtension();
		if (maxFragmentLengthExtension != null) {
			if (recordSizeLimitExt != null) {
				throw new HandshakeException("Server wants to use record size limit and max. fragment size",
						new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER));
			}
			MaxFragmentLengthExtension.Length maxFragmentLength = maxFragmentLengthExtension.getFragmentLength();
			if (this.maxFragmentLength == maxFragmentLength) {
				// immediately use negotiated max. fragment size
				session.setMaxFragmentLength(maxFragmentLength.length());
			} else {
				throw new HandshakeException("Server wants to use other max. fragment size than proposed",
						new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER));
			}
		}

		CertificateTypeExtension certificateTypeExtension = message.getServerCertificateTypeExtension();
		if (certificateTypeExtension != null) {
			CertificateType serverCertificateType = certificateTypeExtension.getCertificateType();
			if (!isSupportedCertificateType(serverCertificateType, supportedServerCertificateTypes)) {
				throw new HandshakeException(
						"Server wants to use not supported server certificate type " + serverCertificateType,
						new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER));
			}
			session.setReceiveCertificateType(serverCertificateType);
		}
		certificateTypeExtension = message.getClientCertificateTypeExtension();
		if (certificateTypeExtension != null) {
			CertificateType clientCertificateType = certificateTypeExtension.getCertificateType();
			if (!isSupportedCertificateType(clientCertificateType, supportedClientCertificateTypes)) {
				throw new HandshakeException(
						"Server wants to use not supported client certificate type " + clientCertificateType,
						new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER));
			}
			session.setSendCertificateType(clientCertificateType);
		}
		if (hasRenegotiationInfoExtension) {
			session.setSecureRengotiation(true);
		} else if (secureRenegotiation == DtlsSecureRenegotiation.NEEDED) {
			throw new HandshakeException("Server doesn't support secure renegotiation!",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE));
		}
	}

	/**
	 * Unless a anonymous or a PSK based cipher suite is used, the server is
	 * intended to always sends a {@link CertificateMessage}. The client
	 * verifies it and stores the server's public key.
	 * 
	 * @param message the server's {@link CertificateMessage}.
	 * @throws HandshakeException if the certificate could not be verified.
	 */
	private void receivedServerCertificate(CertificateMessage message) throws HandshakeException {
		if (message.isEmpty()) {
			LOGGER.debug("Certificate validation failed: empty server certificate!");
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
			throw new HandshakeException("Empty server certificate!", alert);
		}
		verifyCertificate(message, verifyServerCertificatesSubject);
	}

	/**
	 * Process the ServerKeyExchange message sent by the server, when the server
	 * {@link CertificateMessage} does not contain enough data to allow the
	 * client to exchange a premaster secret. Used, when the key exchange is
	 * ECDH(E). The client tries to verify the server's signature and on success
	 * prepares the ECDH(E) key agreement. ServerKeyExchange message used by
	 * other cipher suites (e.g. PSK using a server's psk identity hint, or
	 * PSK_ECDHE) are not passed to this function.
	 * 
	 * @param message the server's {@link ServerKeyExchange} message.
	 * @throws HandshakeException if the message can't be verified
	 * @since 3.0 (renamed, was receivedServerKeyExchange)
	 */
	private void receivedEcdhSignedServerKeyExchange(EcdhSignedServerKeyExchange message) throws HandshakeException {
		message.verifySignature(otherPeersPublicKey, clientRandom, serverRandom);
		// server identity has been proven
		serverKeyExchange = message;
		setOtherPeersSignatureVerified();
	}

	/**
	 * Process received certificate request message.
	 * 
	 * Determine a matching client certificate to prepare for the client's
	 * certificate message. Calls {@link #processCertificateIdentityAvailable()}
	 * on available identity result.
	 * 
	 * @param message certificate request message
	 * @throws HandshakeException if an exception occurred
	 * @since 3.0
	 */
	private void receivedCertificateRequest(CertificateRequest message) throws HandshakeException {
		// save for later, will be handled by server hello done
		certificateRequest = message;
		requestCertificateIdentity(certificateRequest.getCertificateAuthorities(), getServerNames(),
				certificateRequest.getCertificateKeyAlgorithms(), certificateRequest.getSupportedSignatureAlgorithms(),
				null);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Continues process of server's certificate request when the certificate
	 * identity result is available. if the server hello done is already
	 * received, the left necessary messages (depending on server's previous
	 * flight) are prepared and Starts to create the next flight calling
	 * {@link #processServerHelloDone()}.
	 * 
	 * @since 3.0
	 */
	@Override
	protected void processCertificateIdentityAvailable() throws HandshakeException {
		if (receivedServerHelloDone) {
			processServerHelloDone();
		}
	}

	/**
	 * Process received server hello done message.
	 * 
	 * Starts to create the client's response flight calling
	 * {@link #processServerHelloDone()}, if either no client certificate is
	 * requested or the client certificate is already available.
	 * 
	 * @throws HandshakeException if an exception occurred
	 * @since 3.0
	 */
	private void receivedServerHelloDone() throws HandshakeException {
		receivedServerHelloDone = true;
		if (certificateRequest == null || certificateIdentityAvailable) {
			processServerHelloDone();
		}
	}

	/**
	 * The client starts to create the response flight.
	 * 
	 * Requires the client's certificate to be available.
	 * 
	 * Depending on the cipher suite, the PSK credentials are fetched. That
	 * calls {@link #processMasterSecret()} on available PSK credentials.
	 * 
	 * @throws HandshakeException if the client's handshake records cannot be
	 *             created
	 * @since 3.0 (renamed, was receivedServerHelloDone)
	 */
	private void processServerHelloDone() throws HandshakeException {
		flightNumber += 2;

		flight5 = createFlight();

		createCertificateMessage(flight5);

		/*
		 * Second, send ClientKeyExchange as specified by the key exchange
		 * algorithm.
		 */
		PskPublicInformation clientIdentity;
		DTLSSession session = getSession();
		KeyExchangeAlgorithm keyExchangeAlgorithm = session.getKeyExchange();
		XECDHECryptography ecdhe = null;
		SecretKey ecdheSecret = null;
		byte[] encodedPoint = null;

		if (KeyExchangeAlgorithm.ECDHE_PSK == keyExchangeAlgorithm
				|| KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN == keyExchangeAlgorithm) {
			try {
				SupportedGroup ecGroup = serverKeyExchange.getSupportedGroup();
				if (supportedGroups.contains(ecGroup)) {
					ecdhe = new XECDHECryptography(ecGroup);
					ecdheSecret = ecdhe.generateSecret(serverKeyExchange.getEncodedPoint());
					encodedPoint = ecdhe.getEncodedPoint();
					session.setEcGroup(ecGroup);
				} else {
					AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER);
					throw new HandshakeException("Cannot process handshake message, ec-group not offered! ", alert);
				}
			} catch (GeneralSecurityException ex) {
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER);
				throw new HandshakeException("Cannot process handshake message, caused by " + ex.getMessage(), alert,
						ex);
			}
		}
		ClientKeyExchange clientKeyExchange;
		byte[] seed;
		switch (keyExchangeAlgorithm) {
		case EC_DIFFIE_HELLMAN:
			clientKeyExchange = new ECDHClientKeyExchange(encodedPoint);
			wrapMessage(flight5, clientKeyExchange);
			seed = generateMasterSecretSeed();
			SecretKey masterSecret = PseudoRandomFunction.generateMasterSecret(
					session.getCipherSuite().getThreadLocalPseudoRandomFunctionMac(), ecdheSecret, seed,
					session.useExtendedMasterSecret());
			applyMasterSecret(masterSecret);
			SecretUtil.destroy(masterSecret);
			processMasterSecret();
			break;
		case PSK:
			clientIdentity = getPskClientIdentity();
			LOGGER.trace("Using PSK identity: {}", clientIdentity);
			clientKeyExchange = new PSKClientKeyExchange(clientIdentity);
			wrapMessage(flight5, clientKeyExchange);
			seed = generateMasterSecretSeed();
			requestPskSecretResult(clientIdentity, null, seed);
			break;
		case ECDHE_PSK:
			clientIdentity = getPskClientIdentity();
			LOGGER.trace("Using ECDHE PSK identity: {}", clientIdentity);
			clientKeyExchange = new EcdhPskClientKeyExchange(clientIdentity, encodedPoint);
			wrapMessage(flight5, clientKeyExchange);
			seed = generateMasterSecretSeed();
			requestPskSecretResult(clientIdentity, ecdheSecret, seed);
			break;

		default:
			// already checked in HandshakeMessage.readClientKeyExchange
			break;
		}
		SecretUtil.destroy(ecdhe);
		SecretUtil.destroy(ecdheSecret);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Continues process of server hello done when all credentials are
	 * available. Prepares the left necessary messages (depending on server's
	 * previous flight) and sends the next flight.
	 * 
	 * @since 2.3
	 */
	@Override
	protected void processMasterSecret() throws HandshakeException {
		if (!isExpectedStates(SEVER_CERTIFICATE) || otherPeersCertificateVerified) {
			completeProcessingServerHelloDone();
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Continues process of server's certificate when the verification result is
	 * available. if the master secret is available as well, prepares the left
	 * necessary messages (depending on server's previous flight) and sends the
	 * next flight.
	 * 
	 * @since 2.5
	 */
	@Override
	protected void processCertificateVerified() throws HandshakeException {
		if (hasMasterSecret()) {
			completeProcessingServerHelloDone();
		}
	}

	/**
	 * Complete the client's response flight, when PSK credentials are available
	 * or the certificate is verified.
	 * 
	 * @throws HandshakeException if an exception occurred processing the server
	 *             hello done
	 * @since 3.0 (renamed, was processServerHelloDone)
	 */
	protected void completeProcessingServerHelloDone() throws HandshakeException {

		DTLSSession session = getSession();
		if (session.getCipherSuite().isEccBased()) {
			expectEcc();
		}

		/*
		 * Third, send CertificateVerify message if necessary.
		 */
		SignatureAndHashAlgorithm negotiatedSignatureAndHashAlgorithm = session.getSignatureAndHashAlgorithm();
		if (negotiatedSignatureAndHashAlgorithm != null) {
			// valid negotiated signature and hash algorithm
			// prepare certificate verify message
			CertificateVerify certificateVerify = new CertificateVerify(negotiatedSignatureAndHashAlgorithm, privateKey,
					handshakeMessages);
			wrapMessage(flight5, certificateVerify);
		}

		/*
		 * Fourth, send ChangeCipherSpec
		 */
		ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage();
		wrapMessage(flight5, changeCipherSpecMessage);
		setCurrentWriteState();

		/*
		 * Fifth, send the finished message.
		 */
		// create hash of handshake messages
		// can't do this on the fly, since there is no explicit ordering of
		// messages
		MessageDigest md = getHandshakeMessageDigest();
		MessageDigest mdWithClientFinished = cloneMessageDigest(md);

		Finished finished = createFinishedMessage(md.digest());
		wrapMessage(flight5, finished);

		// compute handshake hash with client's finished message also
		// included, used for server's finished message
		mdWithClientFinished.update(finished.toByteArray());
		handshakeHash = mdWithClientFinished.digest();
		sendFlight(flight5);

		expectChangeCipherSpecMessage();
	}

	private void createCertificateMessage(final DTLSFlight flight) {

		/*
		 * First, if required by server, send Certificate.
		 */
		if (certificateRequest != null) {
			List<SignatureAndHashAlgorithm> supported = supportedSignatureAlgorithms;
			if (supported.isEmpty()) {
				supported = SignatureAndHashAlgorithm.DEFAULT;
			}
			CertificateType certificateType = getSession().sendCertificateType();
			CertificateMessage clientCertificate = null;
			SignatureAndHashAlgorithm negotiatedSignatureAndHashAlgorithm = null;
			if (CertificateType.RAW_PUBLIC_KEY == certificateType) {
				// empty certificate, if no proper public key is available
				PublicKey publicKey = this.publicKey;
				if (publicKey != null) {
					negotiatedSignatureAndHashAlgorithm = certificateRequest.getSignatureAndHashAlgorithm(publicKey,
							supported);
					if (negotiatedSignatureAndHashAlgorithm != null) {
						clientCertificate = new CertificateMessage(publicKey);
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("sending CERTIFICATE message with client RawPublicKey [{}] to server",
									StringUtil.byteArray2HexString(publicKey.getEncoded()));
						}
					}
				}
			} else if (CertificateType.X_509 == certificateType) {
				if (certificateChain != null) {
					negotiatedSignatureAndHashAlgorithm = certificateRequest
							.getSignatureAndHashAlgorithm(certificateChain, supported);
					if (negotiatedSignatureAndHashAlgorithm != null) {
						List<X500Principal> authorities = truncateCertificatePath
								? certificateRequest.getCertificateAuthorities()
								: null;
						clientCertificate = new CertificateMessage(certificateChain, authorities);
						if (clientCertificate.isEmpty()) {
							// don't sent a certificate verify message
							negotiatedSignatureAndHashAlgorithm = null;
						}
					}
				}
			} else {
				throw new IllegalArgumentException("Certificate type " + certificateType + " not supported!");
			}
			if (clientCertificate == null && negotiatedSignatureAndHashAlgorithm == null) {
				// no matching algorithm, send empty certificate message
				clientCertificate = new CertificateMessage();
			}
			wrapMessage(flight, clientCertificate);
			getSession().setSignatureAndHashAlgorithm(negotiatedSignatureAndHashAlgorithm);
		}
	}

	/**
	 * Checks, if the provided certificate type is supported.
	 * 
	 * @param certType certificate type
	 * @param supportedCertificateTypes list of supported certificate type. if
	 *            {@code null}, only {@link CertificateType#X_509} is supported.
	 * @return {@code true}, if supported, {@code false} otherwise.
	 */
	protected static boolean isSupportedCertificateType(CertificateType certType,
			List<CertificateType> supportedCertificateTypes) {
		if (supportedCertificateTypes != null) {
			return supportedCertificateTypes.contains(certType);
		} else {
			return certType == CertificateType.X_509;
		}
	}

	public void startHandshake() throws HandshakeException {

		handshakeStarted();

		ClientHello startMessage = new ClientHello(maxProtocolVersion, supportedCipherSuites,
				supportedSignatureAlgorithms, supportedClientCertificateTypes, supportedServerCertificateTypes,
				supportedGroups);

		if (CipherSuite.containsEccBasedCipherSuite(startMessage.getCipherSuites())) {
			expectEcc();
		}

		// store client random for later calculations
		clientRandom = startMessage.getRandom();

		startMessage.addCompressionMethod(CompressionMethod.NULL);

		if (extendedMasterSecretMode != ExtendedMasterSecretMode.NONE) {
			startMessage.addExtension(ExtendedMasterSecretExtension.INSTANCE);
		}

		addConnectionId(startMessage);

		addRecordSizeLimit(startMessage);

		addMaxFragmentLength(startMessage);

		addServerNameIndication(startMessage);

		// store for later calculations
		flightNumber = 1;
		clientHello = startMessage;
		DTLSFlight flight = createFlight();
		wrapMessage(flight, startMessage);
		sendFlight(flight);
		setExpectedStates(INIT);
	}

	/**
	 * Add record size limit extension, if configured with
	 * {@link DtlsConfig#DTLS_RECORD_SIZE_LIMIT}.
	 * 
	 * @param helloMessage client hello to add {@link RecordSizeLimitExtension}.
	 * @since 2.4
	 */
	protected void addRecordSizeLimit(final ClientHello helloMessage) {
		if (recordSizeLimit != null) {
			RecordSizeLimitExtension ext = new RecordSizeLimitExtension(recordSizeLimit);
			helloMessage.addExtension(ext);
			LOGGER.debug("Indicating record size limit [{}] to server [{}]", recordSizeLimit, peerToLog);
		}
	}

	protected void addMaxFragmentLength(final ClientHello helloMessage) {
		if (maxFragmentLength != null) {
			MaxFragmentLengthExtension ext = new MaxFragmentLengthExtension(maxFragmentLength);
			helloMessage.addExtension(ext);
			LOGGER.debug("Indicating max. fragment length [{}] to server [{}]", maxFragmentLength, peerToLog);
		}
	}

	protected void addConnectionId(final ClientHello helloMessage) {
		if (supportsConnectionId()) {
			final ConnectionId connectionId;
			if (connectionIdGenerator.useConnectionId()) {
				// use the already created unique cid
				connectionId = getConnection().getConnectionId();
			} else {
				// use empty cid
				connectionId = ConnectionId.EMPTY;
			}
			ExtensionType cidType;
			if (useDeprecatedCid  != null) {
				cidType = ExtensionType.getExtensionTypeById(useDeprecatedCid);
			} else {
				cidType = ExtensionType.CONNECTION_ID;
			}
			ConnectionIdExtension extension = ConnectionIdExtension.fromConnectionId(connectionId, cidType);
			helloMessage.addExtension(extension);
		}
	}

	protected void addServerNameIndication(final ClientHello helloMessage) {
		ServerNames serverNames = getServerNames();
		if (serverNames != null) {
			LOGGER.debug("adding SNI extension to CLIENT_HELLO message [{}]", getSession().getHostName());
			helloMessage.addExtension(ServerNameExtension.forServerNames(serverNames));
		}
	}

	/**
	 * Get PSK client identity.
	 * 
	 * @return psk client identity associated with the destination
	 *         {@link #getPeerAddress()}
	 * @throws HandshakeException if no identity is available for the
	 *             destination
	 * @since 2.3
	 */
	protected PskPublicInformation getPskClientIdentity() throws HandshakeException {

		ServerNames serverName = getServerNames();
		if (serverName != null && !getSession().isSniSupported()) {
			LOGGER.warn(
					"client is configured to use SNI but server does not support it, PSK authentication is likely to fail");
		}
		PskPublicInformation pskIdentity = advancedPskStore.getIdentity(getPeerAddress(), serverName);
		// look up identity in scope of virtual host
		if (pskIdentity == null) {
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR);
			if (serverName != null) {
				throw new HandshakeException(String.format("No Identity found for peer [address: %s, virtual host: %s]",
						peerToLog, getSession().getHostName()), alert);
			} else {
				throw new HandshakeException(String.format("No Identity found for peer [address: %s]", peerToLog),
						alert);
			}
		}
		return pskIdentity;
	}

	@Override
	public boolean isProbing() {
		return probe;
	}

	@Override
	public void resetProbing() {
		probe = false;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Connections of probing handshakes are not intended to be removed.
	 */
	@Override
	public boolean isRemovingConnection() {
		return !probe && super.isRemovingConnection();
	}
}
