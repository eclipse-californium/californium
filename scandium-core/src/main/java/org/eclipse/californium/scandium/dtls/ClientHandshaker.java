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
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;

import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.util.NoPublicAPI;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.SupportedPointFormatsExtension.ECPointFormat;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;

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

	// Members ////////////////////////////////////////////////////////

	private ProtocolVersion maxProtocolVersion = ProtocolVersion.VERSION_DTLS_1_2;

	/**
	 * Indicates probing for this handshake.
	 */
	private boolean probe;

	/**
	 * The server's key exchange message
	 * 
	 * @since 2.3
	 */
	protected ECDHServerKeyExchange serverKeyExchange;

	/**
	 * The client's hello handshake message. Store it, to add the cookie in the
	 * second flight.
	 */
	protected ClientHello clientHello = null;

	/**
	 * The client's flight 5.
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
	 * the supported groups (curves) ordered by preference
	 * 
	 * @since 2.3
	 */
	protected final List<SupportedGroup> supportedGroups;

	protected final Integer maxFragmentLengthCode;
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

	/** The server's {@link CertificateRequest}. Optional. */
	protected CertificateRequest certificateRequest = null;

	/** The hash of all received handshake messages sent in the finished message. */
	protected byte[] handshakeHash = null;

	protected ServerNames indicatedServerNames;

	// Constructors ///////////////////////////////////////////////////

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
	public ClientHandshaker(String hostname, RecordLayer recordLayer, ScheduledExecutorService timer,
			Connection connection, DtlsConnectorConfig config, boolean probe) {
		super(0, 0, recordLayer, timer, connection, config);
		this.supportedCipherSuites = config.getSupportedCipherSuites();
		this.supportedGroups = config.getSupportedGroups();
		this.maxFragmentLengthCode = config.getMaxFragmentLengthCode();
		this.truncateCertificatePath = config.useTruncatedCertificatePathForClientsCertificateMessage();
		this.supportedServerCertificateTypes = config.getTrustCertificateTypes();
		this.supportedClientCertificateTypes = config.getIdentityCertificateTypes();
		this.supportedSignatureAlgorithms = config.getSupportedSignatureAlgorithms();
		this.probe = probe;
		getSession().setHostName(hostname);
	}

	// Methods ////////////////////////////////////////////////////////

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
				receivedServerKeyExchange((EcdhEcdsaServerKeyExchange) message);
				break;

			case PSK:
				// server hint is not supported! Therefore no processing is done
				break;

			case ECDHE_PSK:
				serverKeyExchange =(EcdhPskServerKeyExchange) message;
				break;

			default:
				throw new HandshakeException(
						String.format("Unsupported key exchange algorithm %s", getSession().getKeyExchange().name()),
						new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE));
			}
			break;

		case CERTIFICATE_REQUEST:
			// save for later, will be handled by server hello done
			certificateRequest = (CertificateRequest) message;
			break;

		case SERVER_HELLO_DONE:
			receivedServerHelloDone((ServerHelloDone) message);
			break;

		case FINISHED:
			receivedServerFinished((Finished) message);
			break;

		default:
			throw new HandshakeException(
					String.format("Received unexpected handshake message [%s] from peer %s", message.getMessageType(), peerToLog),
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
		message.verifyData(getSession().getCipherSuite().getThreadLocalPseudoRandomFunctionMac(), masterSecret, false,
				handshakeHash);
		contextEstablished();
		handshakeCompleted();
	}

	/**
	 * A {@link HelloVerifyRequest} is sent by the server upon the arrival of
	 * the client's {@link ClientHello}. It is sent by the server to prevent
	 * flooding of a client. The client answers with the same
	 * {@link ClientHello} as before with the additional cookie.
	 * 
	 * @param message
	 *            the server's {@link HelloVerifyRequest}.
	 */
	protected void receivedHelloVerifyRequest(HelloVerifyRequest message) {
		// HelloVerifyRequest and messages before are not included in the handshake hash
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

		usedProtocol = message.getServerVersion();
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
			ConnectionIdExtension extension = message.getConnectionIdExtension();
			if (extension != null) {
				ConnectionId connectionId = extension.getConnectionId();
				context.setWriteConnectionId(connectionId);
				context.setReadConnectionId(getReadConnectionId());
			}
		}
		if (message.hasExtendedMasterSecret()) {
			session.setExtendedMasterSecret(true);
		} else if (extendedMasterSecretMode == ExtendedMasterSecretMode.REQUIRED) {
			throw new HandshakeException("Extended Master Secret required!",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE));
		}
		session.setSendCertificateType(message.getClientCertificateType());
		session.setSniSupported(message.hasServerNameExtension());
		setExpectedStates(cipherSuite.requiresServerCertificateMessage() ? SEVER_CERTIFICATE : NO_SEVER_CERTIFICATE);
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
		HelloExtensions serverExtensions = message.getExtensions();
		if (serverExtensions != null && !serverExtensions.isEmpty()) {
			HelloExtensions clientExtensions = clientHello.getExtensions();
			if (clientExtensions == null || clientExtensions.isEmpty()) {
				throw new HandshakeException("Server wants extensions, but client not!",
						new AlertMessage(AlertLevel.FATAL, AlertDescription.UNSUPPORTED_EXTENSION));
			} else {
				for (HelloExtension serverExtension : serverExtensions.getExtensions()) {
					if (clientExtensions.getExtension(serverExtension.getType()) == null) {
						throw new HandshakeException("Server wants " + serverExtension.getType() + ", but client not!",
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
		RecordSizeLimitExtension recordSizeLimitExt = message.getRecordSizeLimit();
		if (recordSizeLimitExt != null) {
			session.setRecordSizeLimit(recordSizeLimitExt.getRecordSizeLimit());
		}

		MaxFragmentLengthExtension maxFragmentLengthExtension = message.getMaxFragmentLength();
		if (maxFragmentLengthExtension != null) {
			if (recordSizeLimitExt != null) {
				throw new HandshakeException("Server wants to use record size limit and max. fragment size",
						new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER));
			}
			MaxFragmentLengthExtension.Length maxFragmentLength = maxFragmentLengthExtension.getFragmentLength();
			if (maxFragmentLength.code() == maxFragmentLengthCode) {
				// immediately use negotiated max. fragment size
				session.setMaxFragmentLength(maxFragmentLength.length());
			} else {
				throw new HandshakeException("Server wants to use other max. fragment size than proposed",
						new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER));
			}
		}

		CertificateType serverCertificateType = message.getServerCertificateType();
		if (!isSupportedCertificateType(serverCertificateType, supportedServerCertificateTypes)) {
			throw new HandshakeException(
					"Server wants to use not supported server certificate type " + serverCertificateType,
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER));
		}
		session.setReceiveCertificateType(serverCertificateType);
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
		verifyCertificate(message);
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
	 */
	private void receivedServerKeyExchange(EcdhEcdsaServerKeyExchange message) throws HandshakeException {
		message.verifySignature(otherPeersPublicKey, clientRandom, serverRandom);
		// server identity has been proven
		serverKeyExchange = message;
		setOtherPeersSignatureVerified();
	}

	/**
	 * The ServerHelloDone message is sent by the server to indicate the end of
	 * the ServerHello and associated messages. The client starts to fetch all
	 * required credentials. If these credentials are available, the processing
	 * is continued with {@link #doProcessMasterSecretResult(PskSecretResult)}.
	 * 
	 * @throws HandshakeException if the server's hello done can not be
	 *             processed.
	 * @throws GeneralSecurityException if the client's handshake records cannot
	 *             be created
	 */
	private void receivedServerHelloDone(ServerHelloDone message) throws HandshakeException {
		flightNumber += 2;

		flight5 = createFlight();

		createCertificateMessage(flight5);

		/*
		 * Second, send ClientKeyExchange as specified by the key exchange
		 * algorithm.
		 */
		PskPublicInformation clientIdentity;
		PskSecretResult masterSecretResult;
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
			processMasterSecret(masterSecret);
			break;
		case PSK:
			clientIdentity = getPskClientIdentity();
			LOGGER.trace("Using PSK identity: {}", clientIdentity);
			clientKeyExchange = new PSKClientKeyExchange(clientIdentity);
			wrapMessage(flight5, clientKeyExchange);
			seed = generateMasterSecretSeed();
			masterSecretResult = requestPskSecretResult(clientIdentity, null, seed);
			if (masterSecretResult != null) {
				processPskSecretResult(masterSecretResult);
			}
			break;
		case ECDHE_PSK:
			clientIdentity = getPskClientIdentity();
			LOGGER.trace("Using ECDHE PSK identity: {}", clientIdentity);
			clientKeyExchange = new EcdhPskClientKeyExchange(clientIdentity, encodedPoint);
			wrapMessage(flight5, clientKeyExchange);
			seed = generateMasterSecretSeed();
			masterSecretResult = requestPskSecretResult(clientIdentity, ecdheSecret, seed);
			if (masterSecretResult != null) {
				processPskSecretResult(masterSecretResult);
			}
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
	protected void processMasterSecret(SecretKey masterSecret) throws HandshakeException {

		applyMasterSecret(masterSecret);
		SecretUtil.destroy(masterSecret);
		if (!isExpectedStates(SEVER_CERTIFICATE) || otherPeersCertificateVerified) {
			processServerHelloDone();
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
		if (masterSecret != null) {
			processServerHelloDone();
		}
	}

	/**
	 * Process received server hello done, when PSK credentials are available or
	 * the certificates are verified.
	 * 
	 * @throws HandshakeException if an exception occurred processing the server
	 *             hello done
	 * @since 2.5
	 */
	protected void processServerHelloDone() throws HandshakeException {
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
		MessageDigest mdWithClientFinished;
		try {
			mdWithClientFinished = (MessageDigest) md.clone();
		} catch (CloneNotSupportedException e) {
			throw new HandshakeException("Cannot create FINISHED message",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR));
		}

		Finished finished = new Finished(getSession().getCipherSuite().getThreadLocalPseudoRandomFunctionMac(),
				this.masterSecret, true, md.digest());
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
					negotiatedSignatureAndHashAlgorithm = certificateRequest.getSignatureAndHashAlgorithm(publicKey, supported);
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
				throw new IllegalArgumentException(
						"Certificate type " + certificateType + " not supported!");
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

		ClientHello startMessage = new ClientHello(maxProtocolVersion, supportedCipherSuites, supportedSignatureAlgorithms,
				supportedClientCertificateTypes, supportedServerCertificateTypes, supportedGroups);

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
	 * Add record size limit extension, if configured in
	 * {@link DtlsConnectorConfig#getRecordSizeLimit()}.
	 * 
	 * @param helloMessage client hello to add {@link RecordSizeLimitExtension}.
	 * @since 2.4
	 */
	protected void addRecordSizeLimit(final ClientHello helloMessage) {
		if (recordSizeLimit != null) {
			RecordSizeLimitExtension  ext = new RecordSizeLimitExtension(recordSizeLimit); 
			helloMessage.addExtension(ext);
			LOGGER.debug(
					"Indicating record size limit [{}] to server [{}]",
					recordSizeLimit, peerToLog);
		}
	}

	protected void addMaxFragmentLength(final ClientHello helloMessage) {
		if (maxFragmentLengthCode != null) {
			MaxFragmentLengthExtension ext = new MaxFragmentLengthExtension(maxFragmentLengthCode); 
			helloMessage.addExtension(ext);
			LOGGER.debug(
					"Indicating max. fragment length [{}] to server [{}]",
					maxFragmentLengthCode, peerToLog);
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
			ConnectionIdExtension extension = ConnectionIdExtension.fromConnectionId(connectionId);
			helloMessage.addExtension(extension);
		}
	}

	protected void addServerNameIndication(final ClientHello helloMessage) {

		if (sniEnabled && getSession().getServerNames() != null) {
			LOGGER.debug("adding SNI extension to CLIENT_HELLO message [{}]", getSession().getHostName());
			helloMessage.addExtension(ServerNameExtension.forServerNames(getSession().getServerNames()));
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

		ServerNames serverName = sniEnabled ? getSession().getServerNames() : null;
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
				throw new HandshakeException(
						String.format("No Identity found for peer [address: %s]", peerToLog), alert);
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
