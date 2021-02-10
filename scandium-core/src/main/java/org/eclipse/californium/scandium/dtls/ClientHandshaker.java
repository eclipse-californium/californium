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
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;

import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.util.Bytes;
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
 * {@link Handshaker} class.
 */
@NoPublicAPI
public class ClientHandshaker extends Handshaker {

	protected static HandshakeState[] SEVER_CERTIFICATE = { new HandshakeState(HandshakeType.HELLO_VERIFY_REQUEST, true),
			new HandshakeState(HandshakeType.SERVER_HELLO), new HandshakeState(HandshakeType.CERTIFICATE),
			new HandshakeState(HandshakeType.SERVER_KEY_EXCHANGE),
			new HandshakeState(HandshakeType.CERTIFICATE_REQUEST, true),
			new HandshakeState(HandshakeType.SERVER_HELLO_DONE), new HandshakeState(ContentType.CHANGE_CIPHER_SPEC),
			new HandshakeState(HandshakeType.FINISHED) };
	private static HandshakeState[] NO_SEVER_CERTIFICATE = {
			new HandshakeState(HandshakeType.HELLO_VERIFY_REQUEST, true),
			new HandshakeState(HandshakeType.SERVER_HELLO), new HandshakeState(HandshakeType.SERVER_KEY_EXCHANGE, true),
			new HandshakeState(HandshakeType.SERVER_HELLO_DONE), new HandshakeState(ContentType.CHANGE_CIPHER_SPEC),
			new HandshakeState(HandshakeType.FINISHED) };

	// Members ////////////////////////////////////////////////////////

	private ProtocolVersion maxProtocolVersion = ProtocolVersion.VERSION_DTLS_1_2;

	/**
	 * Indicates probing for this handshake.
	 */
	private boolean probe;

	/**
	 * The server's public key from its certificate
	 */
	private PublicKey serverPublicKey;

	/**
	 * The server's key exchange message
	 * 
	 * @since 2.3
	 */
	protected ECDHServerKeyExchange serverKeyExchange;

	/**
	 * The create client key exchange message.
	 * 
	 * @since 2.3
	 */
	protected ClientKeyExchange clientKeyExchange;

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

	/**
	 * Indicates, that a none-empty client certificate is sent.
	 * 
	 * If no matching client certificate is available for the request, an empty
	 * certificate is sent. That case doesn't use a certificate verify message.
	 * 
	 * @since 2.6
	 */
	protected boolean sentClientCertificate;

	/** The hash of all received handshake messages sent in the finished message. */
	protected byte[] handshakeHash = null;

	protected ServerNames indicatedServerNames;
	protected SignatureAndHashAlgorithm negotiatedSignatureAndHashAlgorithm;

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
	public ClientHandshaker(String hostname, RecordLayer recordLayer, ScheduledExecutorService timer, Connection connection,
			DtlsConnectorConfig config, boolean probe) {
		this(probe, new DTLSSession(hostname), recordLayer, timer, connection, config);
	}

	/**
	 * Creates a new handshaker for negotiating a DTLS session with a server.
	 * 
	 * @param probe {@code true} enable probing for this handshake,
	 *            {@code false}, not probing handshake.
	 * @param session the session to negotiate with the server.
	 * @param recordLayer the object to use for sending flights to the peer.
	 * @param timer scheduled executor for flight retransmission.
	 * @param connection the connection related with the session.
	 * @param config the DTLS configuration.
	 * @throws NullPointerException if any of the provided parameter is
	 *             {@code null}
	 * @since 3.0
	 */
	protected ClientHandshaker(boolean probe, DTLSSession session, RecordLayer recordLayer, ScheduledExecutorService timer, Connection connection,
			DtlsConnectorConfig config) {
		super(0, 0, session, recordLayer, timer, connection, config);
		this.supportedCipherSuites = config.getSupportedCipherSuites();
		this.supportedGroups = config.getSupportedGroups();
		this.maxFragmentLengthCode = config.getMaxFragmentLengthCode();
		this.truncateCertificatePath = config.useTruncatedCertificatePathForClientsCertificateMessage();
		this.supportedServerCertificateTypes = config.getTrustCertificateTypes();
		this.supportedClientCertificateTypes = config.getIdentityCertificateTypes();
		this.supportedSignatureAlgorithms = config.getSupportedSignatureAlgorithms();
		this.probe = probe;
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
		// HelloVerifyRequest and messages before are not included in the handshake hashs
		handshakeMessages.clear();

		clientHello.setCookie(message.getCookie());

		flightNumber = 3;
		DTLSFlight flight = createFlight();
		wrapMessage(flight, clientHello);
		sendFlight(flight);
		// the cookie may have changed
		--statesIndex;
	}

	/**
	 * Stores the negotiated security parameters.
	 * 
	 * @param message
	 *            the {@link ServerHello} message.
	 * @throws HandshakeException if the ServerHello message cannot be processed,
	 * 	e.g. because the server selected an unknown or unsupported cipher suite
	 */
	protected void receivedServerHello(ServerHello message) throws HandshakeException {
		// store the negotiated values

		usedProtocol = message.getServerVersion();
		if (usedProtocol.compareTo(ProtocolVersion.VERSION_DTLS_1_2) != 0) {
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.PROTOCOL_VERSION);
			throw new HandshakeException("The client only supports DTLS v1.2, not " + usedProtocol + "!", alert);
		}

		serverRandom = message.getRandom();
		DTLSSession session = getSession();
		session.setSessionIdentifier(message.getSessionId());
		CipherSuite cipherSuite = message.getCipherSuite();
		if (!supportedCipherSuites.contains(cipherSuite)) {
			throw new HandshakeException(
					"Server wants to use not supported cipher suite " + cipherSuite,
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.ILLEGAL_PARAMETER));
		}
		session.setCipherSuite(cipherSuite);
		CompressionMethod compressionMethod = message.getCompressionMethod();
		if (compressionMethod != CompressionMethod.NULL) {
			throw new HandshakeException(
					"Server wants to use not supported compression method " + compressionMethod,
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.ILLEGAL_PARAMETER));
		}
		session.setCompressionMethod(message.getCompressionMethod());
		verifyServerHelloExtensions(message);
		if (connectionIdGenerator != null) {
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
		if (!cipherSuite.requiresServerCertificateMessage()) {
			states = NO_SEVER_CERTIFICATE;
		}
	}

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
			throw new HandshakeException(
					"Server wants to use only not supported EC point formats!",
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.ILLEGAL_PARAMETER));
		}

		DTLSSession session = getSession();
		RecordSizeLimitExtension recordSizeLimitExt = message.getRecordSizeLimit();
		if (recordSizeLimitExt != null) {
			session.setRecordSizeLimit(recordSizeLimitExt.getRecordSizeLimit());
		}

		MaxFragmentLengthExtension maxFragmentLengthExtension = message.getMaxFragmentLength();
		if (maxFragmentLengthExtension != null) {
			if (recordSizeLimitExt != null) {
				throw new HandshakeException(
						"Server wants to use record size limit and max. fragment size",
						new AlertMessage(
								AlertLevel.FATAL,
								AlertDescription.ILLEGAL_PARAMETER));
			}
			MaxFragmentLengthExtension.Length maxFragmentLength = maxFragmentLengthExtension.getFragmentLength(); 
			if (maxFragmentLength.code() == maxFragmentLengthCode) {
				// immediately use negotiated max. fragment size
				session.setMaxFragmentLength(maxFragmentLength.length());
			} else {
				throw new HandshakeException(
						"Server wants to use other max. fragment size than proposed",
						new AlertMessage(
								AlertLevel.FATAL,
								AlertDescription.ILLEGAL_PARAMETER));
			}
		}

		CertificateType serverCertificateType = message.getServerCertificateType();
		if (!isSupportedCertificateType(serverCertificateType, supportedServerCertificateTypes)) {
			throw new HandshakeException(
					"Server wants to use not supported server certificate type " + serverCertificateType,
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.ILLEGAL_PARAMETER));
		}
		session.setReceiveCertificateType(serverCertificateType);
	}

	/**
	 * Unless a anonymous cipher suite is used, the server always sends a
	 * {@link CertificateMessage}. The client verifies it and stores the
	 * server's public key.
	 * 
	 * @param message
	 *            the server's {@link CertificateMessage}.
	 * @throws HandshakeException
	 *             if the certificate could not be verified.
	 */
	private void receivedServerCertificate(CertificateMessage message) throws HandshakeException {
		if (message.isEmpty()) {
			LOGGER.debug("Certificate validation failed: empty server certificate!");
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
			throw new HandshakeException("Empty server certificate!", alert);
		}
		verifyCertificate(message);
		serverPublicKey = message.getPublicKey();
	}

	/**
	 * The ServerKeyExchange message is sent by the server only when the server
	 * {@link CertificateMessage} (if sent) does not contain enough data to
	 * allow the client to exchange a premaster secret. Used when the key
	 * exchange is ECDH. The client tries to verify the server's signature and
	 * on success prepares the ECDH key agreement.
	 * 
	 * @param message
	 *            the server's {@link ServerKeyExchange} message.
	 * @throws HandshakeException if the message can't be verified
	 */
	private void receivedServerKeyExchange(EcdhEcdsaServerKeyExchange message) throws HandshakeException {
		message.verifySignature(serverPublicKey, clientRandom, serverRandom);
		// server identity has been proven
		if (peerCertPath != null) {
			getSession().setPeerIdentity(new X509CertPath(peerCertPath));
		} else {
			getSession().setPeerIdentity(new RawPublicKeyIdentity(serverPublicKey));
		}
		serverKeyExchange = message;
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
		byte[] seed;
		switch (keyExchangeAlgorithm) {
		case EC_DIFFIE_HELLMAN:
			clientKeyExchange = new ECDHClientKeyExchange(encodedPoint);
			wrapMessage(flight5, clientKeyExchange);
			seed = generateMasterSecretSeed();
			SecretKey masterSecret = PseudoRandomFunction.generateMasterSecret(
					session.getCipherSuite().getThreadLocalPseudoRandomFunctionMac(), ecdheSecret,
					seed, session.useExtendedMasterSecret());
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
	 * available. Prepares all necessary messages (depending on server's
	 * previous flight) and sends the next flight.
	 * 
	 * @since 2.3
	 */
	@Override
	protected void processMasterSecret(SecretKey masterSecret) throws HandshakeException {

		applyMasterSecret(masterSecret);
		SecretUtil.destroy(masterSecret);
		if (states != SEVER_CERTIFICATE || certificateVerfied) {
			processServerHelloDone();
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Continues process of server's certificate when the verification result is
	 * available. Prepares all necessary messages (depending on server's
	 * previous flight) and sends the next flight.
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
	private void processServerHelloDone() throws HandshakeException {
		DTLSSession session = getSession();
		/*
		 * Third, send CertificateVerify message if necessary.
		 */
		if (sentClientCertificate && certificateRequest != null && negotiatedSignatureAndHashAlgorithm != null) {
			CertificateType clientCertificateType = session.sendCertificateType();
			if (!isSupportedCertificateType(clientCertificateType, supportedClientCertificateTypes)) {
				throw new HandshakeException(
						"Server wants to use not supported client certificate type " + clientCertificateType,
						new AlertMessage(
								AlertLevel.FATAL,
								AlertDescription.UNSUPPORTED_CERTIFICATE));
			}

			// prepare handshake messages

			CertificateVerify certificateVerify = new CertificateVerify(negotiatedSignatureAndHashAlgorithm, privateKey, handshakeMessages);
			session.setSignatureAndHashAlgorithm(negotiatedSignatureAndHashAlgorithm);
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
			throw new HandshakeException(
					"Cannot create FINISHED message",
					new AlertMessage(
							AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR));
		}

		Finished finished = new Finished(getSession().getCipherSuite().getThreadLocalPseudoRandomFunctionMac(), this.masterSecret, true, md.digest());
		wrapMessage(flight5, finished);

		// compute handshake hash with client's finished message also
		// included, used for server's finished message
		mdWithClientFinished.update(finished.toByteArray());
		handshakeHash = mdWithClientFinished.digest();
		sendFlight(flight5);

		expectChangeCipherSpecMessage();
	}

	protected void createCertificateMessage(final DTLSFlight flight) {

		/*
		 * First, if required by server, send Certificate.
		 */
		if (certificateRequest != null) {
			List<SignatureAndHashAlgorithm> supported = supportedSignatureAlgorithms;
			if (supported.isEmpty()) {
				supported = SignatureAndHashAlgorithm.DEFAULT;
			}
			certificateRequest.selectSignatureAlgorithms(supported);
			CertificateMessage clientCertificate;
			if (CertificateType.RAW_PUBLIC_KEY == getSession().sendCertificateType()) {
				// empty certificate, if no proper public key is available
				PublicKey publicKey = this.publicKey;
				if (publicKey != null) {
					negotiatedSignatureAndHashAlgorithm = certificateRequest.getSignatureAndHashAlgorithm(publicKey);
					if (negotiatedSignatureAndHashAlgorithm == null) {
						publicKey = null;
					}
				}
				if (LOGGER.isDebugEnabled()) {
					byte[] raw = publicKey == null ? Bytes.EMPTY : publicKey.getEncoded();
					LOGGER.debug("sending CERTIFICATE message with client RawPublicKey [{}] to server", StringUtil.byteArray2HexString(raw));
				}
				clientCertificate = new CertificateMessage(publicKey);
			} else if (CertificateType.X_509 == getSession().sendCertificateType()) {
				// empty certificate, if no proper certificate chain is available
				List<X509Certificate> clientChain = Collections.emptyList();
				if (certificateChain != null) {
					negotiatedSignatureAndHashAlgorithm = certificateRequest.getSignatureAndHashAlgorithm(certificateChain);
					if (negotiatedSignatureAndHashAlgorithm != null) {
						clientChain = certificateChain;
					}
				}
				List<X500Principal> authorities = truncateCertificatePath ? certificateRequest.getCertificateAuthorities() : null;
				clientCertificate = new CertificateMessage(clientChain, authorities);
			} else {
				throw new IllegalArgumentException("Certificate type " + getSession().sendCertificateType() + " not supported!");
			}
			sentClientCertificate = clientCertificate.getMessageLength() > 3;
			wrapMessage(flight, clientCertificate);
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
		states = SEVER_CERTIFICATE;
		statesIndex = 0;
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
		if (connectionIdGenerator != null) {
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
