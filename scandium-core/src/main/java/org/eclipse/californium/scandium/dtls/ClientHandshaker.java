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
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.List;

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
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.SupportedPointFormatsExtension.ECPointFormat;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography;
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

	private ProtocolVersion maxProtocolVersion = new ProtocolVersion();

	/** The server's public key from its certificate */
	private PublicKey serverPublicKey;

	/** The server's ephemeral public key, used for key agreement */
	protected ECPublicKey ephemeralServerPublicKey;

	/** The client's hello handshake message. Store it, to add the cookie in the second flight. */
	protected ClientHello clientHello = null;

	/** the preferred cipher suites ordered by preference */
	private final List<CipherSuite> preferredCipherSuites;

	protected final Integer maxFragmentLengthCode;
	protected final boolean truncateCertificatePath;

	/**
	 * The certificate types this peer supports for client authentication.
	 */
	protected final List<CertificateType> supportedClientCertificateTypes;

	/**
	 * The certificate types this peer supports for server authentication.
	 */
	protected final List<CertificateType> supportedServerCertificateTypes;

	/** The server's {@link CertificateRequest}. Optional. */
	protected CertificateRequest certificateRequest = null;

	/** The hash of all received handshake messages sent in the finished message. */
	protected byte[] handshakeHash = null;

	protected ServerNames indicatedServerNames;
	protected SignatureAndHashAlgorithm negotiatedSignatureAndHashAlgorithm;

	// Constructors ///////////////////////////////////////////////////

	/**
	 * Creates a new handshaker for negotiating a DTLS session with a server.
	 * 
	 * @param session
	 *            the session to negotiate with the server.
	 * @param recordLayer
	 *            the object to use for sending flights to the peer.
	 * @param connection
	 *            the connection related with the session.
	 * @param config
	 *            the DTLS configuration.
	 * @param maxTransmissionUnit
	 *            the MTU value reported by the network interface the record layer is bound to.
	 * @throws IllegalStateException
	 *            if the message digest required for computing the FINISHED message hash cannot be instantiated.
	 * @throws NullPointerException
	 *            if session, recordLayer or config is <code>null</code>
	 */
	public ClientHandshaker(DTLSSession session, RecordLayer recordLayer, Connection connection,
			DtlsConnectorConfig config, int maxTransmissionUnit) {
		super(true, 0, session, recordLayer, connection, config, maxTransmissionUnit);
		this.preferredCipherSuites = config.getSupportedCipherSuites();
		this.maxFragmentLengthCode = config.getMaxFragmentLengthCode();
		this.truncateCertificatePath = config.useTruncatedCertificatePathForClientsCertificateMessage();
		this.supportedServerCertificateTypes = config.getTrustCertificateTypes();
		this.supportedClientCertificateTypes = config.getIdentityCertificateTypes();
	}

	// Methods ////////////////////////////////////////////////////////

	final SignatureAndHashAlgorithm getNegotiatedSignatureAndHashAlgorithm() {
		return negotiatedSignatureAndHashAlgorithm;
	}

	@Override
	protected void doProcessMessage(HandshakeMessage message) throws HandshakeException, GeneralSecurityException {

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

			switch (getKeyExchangeAlgorithm()) {
			case EC_DIFFIE_HELLMAN:
				receivedServerKeyExchange((ECDHServerKeyExchange) message);
				break;

			case PSK:
				// server hint is not supported! Therefore no processing is done
				break;
			
			case ECDHE_PSK:
				receivedServerKeyExchange((EcdhPskServerKeyExchange) message);
				break;
				
			case NULL:
				LOGGER.info("Received unexpected ServerKeyExchange message in NULL key exchange mode.");
				break;

			default:
				throw new HandshakeException(
						String.format("Unsupported key exchange algorithm %s", getKeyExchangeAlgorithm().name()),
						new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, message.getPeer()));
			}
			break;

		case CERTIFICATE_REQUEST:
			// save for later, will be handled by server hello done
			certificateRequest = (CertificateRequest) message;
			break;

		case SERVER_HELLO_DONE:
			receivedServerHelloDone((ServerHelloDone) message);
			expectChangeCipherSpecMessage();
			break;

		case FINISHED:
			receivedServerFinished((Finished) message);
			break;

		default:
			throw new HandshakeException(
					String.format("Received unexpected handshake message [%s] from peer %s", message.getMessageType(), message.getPeer()),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE, message.getPeer()));
		}
	}

	/**
	 * Called when the client received the server's finished message. If the
	 * data can be verified, encrypted application data can be sent.
	 * 
	 * @param message
	 *            the {@link Finished} message.
	 * @throws HandshakeException
	 * @throws GeneralSecurityException if the APPLICATION record cannot be created 
	 */
	private void receivedServerFinished(Finished message) throws HandshakeException, GeneralSecurityException {
		message.verifyData(session.getCipherSuite().getThreadLocalPseudoRandomFunctionMac(), masterSecret, false,
				handshakeHash);
		sessionEstablished();
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
	 * @throws HandshakeException if the CLIENT_HELLO record cannot be created
	 */
	protected void receivedHelloVerifyRequest(HelloVerifyRequest message) throws HandshakeException {
		// HelloVerifyRequest and messages before are not included in the handshake hashs
		handshakeMessages.clear();

		clientHello.setCookie(message.getCookie());

		flightNumber = 3;
		DTLSFlight flight = new DTLSFlight(getSession(), flightNumber);
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
		serverRandom = message.getRandom();
		session.setSessionIdentifier(message.getSessionId());
		CipherSuite cipherSuite = message.getCipherSuite();
		if (!preferredCipherSuites.contains(cipherSuite)) {
			throw new HandshakeException(
					"Server wants to use not supported cipher suite " + cipherSuite,
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.ILLEGAL_PARAMETER,
							message.getPeer()));
		}
		session.setCipherSuite(cipherSuite);
		CompressionMethod compressionMethod = message.getCompressionMethod();
		if (compressionMethod != CompressionMethod.NULL) {
			throw new HandshakeException(
					"Server wants to use not supported compression method " + compressionMethod,
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.ILLEGAL_PARAMETER,
							message.getPeer()));
		}
		session.setCompressionMethod(message.getCompressionMethod());
		verifyServerHelloExtensions(message);
		if (connectionIdGenerator != null) {
			ConnectionIdExtension extension = message.getConnectionIdExtension();
			if (extension != null) {
				ConnectionId connectionId = extension.getConnectionId();
				session.setWriteConnectionId(connectionId);
			}
		}
		session.setSendCertificateType(message.getClientCertificateType());
		session.setSniSupported(message.hasServerNameExtension());
		session.setParameterAvailable();
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
						new AlertMessage(AlertLevel.FATAL, AlertDescription.UNSUPPORTED_EXTENSION, message.getPeer()));
			} else {
				for (HelloExtension serverExtension : serverExtensions.getExtensions()) {
					if (clientExtensions.getExtension(serverExtension.getType()) == null) {
						throw new HandshakeException("Server wants " + serverExtension.getType() + ", but client not!",
								new AlertMessage(AlertLevel.FATAL, AlertDescription.UNSUPPORTED_EXTENSION,
										message.getPeer()));
					}
				}
			}
		}

		SupportedPointFormatsExtension pointFormatsExtension = message.getSupportedPointFormatsExtension();
		if (pointFormatsExtension !=null && !pointFormatsExtension.contains(ECPointFormat.UNCOMPRESSED)) {
			throw new HandshakeException(
					"Server wants to use only not supported EC point formats!",
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.ILLEGAL_PARAMETER,
							message.getPeer()));
		}
		MaxFragmentLengthExtension maxFragmentLengthExtension = message.getMaxFragmentLength();
		if (maxFragmentLengthExtension != null) {
			MaxFragmentLengthExtension.Length maxFragmentLength = maxFragmentLengthExtension.getFragmentLength(); 
			if (maxFragmentLength.code() == maxFragmentLengthCode) {
				// immediately use negotiated max. fragment size
				session.setMaxFragmentLength(maxFragmentLength.length());
			} else {
				throw new HandshakeException(
						"Server wants to use other max. fragment size than proposed",
						new AlertMessage(
								AlertLevel.FATAL,
								AlertDescription.ILLEGAL_PARAMETER,
								message.getPeer()));
			}
		}
		CertificateType serverCertificateType = message.getServerCertificateType();
		if (!isSupportedCertificateType(serverCertificateType, supportedServerCertificateTypes)) {
			throw new HandshakeException(
					"Server wants to use not supported server certificate type " + serverCertificateType,
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.ILLEGAL_PARAMETER,
							message.getPeer()));
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
	private void receivedServerKeyExchange(ECDHServerKeyExchange message) throws HandshakeException {
		message.verifySignature(serverPublicKey, clientRandom, serverRandom);
		// server identity has been proven
		if (peerCertPath != null) {
			session.setPeerIdentity(new X509CertPath(peerCertPath));
		} else {
			session.setPeerIdentity(new RawPublicKeyIdentity(serverPublicKey));
		}
		ephemeralServerPublicKey = message.getPublicKey();
		try {
			ecdhe = new ECDHECryptography(ephemeralServerPublicKey.getParams());
		} catch (GeneralSecurityException e) {
			throw new HandshakeException(
				String.format(
					"Cannot create ephemeral keys from domain params provided by server: %s",
					e.getMessage()),
				new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, getPeerAddress()));
		}
	}

	/**
	 * This method is called after receiving {@link ServerKeyExchange} message in ECDHE_PSK mode 
	 * to extract the ServerDHEParams that includes the ephemeral public key.
	 * 
	 * @param message
	 * @throws HandshakeException
	 */
	private void receivedServerKeyExchange(EcdhPskServerKeyExchange message) throws HandshakeException {
		ephemeralServerPublicKey = message.getPublicKey();
		try {
			ecdhe = new ECDHECryptography(ephemeralServerPublicKey.getParams());
		} catch (GeneralSecurityException e) {
			throw new HandshakeException(
				String.format(
					"Cannot create ephemeral keys from domain params provided by server: %s",
					e.getMessage()),
				new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, getPeerAddress()));
		}
	}

	/**
	 * The ServerHelloDone message is sent by the server to indicate the end of
	 * the ServerHello and associated messages. The client prepares all
	 * necessary messages (depending on server's previous flight) and returns
	 * the next flight.
	 * 
	 * @throws HandshakeException
	 * @throws GeneralSecurityException if the client's handshake records cannot be created
	 */
	protected void receivedServerHelloDone(ServerHelloDone message) throws HandshakeException, GeneralSecurityException {
		flightNumber += 2;
		DTLSFlight flight = new DTLSFlight(getSession(), flightNumber);

		createCertificateMessage(flight);

		/*
		 * Second, send ClientKeyExchange as specified by the key exchange
		 * algorithm.
		 */
		ClientKeyExchange clientKeyExchange;
		SecretKey premasterSecret;
		PskUtil pskUtil = null;
		switch (getKeyExchangeAlgorithm()) {
		case EC_DIFFIE_HELLMAN:
			clientKeyExchange = new ECDHClientKeyExchange(ecdhe.getPublicKey(), session.getPeer());
			premasterSecret = ecdhe.generateSecret(ephemeralServerPublicKey);
			break;
		case PSK:
			pskUtil = new PskUtil(sniEnabled, session, pskStore);
			LOGGER.debug("Using PSK identity: {}", pskUtil.getPskPrincipal());
			clientKeyExchange = new PSKClientKeyExchange(pskUtil.getPskPublicIdentity(), session.getPeer());
			premasterSecret = pskUtil.generatePremasterSecretFromPSK(null);
			break;
		case ECDHE_PSK:
			pskUtil = new PskUtil(sniEnabled, session, pskStore);
			LOGGER.debug("Using PSK identity: {}", pskUtil.getPskPrincipal());
			clientKeyExchange = new EcdhPskClientKeyExchange(pskUtil.getPskPublicIdentity(), ecdhe.getPublicKey(), session.getPeer());
			SecretKey eck = ecdhe.generateSecret(ephemeralServerPublicKey);
			premasterSecret = pskUtil.generatePremasterSecretFromPSK(eck);
			SecretUtil.destroy(eck);
			break;

		default:
			throw new HandshakeException(
					"Unknown key exchange algorithm: " + getKeyExchangeAlgorithm(),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, session.getPeer()));
		}
		SecretUtil.destroy(pskUtil);
		if (premasterSecret != null) {
			generateKeys(premasterSecret);
			SecretUtil.destroy(premasterSecret);
		}
		wrapMessage(flight, clientKeyExchange);

		/*
		 * Third, send CertificateVerify message if necessary.
		 */
		if (certificateRequest != null && negotiatedSignatureAndHashAlgorithm != null) {
			CertificateType clientCertificateType = session.sendCertificateType();
			if (!isSupportedCertificateType(clientCertificateType, supportedClientCertificateTypes)) {
				throw new HandshakeException(
						"Server wants to use not supported client certificate type " + clientCertificateType,
						new AlertMessage(
								AlertLevel.FATAL,
								AlertDescription.ILLEGAL_PARAMETER,
								message.getPeer()));
			}

			// prepare handshake messages

			CertificateVerify certificateVerify = new CertificateVerify(negotiatedSignatureAndHashAlgorithm, privateKey, handshakeMessages, session.getPeer());

			wrapMessage(flight, certificateVerify);
		}

		/*
		 * Fourth, send ChangeCipherSpec
		 */
		ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage(session.getPeer());
		wrapMessage(flight, changeCipherSpecMessage);
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
							AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, message.getPeer()));
		}

		Finished finished = new Finished(session.getCipherSuite().getThreadLocalPseudoRandomFunctionMac(), masterSecret, isClient, md.digest(), session.getPeer());
		wrapMessage(flight, finished);

		// compute handshake hash with client's finished message also
		// included, used for server's finished message
		mdWithClientFinished.update(finished.toByteArray());
		handshakeHash = mdWithClientFinished.digest();
		sendFlight(flight);
	}

	protected void createCertificateMessage(final DTLSFlight flight) throws HandshakeException {

		/*
		 * First, if required by server, send Certificate.
		 */
		if (certificateRequest != null) {
			CertificateMessage clientCertificate;
			if (CertificateType.RAW_PUBLIC_KEY == session.sendCertificateType()) {
				byte[] rawPublicKeyBytes = Bytes.EMPTY;
				PublicKey key = determineClientRawPublicKey(certificateRequest);
				if (key != null) {
					rawPublicKeyBytes = key.getEncoded();
				}
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("sending CERTIFICATE message with client RawPublicKey [{}] to server", StringUtil.byteArray2HexString(rawPublicKeyBytes));
				}
				clientCertificate = new CertificateMessage(rawPublicKeyBytes, session.getPeer());
			} else if (CertificateType.X_509 == session.sendCertificateType()) {
				List<X509Certificate> clientChain = determineClientCertificateChain(certificateRequest);
				List<X500Principal> authorities = truncateCertificatePath ? certificateRequest.getCertificateAuthorities() : null;
				clientCertificate = new CertificateMessage(clientChain, authorities, session.getPeer());
			} else {
				throw new IllegalArgumentException("Certificate type " + session.sendCertificateType() + " not supported!");
			}
			wrapMessage(flight, clientCertificate);
		}
	}

	/**
	 * Determines the public key to send to the server based on the constraints conveyed in the server's
	 * <em>CERTIFICATE_REQUEST</em>.
	 * 
	 * @param certRequest The certificate request containing the constraints to match.
	 * @return An appropriate key or {@code null} if this handshaker has not been configured with an appropriate key.
	 */
	PublicKey determineClientRawPublicKey(CertificateRequest certRequest) throws HandshakeException {

		if (publicKey == null) {
			return null;
		} else {
			negotiatedSignatureAndHashAlgorithm = certRequest.getSignatureAndHashAlgorithm(publicKey);
			if (negotiatedSignatureAndHashAlgorithm == null) {
				return null;
			} else {
				return publicKey;
			}
		}
	}

	/**
	 * Determines the certificate chain to send to the server based on the constraints conveyed in the server's
	 * <em>CERTIFICATE_REQUEST</em>.
	 * 
	 * @param certRequest The certificate request containing the constraints to match.
	 * @return The certificate chain to send to the server. The chain will have length 0 if this handshaker has not been
	 * configured with an appropriate certificate chain.
	 */
	List<X509Certificate> determineClientCertificateChain(CertificateRequest certRequest) throws HandshakeException {

		if (certificateChain == null) {
			return Collections.emptyList();
		} else {
			negotiatedSignatureAndHashAlgorithm = certRequest.getSignatureAndHashAlgorithm(certificateChain);
			if (negotiatedSignatureAndHashAlgorithm == null) {
				return Collections.emptyList();
			} else {
				return certificateChain;
			}
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
	private static boolean isSupportedCertificateType(CertificateType certType,
			List<CertificateType> supportedCertificateTypes) {
		if (supportedCertificateTypes != null) {
			return supportedCertificateTypes.contains(certType);
		} else {
			return certType == CertificateType.X_509;
		}
	}

	@Override
	public void startHandshake() throws HandshakeException {

		handshakeStarted();

		ClientHello startMessage = new ClientHello(maxProtocolVersion, preferredCipherSuites,
				supportedClientCertificateTypes, supportedServerCertificateTypes, session.getPeer());

		// store client random for later calculations
		clientRandom = startMessage.getRandom();

		startMessage.addCompressionMethod(CompressionMethod.NULL);

		addConnectionId(startMessage);

		addMaxFragmentLength(startMessage);

		addServerNameIndication(startMessage);

		// store for later calculations
		flightNumber = 1;
		clientHello = startMessage;
		DTLSFlight flight = new DTLSFlight(session, flightNumber);
		wrapMessage(flight, startMessage);
		sendFlight(flight);
		states = SEVER_CERTIFICATE;
		statesIndex = 0;
	}

	protected void addMaxFragmentLength(final ClientHello helloMessage) {
		if (maxFragmentLengthCode != null) {
			MaxFragmentLengthExtension ext = new MaxFragmentLengthExtension(maxFragmentLengthCode); 
			helloMessage.addExtension(ext);
			LOGGER.trace(
					"Indicating max. fragment length [{}] to server [{}]",
					maxFragmentLengthCode, getPeerAddress());
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

		if (sniEnabled && session.getServerNames() != null) {
			LOGGER.debug("adding SNI extension to CLIENT_HELLO message [{}]", session.getHostName());
			helloMessage.addExtension(ServerNameExtension.forServerNames(session.getServerNames()));
		}
	}
}
