/*******************************************************************************
 * Copyright (c) 2015, 2018 Institute for Pervasive Computing, ETH Zurich and others.
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
import java.security.SecureRandom;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.List;

import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.util.ByteArrayUtils;
import org.eclipse.californium.scandium.util.PskUtil;
import org.eclipse.californium.scandium.util.ServerNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ClientHandshaker does the protocol handshaking from the point of view of a
 * client. It is driven by handshake messages as delivered by the parent
 * {@link Handshaker} class.
 */
public class ClientHandshaker extends Handshaker {

	private static final Logger LOGGER = LoggerFactory.getLogger(ClientHandshaker.class.getName());

	// Members ////////////////////////////////////////////////////////

	private ProtocolVersion maxProtocolVersion = new ProtocolVersion();

	/** The server's public key from its certificate */
	private PublicKey serverPublicKey;

	// The server's X.509 certificate chain.
	private CertPath peerCertPath;

	/** The server's ephemeral public key, used for key agreement */
	private ECPublicKey ephemeralServerPublicKey;

	/** The client's hello handshake message. Store it, to add the cookie in the second flight. */
	protected ClientHello clientHello = null;

	/** the preferred cipher suites ordered by preference */
	private final List<CipherSuite> preferredCipherSuites;

	protected Integer maxFragmentLengthCode;

	/**
	 * The certificate types this peer supports for client authentication.
	 */
	protected final List<CertificateType> supportedClientCertificateTypes;

	/**
	 * The certificate types this peer supports for server authentication.
	 */
	protected final List<CertificateType> supportedServerCertificateTypes;

	/*
	 * Store all the message which can possibly be sent by the server. We need
	 * these to compute the handshake hash.
	 */
	/** The server's {@link ServerHello}. Mandatory. */
	protected ServerHello serverHello;
	/** The server's {@link CertificateMessage}. Optional. */
	protected CertificateMessage serverCertificate = null;
	protected CertificateMessage clientCertificate = null;
	/** The server's {@link CertificateRequest}. Optional. */
	protected CertificateRequest certificateRequest = null;
	protected CertificateVerify certificateVerify = null;
	/** The server's {@link ServerKeyExchange}. Optional. */
	protected ServerKeyExchange serverKeyExchange = null;
	/** The server's {@link ServerHelloDone}. Mandatory. */
	protected ServerHelloDone serverHelloDone;

	/** The hash of all received handshake messages sent in the finished message. */
	protected byte[] handshakeHash = null;

	/** Used to retrieve identity/pre-shared-key for a given destination */
	protected final PskStore pskStore;
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
		this.privateKey = config.getPrivateKey();
		this.certificateChain = config.getCertificateChain();
		this.publicKey = config.getPublicKey();
		this.pskStore = config.getPskStore();
		this.preferredCipherSuites = config.getSupportedCipherSuites();
		this.maxFragmentLengthCode = config.getMaxFragmentLengthCode();
		this.sniEnabled = config.isSniEnabled();

		this.supportedServerCertificateTypes = config.getTrustCertificateTypes();
		this.supportedClientCertificateTypes = config.getIdentityCertificateTypes();
	}

	// Methods ////////////////////////////////////////////////////////

	final SignatureAndHashAlgorithm getNegotiatedSignatureAndHashAlgorithm() {
		return negotiatedSignatureAndHashAlgorithm;
	}

	@Override
	protected void doProcessMessage(DTLSMessage message) throws HandshakeException, GeneralSecurityException {

		// log record now (even if message is still encrypted) in case an Exception
		// is thrown during processing
		if (LOGGER.isDebugEnabled()) {
			StringBuilder msg = new StringBuilder();
			msg.append(String.format(
					"Processing %s message from peer [%s]",
					message.getContentType(), message.getPeer()));
			if (LOGGER.isTraceEnabled()) {
				msg.append(":").append(StringUtil.lineSeparator()).append(message);
			}
			LOGGER.debug(msg.toString());
		}
		
		switch (message.getContentType()) {
		case ALERT:
			break;

		case CHANGE_CIPHER_SPEC:
			// TODO check, if all expected messages already received
			setCurrentReadState();
			LOGGER.debug("Processed {} message from peer [{}]",
					message.getContentType(), message.getPeer());
			break;

		case HANDSHAKE:
			HandshakeMessage handshakeMsg = (HandshakeMessage) message;
			switch (handshakeMsg.getMessageType()) {
			case HELLO_REQUEST:
				receivedHelloRequest();
				break;

			case HELLO_VERIFY_REQUEST:
				receivedHelloVerifyRequest((HelloVerifyRequest) handshakeMsg);
				break;

			case SERVER_HELLO:
				receivedServerHello((ServerHello) handshakeMsg);
				break;

			case CERTIFICATE:
				receivedServerCertificate((CertificateMessage) handshakeMsg);
				break;

			case SERVER_KEY_EXCHANGE:

				switch (getKeyExchangeAlgorithm()) {
				case EC_DIFFIE_HELLMAN:
					receivedServerKeyExchange((ECDHServerKeyExchange) handshakeMsg);
					break;

				case PSK:
					serverKeyExchange = (PSKServerKeyExchange) handshakeMsg;
					break;
				
				case ECDHE_PSK:
					receivedServerKeyExchange((EcdhPskServerKeyExchange) handshakeMsg);
					break;
					
				case NULL:
					LOGGER.info("Received unexpected ServerKeyExchange message in NULL key exchange mode.");
					break;

				default:
					throw new HandshakeException(
							String.format("Unsupported key exchange algorithm %s", getKeyExchangeAlgorithm().name()),
							new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, handshakeMsg.getPeer()));
				}
				break;

			case CERTIFICATE_REQUEST:
				// save for later, will be handled by server hello done
				certificateRequest = (CertificateRequest) handshakeMsg;
				break;

			case SERVER_HELLO_DONE:
				receivedServerHelloDone((ServerHelloDone) handshakeMsg);
				expectChangeCipherSpecMessage();
				break;

			case FINISHED:
				receivedServerFinished((Finished) handshakeMsg);
				break;

			default:
				throw new HandshakeException(
						String.format("Received unexpected handshake message [%s] from peer %s", handshakeMsg.getMessageType(), handshakeMsg.getPeer()),
						new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE, handshakeMsg.getPeer()));
			}

			incrementNextReceiveSeq();
			LOGGER.debug("Processed {} message with sequence no [{}] from peer [{}]",
					handshakeMsg.getMessageType(), handshakeMsg.getMessageSeq(), handshakeMsg.getPeer());
			break;

		default:
			throw new HandshakeException(
					String.format("Received unexpected message [%s] from peer %s", message.getContentType(), message.getPeer()),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, message.getPeer()));
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
		String prfMacName = session.getCipherSuite().getPseudoRandomFunctionMacName();
		message.verifyData(prfMacName, session.getMasterSecret(), false, handshakeHash);
		state = HandshakeType.FINISHED.getCode();
		sessionEstablished();
		handshakeCompleted();
	}

	/**
	 * Used by the server to kickstart negotiations.
	 * 
	 * @param message
	 *            the hello request message
	 * @throws HandshakeException if the CLIENT_HELLO record cannot be created
	 */
	private void receivedHelloRequest() throws HandshakeException {
		if (state < HandshakeType.HELLO_REQUEST.getCode()) {
			startHandshake();
		} else {
			// already started with handshake, drop this message
		}
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

		clientHello.setCookie(message.getCookie());

		flightNumber = 3;
		DTLSFlight flight = new DTLSFlight(getSession(), flightNumber);
		wrapMessage(flight, clientHello);
		sendFlight(flight);
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
		if (serverHello != null && (message.getMessageSeq() == serverHello.getMessageSeq())) {
			// received duplicate version (retransmission), discard it
			return;
		}
		serverHello = message;

		// store the negotiated values
		usedProtocol = message.getServerVersion();
		serverRandom = message.getRandom();
		session.setSessionIdentifier(message.getSessionId());
		session.setCipherSuite(message.getCipherSuite());
		session.setCompressionMethod(message.getCompressionMethod());
		if (message.getMaxFragmentLength() != null) {
			MaxFragmentLengthExtension.Length maxFragmentLength = message.getMaxFragmentLength().getFragmentLength(); 
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
		if (connectionIdGenerator != null) {
			ConnectionIdExtension extension = serverHello.getConnectionIdExtension();
			if (extension != null) {
				ConnectionId connectionId = extension.getConnectionId();
				session.setWriteConnectionId(connectionId);
			}
		}
		session.setSendCertificateType(serverHello.getClientCertificateType());
		session.setReceiveCertificateType(serverHello.getServerCertificateType());
		session.setSniSupported(serverHello.hasServerNameExtension());
		session.setParameterAvailable();
		initMessageDigest();
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
		if (serverCertificate != null && (serverCertificate.getMessageSeq() == message.getMessageSeq())) {
			// discard duplicate message
			return;
		}

		serverCertificate = message;
		verifyCertificate(serverCertificate);
		serverPublicKey = serverCertificate.getPublicKey();
		peerCertPath = message.getCertificateChain();
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
		if (serverKeyExchange != null && (serverKeyExchange.getMessageSeq() == message.getMessageSeq())) {
			// discard duplicate message
			return;
		}

		serverKeyExchange = message;
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
		if (serverKeyExchange != null && (serverKeyExchange.getMessageSeq() == message.getMessageSeq())) {
			// discard duplicate message
			return;
		}
		serverKeyExchange = message;
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
	private void receivedServerHelloDone(ServerHelloDone message) throws HandshakeException, GeneralSecurityException {

		if (serverHelloDone != null && (serverHelloDone.getMessageSeq() == message.getMessageSeq())) {
			// discard duplicate message
			return;
		}
		serverHelloDone = message;
		flightNumber += 2;
		DTLSFlight flight = new DTLSFlight(getSession(), flightNumber);

		createCertificateMessage(flight);

		/*
		 * Second, send ClientKeyExchange as specified by the key exchange
		 * algorithm.
		 */
		ClientKeyExchange clientKeyExchange;
		byte[] premasterSecret;
		switch (getKeyExchangeAlgorithm()) {
		case EC_DIFFIE_HELLMAN:
			clientKeyExchange = new ECDHClientKeyExchange(ecdhe.getPublicKey(), session.getPeer());
			premasterSecret = ecdhe.getSecret(ephemeralServerPublicKey).getEncoded();
			generateKeys(premasterSecret);
			break;
		case PSK:
			PskUtil pskUtilPlain = new PskUtil(sniEnabled, session, pskStore);
			LOGGER.debug("Using PSK identity: {}", pskUtilPlain.getPskPrincipal());
			session.setPeerIdentity(pskUtilPlain.getPskPrincipal());
			clientKeyExchange = new PSKClientKeyExchange(pskUtilPlain.getPskPublicIdentity(), session.getPeer());
			premasterSecret = generatePremasterSecretFromPSK(pskUtilPlain.getPreSharedKey(), null);
			generateKeys(premasterSecret);
			break;
		case ECDHE_PSK:
			PskUtil pskUtil = new PskUtil(sniEnabled, session, pskStore);
			LOGGER.debug("Using PSK identity: {}", pskUtil.getPskPrincipal());
			session.setPeerIdentity(pskUtil.getPskPrincipal());
			clientKeyExchange = new EcdhPskClientKeyExchange(pskUtil.getPskPublicIdentity(), ecdhe.getPublicKey(), session.getPeer());
			byte[] otherSecret = ecdhe.getSecret(ephemeralServerPublicKey).getEncoded();
			premasterSecret = generatePremasterSecretFromPSK(pskUtil.getPreSharedKey(), otherSecret);
			generateKeys(premasterSecret);
			break;
		case NULL:
			clientKeyExchange = new NULLClientKeyExchange(session.getPeer());

			// We assume, that the premaster secret is empty
			generateKeys(Bytes.EMPTY);
			break;

		default:
			throw new HandshakeException(
					"Unknown key exchange algorithm: " + getKeyExchangeAlgorithm(),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, session.getPeer()));
		}
		wrapMessage(flight, clientKeyExchange);

		/*
		 * Third, send CertificateVerify message if necessary.
		 */
		if (certificateRequest != null && negotiatedSignatureAndHashAlgorithm != null) {
			// prepare handshake messages
			handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, clientHello.toByteArray());
			handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, serverHello.toByteArray());
			handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, serverCertificate.toByteArray());
			handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, serverKeyExchange.toByteArray());
			handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, certificateRequest.toByteArray());
			handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, serverHelloDone.toByteArray());
			handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, clientCertificate.toByteArray());
			handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, clientKeyExchange.toByteArray());

			certificateVerify = new CertificateVerify(negotiatedSignatureAndHashAlgorithm, privateKey, handshakeMessages, session.getPeer());

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
		md.update(clientHello.toByteArray());
		md.update(serverHello.toByteArray());
		if (serverCertificate != null) {
			md.update(serverCertificate.toByteArray());
		}
		if (serverKeyExchange != null) {
			md.update(serverKeyExchange.toByteArray());
		}
		if (certificateRequest != null) {
			md.update(certificateRequest.toByteArray());
		}
		md.update(serverHelloDone.toByteArray());

		if (clientCertificate != null) {
			md.update(clientCertificate.toByteArray());
		}
		md.update(clientKeyExchange.toByteArray());

		if (certificateVerify != null) {
			md.update(certificateVerify.toByteArray());
		}

		MessageDigest mdWithClientFinished = null;
		try {
			mdWithClientFinished = (MessageDigest) md.clone();
		} catch (CloneNotSupportedException e) {
			throw new HandshakeException(
					"Cannot create FINISHED message",
					new AlertMessage(
							AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, message.getPeer()));
		}

		handshakeHash = md.digest();
		String prfMacName = session.getCipherSuite().getPseudoRandomFunctionMacName();
		Finished finished = new Finished(prfMacName, session.getMasterSecret(), isClient, handshakeHash, session.getPeer());
		wrapMessage(flight, finished);

		// compute handshake hash with client's finished message also
		// included, used for server's finished message
		mdWithClientFinished.update(finished.toByteArray());
		handshakeHash = mdWithClientFinished.digest();
		sendFlight(flight);
	}

	private void createCertificateMessage(final DTLSFlight flight) throws HandshakeException {

		/*
		 * First, if required by server, send Certificate.
		 */
		if (certificateRequest != null) {

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
				// make sure we only send certs not part of the server's trust anchor
				List<X509Certificate> truncatedChain = certificateRequest.removeTrustedCertificates(clientChain);
				LOGGER.debug("sending CERTIFICATE message with client certificate chain [length: {}] to server", truncatedChain.size());
				clientCertificate = new CertificateMessage(truncatedChain, session.getPeer());
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

	@Override
	public void startHandshake() throws HandshakeException {

		handshakeStarted();

		ClientHello startMessage = new ClientHello(maxProtocolVersion, new SecureRandom(), 
				preferredCipherSuites,
				supportedClientCertificateTypes, supportedServerCertificateTypes, session.getPeer());

		// store client random for later calculations
		clientRandom = startMessage.getRandom();

		startMessage.addCompressionMethod(CompressionMethod.NULL);

		addConnectionId(startMessage);

		addMaxFragmentLength(startMessage);

		addServerNameIndication(startMessage);

		// set current state
		state = startMessage.getMessageType().getCode();

		// store for later calculations
		flightNumber = 1;
		clientHello = startMessage;
		DTLSFlight flight = new DTLSFlight(session, flightNumber);
		wrapMessage(flight, startMessage);
		sendFlight(flight);
	}

	protected void addMaxFragmentLength(final ClientHello helloMessage) {
		if (maxFragmentLengthCode != null) {
			MaxFragmentLengthExtension ext = new MaxFragmentLengthExtension(maxFragmentLengthCode); 
			helloMessage.addExtension(ext);
			LOGGER.debug(
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

		if (sniEnabled && session.getVirtualHost() != null) {
			LOGGER.debug("adding SNI extension to CLIENT_HELLO message [{}]", session.getVirtualHost());
			helloMessage.addExtension(ServerNameExtension.forHostName(session.getVirtualHost()));
		}
	}
}
