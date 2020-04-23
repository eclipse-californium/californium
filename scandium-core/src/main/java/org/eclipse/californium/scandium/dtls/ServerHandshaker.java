/*******************************************************************************
 * Copyright (c) 2015, 2019 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - small improvements
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 464383
 *    Kai Hudalla (Bosch Software Innovations GmbH) - store peer's identity in session as a
 *                                                    java.security.Principal (fix 464812)
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add support for stale
 *                                                    session expiration (466554)
 *    Kai Hudalla (Bosch Software Innovations GmbH) - notify SessionListener about start and completion
 *                                                    of handshake
 *    Kai Hudalla (Bosch Software Innovations GmbH) - only include client/server certificate type extensions
 *                                                    in SERVER_HELLO if required for cipher suite
 *    Kai Hudalla (Bosch Software Innovations GmbH) - pick arbitrary supported group if client omits
 *                                                    Supported Elliptic Curves Extension (fix 473678)
 *    Kai Hudalla (Bosch Software Innovations GmbH) - consolidate and fix record buffering and message re-assembly
 *    Kai Hudalla (Bosch Software Innovations GmbH) - replace Handshaker's compressionMethod and cipherSuite
 *                                                    properties with corresponding properties in DTLSSession
 *    Kai Hudalla (Bosch Software Innovations GmbH) - derive max fragment length from network MTU
 *    Kai Hudalla (Bosch Software Innovations GmbH) - support MaxFragmentLength Hello extension sent by client
 *    Achim Kraus (Bosch Software Innovations GmbH) - don't ignore retransmission of last flight
 *    Achim Kraus (Bosch Software Innovations GmbH) - use isSendRawKey also for 
 *                                                    supportedClientCertificateTypes
 *    Ludwig Seitz (RISE SICS) - Updated calls to verifyCertificate() after refactoring
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix issue #560
 *                                                    If client auth is not required, don't sent
 *                                                    client cert types in SERVER_HELLO
 *                                                    Additionally don't send cert types, if
 *                                                    only none cert cipher suites are supported
 *                                                    (similar to PR #468)
 *    Achim Kraus (Bosch Software Innovations GmbH) - issue #549
 *                                                    trustStore := null, disable x.509
 *                                                    trustStore := [], enable x.509, trust all
 *    Vikram (University of Rostock) - added ECDHE_PSK mode
 *    Achim Kraus (Bosch Software Innovations GmbH) - add handshake parameter available to
 *                                                    process reordered handshake messages
 *    Achim Kraus (Bosch Software Innovations GmbH) - add dtls flight number
 *    Achim Kraus (Bosch Software Innovations GmbH) - add preSharedKeyIdentity to
 *                                                    support creating statistics.
 *    Achim Kraus (Bosch Software Innovations GmbH) - redesign DTLSFlight and RecordLayer
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.util.CertPathUtil;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.CertificateRequest.ClientCertificateType;
import org.eclipse.californium.scandium.dtls.SupportedPointFormatsExtension.ECPointFormat;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuiteParameters;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuiteSelector;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.util.SecretUtil;

/**
 * Server handshaker does the protocol handshaking from the point of view of a
 * server. It is message-driven by the parent {@link Handshaker} class.
 */
public class ServerHandshaker extends Handshaker {

	private static HandshakeState[] CLIENT_CERTIFICATE = { new HandshakeState(HandshakeType.CERTIFICATE),
			new HandshakeState(HandshakeType.CLIENT_KEY_EXCHANGE),
			new HandshakeState(HandshakeType.CERTIFICATE_VERIFY),
			new HandshakeState(ContentType.CHANGE_CIPHER_SPEC), new HandshakeState(HandshakeType.FINISHED) };
	private static HandshakeState[] EMPTY_CLIENT_CERTIFICATE = { new HandshakeState(HandshakeType.CERTIFICATE),
			new HandshakeState(HandshakeType.CLIENT_KEY_EXCHANGE),
			new HandshakeState(ContentType.CHANGE_CIPHER_SPEC), new HandshakeState(HandshakeType.FINISHED) };
	protected static HandshakeState[] NO_CLIENT_CERTIFICATE = { new HandshakeState(HandshakeType.CLIENT_KEY_EXCHANGE),
			new HandshakeState(ContentType.CHANGE_CIPHER_SPEC), new HandshakeState(HandshakeType.FINISHED) };

	// Members ////////////////////////////////////////////////////////

	/** Does the server use session id? */
	private boolean useNoSessionId = false;

	/** Is the client wanted to authenticate itself? */
	private boolean clientAuthenticationWanted = false;

	/** Is the client required to authenticate itself? */
	private boolean clientAuthenticationRequired = false;

	/**
	 * The client's public key from its certificate (only sent when
	 * CertificateRequest sent).
	 */
	private PublicKey clientPublicKey;

	/**
	 * Cipher suite selector.
	 * 
	 * @since 2.3
	 */
	private CipherSuiteSelector cipherSuiteSelector;

	/**
	 * The cryptographic options this server supports, e.g. for exchanging keys,
	 * digital signatures etc.
	 */
	private List<CipherSuite> supportedCipherSuites;

	/**
	 * The supported groups (curves) ordered by preference.
	 * 
	 * @since 2.3
	 */
	protected final List<SupportedGroup> supportedGroups;

	/**
	 * The certificate types this server supports for client authentication.
	 */
	private final List<CertificateType> supportedClientCertificateTypes;
	/**
	 * The certificate types this server supports for server authentication.
	 */
	private final List<CertificateType> supportedServerCertificateTypes;
	/**
	 * The supported signature and hash algorithms ordered by preference.
	 * 
	 * @since 2.3
	 */
	private final List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms;

	private CipherSuiteParameters selectedCipherSuiteParameters;

	/** The client's {@link CertificateMessage}. Optional. */
	private CertificateMessage clientCertificate = null;
	/** The client's {@link CertificateVerify}. Optional. */
	private CertificateVerify certificateVerify = null;

	private PskPublicInformation preSharedKeyIdentity;

	/**
	 * The helper class to execute the ECDHE key agreement and key generation.
	 * 
	 * @since 2.3
	 */
	private XECDHECryptography ecdhe;

	// Constructors ///////////////////////////////////////////////////

	/**
	 * Creates a handshaker for negotiating a DTLS session with a client
	 * following the full DTLS handshake protocol.
	 * 
	 * @param initialMessageSequenceNo
	 *            the initial message sequence number to expect from the peer
	 *            (this parameter can be used to initialize the <em>receive_next_seq</em>
	 *            counter to another value than 0, e.g. if one or more cookie exchange round-trips
	 *            have been performed with the peer before the handshake starts).
	 * @param session
	 *            the session to negotiate with the client.
	 * @param recordLayer
	 *            the object to use for sending flights to the peer.
	 * @param connection
	 *            the connection related with the session.
	 * @param config
	 *            the DTLS configuration.
	 * @param maxTransmissionUnit
	 *            the MTU value reported by the network interface the record layer is bound to.
	 *
	 * @throws IllegalStateException
	 *            if the message digest required for computing the FINISHED message hash cannot be instantiated.
	 * @throws IllegalArgumentException
	 *            if the <code>initialMessageSequenceNo</code> is negative.
	 * @throws NullPointerException
	 *            if session, recordLayer or config is <code>null</code>.
	 */
	public ServerHandshaker(int initialMessageSequenceNo, DTLSSession session, RecordLayer recordLayer,
			Connection connection, DtlsConnectorConfig config, int maxTransmissionUnit) {
		super(false, initialMessageSequenceNo, session, recordLayer, connection, config, maxTransmissionUnit);

		this.cipherSuiteSelector = config.getCipherSuiteSelector();
		this.supportedCipherSuites = config.getSupportedCipherSuites();
		this.supportedGroups = config.getSupportedGroups();

		this.clientAuthenticationWanted = config.isClientAuthenticationWanted();
		this.clientAuthenticationRequired = config.isClientAuthenticationRequired();
		this.useNoSessionId = config.useNoServerSessionId();

		// the server handshake uses the config with exchanged roles!
		this.supportedClientCertificateTypes = config.getTrustCertificateTypes();
		this.supportedServerCertificateTypes = config.getIdentityCertificateTypes();
		List<SignatureAndHashAlgorithm> algorithms = config.getSupportedSignatureAlgorithms();
		if (algorithms.isEmpty()) {
			if (certificateChain == null) {
				algorithms = SignatureAndHashAlgorithm.DEFAULT;
			} else {
				algorithms = SignatureAndHashAlgorithm.getSignatureAlgorithmsFromCertificateChain(certificateChain);
			}
		}
		this.supportedSignatureAndHashAlgorithms = algorithms;
	}

	// Methods ////////////////////////////////////////////////////////

	public PskPublicInformation getPreSharedKeyIdentity() {
		return preSharedKeyIdentity;
	}

	@Override
	protected void doProcessMessage(HandshakeMessage message) throws HandshakeException, GeneralSecurityException {

		switch (message.getMessageType()) {
		case CLIENT_HELLO:
			receivedClientHello((ClientHello) message);
			break;

		case CERTIFICATE:
			receivedClientCertificate((CertificateMessage) message);
			break;

		case CLIENT_KEY_EXCHANGE:
			SecretKey premasterSecret;
			switch (getKeyExchangeAlgorithm()) {
			case PSK:
				premasterSecret = receivedClientKeyExchange((PSKClientKeyExchange) message);
				break;

			case ECDHE_PSK:
				premasterSecret = receivedClientKeyExchange((EcdhPskClientKeyExchange) message);
				break;

			case EC_DIFFIE_HELLMAN:
				premasterSecret = receivedClientKeyExchange((ECDHClientKeyExchange) message);
				break;

			default:
				throw new HandshakeException(
						String.format("Unsupported key exchange algorithm %s", getKeyExchangeAlgorithm().name()),
						new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, message.getPeer()));
			}
			if (premasterSecret != null) {
				generateKeys(premasterSecret);
				SecretUtil.destroy(premasterSecret);
			}

			if (!clientAuthenticationRequired || getKeyExchangeAlgorithm() != KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN) {
				expectChangeCipherSpecMessage();
			}
			break;

		case CERTIFICATE_VERIFY:
			receivedCertificateVerify((CertificateVerify) message);
			expectChangeCipherSpecMessage();
			break;

		case FINISHED:
			receivedClientFinished((Finished) message);
			break;

		default:
			throw new HandshakeException(
					String.format("Received unexpected %s message from peer %s", message.getMessageType(), message.getPeer()),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE, message.getPeer()));
		}
	}

	/**
	 * If the server requires mutual authentication, the client must send its
	 * certificate.
	 * 
	 * @param message
	 *            the client's {@link CertificateMessage}.
	 * @throws HandshakeException
	 *             if the certificate could not be verified.
	 */
	private void receivedClientCertificate(final CertificateMessage message) throws HandshakeException {

		clientCertificate = message;
		clientPublicKey = message.getPublicKey();
		if (clientAuthenticationRequired && message.getCertificateChain() != null
				&& clientPublicKey == null) {
			LOGGER.debug("Client authentication failed: missing certificate!");
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE,
					session.getPeer());
			throw new HandshakeException("Client Certificate required!", alert);
		}
		verifyCertificate(message);
		if (clientPublicKey == null) {
			states = EMPTY_CLIENT_CERTIFICATE;
		}
	}

	/**
	 * Verifies the client's CertificateVerify message.
	 * <p>
	 * If verification succeeds, the session's <em>peerIdentity</em> property
	 * contains a principal reflecting the client's authenticated identity.
	 * 
	 * @param message The client's <em>CERTIFICATE_VERIFY</em> message.
	 * @throws HandshakeException if verification of the signature fails.
	 */
	private void receivedCertificateVerify(CertificateVerify message) throws HandshakeException {
		certificateVerify = message;
		// remove last message - CertificateVerify itself
		handshakeMessages.remove(handshakeMessages.size() - 1);
		message.verifySignature(clientPublicKey, handshakeMessages);
		// add CertificateVerify again
		handshakeMessages.add(message);
		// at this point we have successfully authenticated the client
		if (peerCertPath != null) {
			session.setPeerIdentity(new X509CertPath(peerCertPath));
		} else {
			session.setPeerIdentity(new RawPublicKeyIdentity(clientPublicKey));
		}
	}

	/**
	 * Called, when the server received the client's {@link Finished} message.
	 * Generate a {@link DTLSFlight} containing the
	 * {@link ChangeCipherSpecMessage} and {@link Finished} message. This flight
	 * will not be retransmitted, unless we receive the same finish message in
	 * the future; then, we retransmit this flight.
	 * 
	 * @param message
	 *            the client's {@link Finished} message.
	 * @throws HandshakeException if the client did not send the required <em>CLIENT_CERTIFICATE</em>
	 *            and <em>CERTIFICATE_VERIFY</em> messages or if the server's FINISHED message
	 *            cannot be created
	 */
	private void receivedClientFinished(Finished message) throws HandshakeException {

		// check if client sent all expected messages
		// (i.e. ClientCertificate/CertificateVerify when server sent CertificateRequest)
		if (CipherSuite.KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN.equals(getKeyExchangeAlgorithm()) && 
				clientAuthenticationRequired && 
				(clientCertificate == null || certificateVerify == null)) {
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, session.getPeer());
			throw new HandshakeException("Client did not send required authentication messages.", alert);
		}

		flightNumber += 2;
		DTLSFlight flight = new DTLSFlight(getSession(), flightNumber);

		// create handshake hash
		MessageDigest md = getHandshakeMessageDigest();

		MessageDigest mdWithClientFinished;
		try {
			/*
			 * the handshake_messages for the Finished message sent by the
			 * client will be different from that for the Finished message sent
			 * by the server, because the one that is sent second will include
			 * the prior one.
			 */
			mdWithClientFinished = (MessageDigest) md.clone();
		} catch (CloneNotSupportedException e) {
			throw new HandshakeException(
					"Cannot create FINISHED message hash",
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.INTERNAL_ERROR,
							message.getPeer()));
//			LOGGER.error("Cannot compute digest for server's Finish handshake message", e);
		}

		// Verify client's data
		message.verifyData(session.getCipherSuite().getThreadLocalPseudoRandomFunctionMac(), masterSecret, true, md.digest());

		/*
		 * First, send ChangeCipherSpec
		 */
		ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage(session.getPeer());
		wrapMessage(flight, changeCipherSpecMessage);
		setCurrentWriteState();

		/*
		 * Second, send Finished message
		 */
		mdWithClientFinished.update(message.toByteArray());
		Finished finished = new Finished(session.getCipherSuite().getThreadLocalPseudoRandomFunctionMac(), masterSecret, isClient, mdWithClientFinished.digest(), session.getPeer());
		wrapMessage(flight, finished);
		sendLastFlight(flight);
		sessionEstablished();
	}

	/**
	 * Called after the server receives a {@link ClientHello} handshake message.
	 * 
	 * Prepares the next flight (mandatory messages depend on the cipher suite / key exchange
	 * algorithm). Mandatory messages are ServerHello and ServerHelloDone; see
	 * <a href="http://tools.ietf.org/html/rfc5246#section-7.3">Figure 1.
	 * Message flow for a full handshake</a> for details about the messages in
	 * the next flight.
	 * 
	 * @param clientHello
	 *            the client's hello message.
	 * @throws HandshakeException if the server's response message(s) cannot be created
	 */
	private void receivedClientHello(final ClientHello clientHello) throws HandshakeException {

		handshakeStarted();

		byte[] cookie = clientHello.getCookie();
		flightNumber = (cookie != null && cookie.length > 0) ? 4 : 2;

		DTLSFlight flight = new DTLSFlight(getSession(), flightNumber);

		createServerHello(clientHello, flight);

		createCertificateMessage(clientHello, flight);

		createServerKeyExchange(clientHello, flight);

		boolean clientCertificate = createCertificateRequest(clientHello, flight);

		if (clientCertificate) {
			states = CLIENT_CERTIFICATE;
		} else {
			states = NO_CLIENT_CERTIFICATE;
		}
		statesIndex = -1;

		/*
		 * Last, send ServerHelloDone (mandatory)
		 */
		ServerHelloDone serverHelloDone = new ServerHelloDone(session.getPeer());
		wrapMessage(flight, serverHelloDone);
		sendFlight(flight);
	}

	private void createServerHello(final ClientHello clientHello, final DTLSFlight flight) throws HandshakeException {

		ProtocolVersion serverVersion = negotiateProtocolVersion(clientHello.getClientVersion());

		// store client and server random
		clientRandom = clientHello.getRandom();
		serverRandom = new Random();

		SessionId sessionId = useNoSessionId ? SessionId.emptySessionId() : new SessionId();
		session.setSessionIdentifier(sessionId);

		// currently only NULL compression supported, no negotiation needed
		if (!clientHello.getCompressionMethods().contains(CompressionMethod.NULL)) {
			// abort handshake
			throw new HandshakeException(
					"Client does not support NULL compression method",
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.HANDSHAKE_FAILURE,
							clientHello.getPeer()));
		} else {
			session.setCompressionMethod(CompressionMethod.NULL);
		}

		HelloExtensions serverHelloExtensions = new HelloExtensions();
		negotiateCipherSuite(clientHello, serverHelloExtensions);
		processHelloExtensions(clientHello, serverHelloExtensions);

		ServerHello serverHello = new ServerHello(serverVersion, serverRandom, sessionId,
				session.getCipherSuite(), session.getCompressionMethod(), serverHelloExtensions, session.getPeer());
		wrapMessage(flight, serverHello);
	}

	private void createCertificateMessage(final ClientHello clientHello, final DTLSFlight flight) throws HandshakeException {

		CertificateMessage certificateMessage = null;
		if (session.getCipherSuite().requiresServerCertificateMessage()) {
			if (CertificateType.RAW_PUBLIC_KEY == session.sendCertificateType()) {
				certificateMessage = new CertificateMessage(publicKey.getEncoded(), session.getPeer());
			} else if (CertificateType.X_509 == session.sendCertificateType()) {
				certificateMessage = new CertificateMessage(certificateChain, session.getPeer());
			} else {
				throw new IllegalArgumentException("Certificate type " + session.sendCertificateType() + " not supported!");
			}
			wrapMessage(flight, certificateMessage);
		}
	}

	private void createServerKeyExchange(final ClientHello clientHello, final DTLSFlight flight) throws HandshakeException {

		/*
		 * Third, send ServerKeyExchange (if required by key exchange
		 * algorithm)
		 */
		ServerKeyExchange serverKeyExchange = null;
		switch (getKeyExchangeAlgorithm()) {
		case EC_DIFFIE_HELLMAN:
			try {
				ecdhe = new XECDHECryptography(selectedCipherSuiteParameters.getSelectedSupportedGroup());
				serverKeyExchange = new EcdhEcdsaServerKeyExchange(session.getSignatureAndHashAlgorithm(), ecdhe, privateKey, clientRandom, serverRandom,
						session.getPeer());
				break;
			} catch (GeneralSecurityException e) {
				throw new HandshakeException(
						String.format("Error performing EC Diffie Hellman key exchange: %s", e.getMessage()),
						new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, getPeerAddress()));
			}

		case PSK:
			/*
			 * If the identity is based on the domain name, servers SHOULD
			 * NOT send an identity hint and clients MUST ignore it.
			 * Are there use cases that different PSKs are used for different
			 * actions or time periods? How to configure the hint then? 
			 */
			// serverKeyExchange = new PSKServerKeyExchange("TODO");
			break;

		case ECDHE_PSK:

			try {
				ecdhe = new XECDHECryptography(selectedCipherSuiteParameters.getSelectedSupportedGroup());
				serverKeyExchange = new EcdhPskServerKeyExchange(PskPublicInformation.EMPTY, ecdhe, session.getPeer());
				break;
			} catch (GeneralSecurityException e) {
				throw new HandshakeException(
						String.format("Error performing EC Diffie Hellman key exchange: %s", e.getMessage()),
						new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, getPeerAddress()));
			}

		default:
			// NULL does not require the server's key exchange message
			break;
		}

		if (serverKeyExchange != null) {
			wrapMessage(flight, serverKeyExchange);
		}
	}

	private boolean createCertificateRequest(final ClientHello clientHello, final DTLSFlight flight)
			throws HandshakeException {
		if ((clientAuthenticationWanted || clientAuthenticationRequired)
				&& session.getCipherSuite().requiresServerCertificateMessage()
				&& selectedCipherSuiteParameters.getSelectedClientCertificateType() != null) {
			CertificateRequest certificateRequest = new CertificateRequest(session.getPeer());
			certificateRequest.addCertificateType(ClientCertificateType.ECDSA_SIGN);
			certificateRequest.addSignatureAlgorithms(supportedSignatureAndHashAlgorithms);
			if (certificateVerifier != null) {
				List<X500Principal> subjects = CertPathUtil
						.toSubjects(Arrays.asList(certificateVerifier.getAcceptedIssuers()));
				certificateRequest.addCerticiateAuthorities(subjects);
			}
			wrapMessage(flight, certificateRequest);
			return true;
		}
		return false;
	}

	/**
	 * Generates the premaster secret by taking the client's public key and
	 * running the ECDHE key agreement.
	 * 
	 * @param message
	 *            the client's key exchange message.
	 * @return the premaster secret
	 * @throws GeneralSecurityException
	 */
	private SecretKey receivedClientKeyExchange(ECDHClientKeyExchange message) throws GeneralSecurityException {
		return ecdhe.generateSecret(message.getEncodedPoint());
	}

	/**
	 * Retrieves the preshared key from the identity hint and then generates the
	 * premaster secret.
	 * 
	 * @param message
	 *            the client's key exchange message.
	 * @return the premaster secret
	 * @throws HandshakeException
	 *             if no specified preshared key available.
	 */
	private SecretKey receivedClientKeyExchange(final PSKClientKeyExchange message) throws HandshakeException {
		// use the client's PSK identity to look up the pre-shared key
		preSharedKeyIdentity = message.getIdentity();
		PskUtil pskUtil = new PskUtil(sniEnabled, session, pskStore, preSharedKeyIdentity);
		SecretKey premaster = pskUtil.generatePremasterSecretFromPSK(null);
		SecretUtil.destroy(pskUtil);
		return premaster;
	}

	private SecretKey receivedClientKeyExchange(final EcdhPskClientKeyExchange message) throws HandshakeException, GeneralSecurityException {
		// use the client's PSK identity to look up the pre-shared key
		preSharedKeyIdentity = message.getIdentity();
		PskUtil pskUtil = new PskUtil(sniEnabled, session, pskStore, preSharedKeyIdentity);
		SecretKey eck = ecdhe.generateSecret(message.getEncodedPoint());
		SecretKey premaster = pskUtil.generatePremasterSecretFromPSK(eck);
		SecretUtil.destroy(pskUtil);
		SecretUtil.destroy(eck);
		return premaster;
	}

	protected void processHelloExtensions(final ClientHello clientHello, final HelloExtensions serverHelloExtensions) {
		MaxFragmentLengthExtension maxFragmentLengthExt = clientHello.getMaxFragmentLengthExtension();
		if (maxFragmentLengthExt != null) {
			session.setMaxFragmentLength(maxFragmentLengthExt.getFragmentLength().length());
			serverHelloExtensions.addExtension(maxFragmentLengthExt);
			LOGGER.debug(
					"Negotiated max. fragment length [{} bytes] with peer [{}]",
					maxFragmentLengthExt.getFragmentLength().length(), clientHello.getPeer());
		}

		ServerNameExtension serverNameExt = clientHello.getServerNameExtension();
		if (serverNameExt != null) {
			if (sniEnabled) {
				// store the names indicated by peer for later reference during key exchange
				session.setServerNames(serverNameExt.getServerNames());
				// RFC6066, section 3 requires the server to respond with
				// an empty SNI extension if it might make use of the value(s)
				// provided by the client
				serverHelloExtensions.addExtension(ServerNameExtension.emptyServerNameIndication());
				session.setSniSupported(true);
				LOGGER.debug(
						"using server name indication received from peer [{}]",
						clientHello.getPeer());
			} else {
				LOGGER.debug("client [{}] included SNI in HELLO but SNI support is disabled",
						clientHello.getPeer());
			}
		}

		if (connectionIdGenerator != null) {
			ConnectionIdExtension connectionIdExtension = clientHello.getConnectionIdExtension();
			if (connectionIdExtension != null) {
				session.setWriteConnectionId(connectionIdExtension.getConnectionId());
				final ConnectionId connectionId;
				if (connectionIdGenerator.useConnectionId()) {
					// use the already created unique cid
					connectionId = getConnection().getConnectionId();
				} else {
					// use empty cid
					connectionId = ConnectionId.EMPTY;
				}
				ConnectionIdExtension extension = ConnectionIdExtension.fromConnectionId(connectionId);
				serverHelloExtensions.addExtension(extension);
			}
		}
	}

	@Override
	public void startHandshake() throws HandshakeException {
		throw new HandshakeException("starting an handshake is not supported for server handshaker!", null);
	}

	/**
	 * Negotiates the version to be used. It will return the lower of that
	 * suggested by the client in the client hello and the highest supported by
	 * the server.
	 * 
	 * @param clientVersion
	 *            the suggested version by the client.
	 * @return the version to be used in the handshake.
	 * @throws HandshakeException
	 *             if the client's version is smaller than DTLS 1.2
	 */
	private ProtocolVersion negotiateProtocolVersion(ProtocolVersion clientVersion) throws HandshakeException {
		ProtocolVersion version = new ProtocolVersion();
		if (clientVersion.compareTo(version) >= 0) {
			return new ProtocolVersion();
		} else {
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.PROTOCOL_VERSION, session.getPeer());
			throw new HandshakeException("The server only supports DTLS v1.2", alert);
		}
	}

	/**
	 * Selects one of the client's proposed cipher suites.
	 * <p>
	 * Iterates through the provided (ordered) list of the client's
	 * preferred ciphers until one is found that is also contained
	 * in the {@link #supportedCipherSuites}.
	 * </p>
	 * <p>
	 * If the client proposes an ECC based cipher suite this method also
	 * tries to determine an appropriate <em>Supported Group</em> by means
	 * of invoking the {@link #getCommonSupportedGroups(ClientHello)} method.
	 * If at least one group is found it will be stored in the {@link #negotiatedSupportedGroups}
	 * list. A ECC based cipher suite will only be accepted, if a server
	 * certificate with the used curve is available.
	 * </p>
	 * <p>
	 * The selected cipher suite is set on the <em>session</em> to be negotiated
	 * using the {@link DTLSSession#setCipherSuite(CipherSuite)} method. The
	 * <em>negotiatedServerCertificateType</em>, <em>negotiatedClientCertificateType</em>
	 * and <em>negotiatedSupportedGroup</em> fields are set to values corresponding to
	 * the selected cipher suite.
	 * </p>
	 * <p>
	 * The <em>SSL_NULL_WITH_NULL_NULL</em> cipher suite is <em>never</em>
	 * negotiated as mandated by <a href="http://tools.ietf.org/html/rfc5246#appendix-A.5">
	 * RFC 5246 Appendix A.5</a>
	 * </p>
	 * 
	 * @param clientHello
	 *            the <em>CLIENT_HELLO</em> message containing the list of cipher suites
	 *            the client supports (ordered by preference).
	 * @param serverHelloExtensions
	 *            the container object to add server extensions to that are required for the selected
	 *            cipher suite.
	 * @throws HandshakeException
	 *             if this server's configuration does not support any of the cipher suites
	 *             proposed by the client.
	 */
	private void negotiateCipherSuite(final ClientHello clientHello, final HelloExtensions serverHelloExtensions)
			throws HandshakeException {

		List<CipherSuite> commonCipherSuites = getCommonCipherSuites(clientHello);
		List<CertificateType> commonServerCertTypes = getCommonServerCertificateTypes(clientHello);
		List<CertificateType> commonClientCertTypes = getCommonClientCertificateTypes(clientHello);
		List<SupportedGroup> commonGroups = getCommonSupportedGroups(clientHello);
		List<SignatureAndHashAlgorithm> commonSignatures = getCommonSignatureAndHashAlgorithms(clientHello);
		ECPointFormat format = negotiateECPointFormat(clientHello);
		CipherSuiteParameters parameters = new CipherSuiteParameters(
				publicKey, certificateChain, clientAuthenticationRequired, clientAuthenticationWanted,
				commonCipherSuites, commonServerCertTypes, commonClientCertTypes,
				commonGroups, commonSignatures, format);
		if (cipherSuiteSelector.select(parameters)) {
			selectedCipherSuiteParameters = parameters;
			CipherSuite cipherSuite = parameters.getSelectedCipherSuite();
			session.setCipherSuite(cipherSuite);
			if (cipherSuite.requiresServerCertificateMessage()) {
				session.setSignatureAndHashAlgorithm(parameters.getSelectedSignature());
				session.setSendCertificateType(parameters.getSelectedServerCertificateType());
				CertificateType certificateType = parameters.getSelectedClientCertificateType();
				if (clientAuthenticationRequired || (clientAuthenticationWanted && certificateType != null)) {
					session.setReceiveCertificateType(parameters.getSelectedClientCertificateType());
				}
			}
			addServerHelloExtensions(cipherSuite, clientHello, serverHelloExtensions);
			session.setParameterAvailable();
			LOGGER.debug("Negotiated cipher suite [{}] with peer [{}]", cipherSuite.name(), getPeerAddress());
		} else {
			// if none of the client's proposed cipher suites matches
			// throw exception
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE,
					session.getPeer());
			throw new HandshakeException("Client proposed unsupported cipher suites only", alert);
		}
	}

	private void addServerHelloExtensions(final CipherSuite negotiatedCipherSuite, final ClientHello clientHello, final HelloExtensions extensions) {
		CertificateType certificateType = session.receiveCertificateType();
		if (certificateType != null) {
			if (clientHello.getClientCertificateTypeExtension() != null) {
				ClientCertificateTypeExtension ext = new ClientCertificateTypeExtension(certificateType);
				extensions.addExtension(ext);
			}
		}
		certificateType = session.sendCertificateType();
		if (certificateType != null) {
			if (clientHello.getServerCertificateTypeExtension() != null) {
				ServerCertificateTypeExtension ext = new ServerCertificateTypeExtension(certificateType);
				extensions.addExtension(ext);
			}
		}
		if (negotiatedCipherSuite.isEccBased()) {
			if (clientHello.getSupportedPointFormatsExtension() != null) {
				// if we chose a ECC cipher suite, the server should send the
				// supported point formats extension in its ServerHello
				extensions.addExtension(SupportedPointFormatsExtension.DEFAULT_POINT_FORMATS_EXTENSION);
			}
		}
	}

	/**
	 * Determines the elliptic curve to use during the EC based DH key exchange.
	 * 
	 * @param clientHello the peer's <em>CLIENT_HELLO</em> message containing
	 *            its preferred elliptic curves
	 * @return a list of common supported curves. Maybe empty, if server and
	 *         client have no curves in common
	 * 
	 * @since 2.3
	 */
	private List<SupportedGroup> getCommonSupportedGroups(ClientHello clientHello) {
		List<SupportedGroup> groups = new ArrayList<>();
		SupportedEllipticCurvesExtension extension = clientHello.getSupportedEllipticCurvesExtension();
		if (extension == null) {
			// according to RFC 4492, section 4 (https://tools.ietf.org/html/rfc4492#section-4)
			// we are free to pick any curve in this case
			groups.addAll(supportedGroups);
		} else {
			for (SupportedGroup group : extension.getSupportedGroups()) {
				// use first group proposed by client contained in list of server's preferred groups
				if (supportedGroups.contains(group)) {
					groups.add(group);
				}
			}
		}
		return groups;
	}

	private ECPointFormat negotiateECPointFormat(ClientHello clientHello) {
		SupportedPointFormatsExtension extension = clientHello.getSupportedPointFormatsExtension();
		if (extension == null) {
			// according to RFC 4492, section 4
			// (https://tools.ietf.org/html/rfc4492#section-4)
			// we are free to pick any format in this case
			return ECPointFormat.UNCOMPRESSED;
		} else if (extension.contains(ECPointFormat.UNCOMPRESSED)) {
			return ECPointFormat.UNCOMPRESSED;
		}
		return null;
	}

	/**
	 * Determines the signature and hash algorithm to use during the EC based
	 * handshake.
	 * 
	 * @param clientHello the peer's <em>CLIENT_HELLO</em> message containing
	 *            its preferred signatures and hash algorithms
	 * @return a list of common signatures and hash algorithms. Maybe empty, if
	 *         server and client have no signature and hash algorithm in common
	 * 
	 * @since 2.3
	 */
	private List<SignatureAndHashAlgorithm> getCommonSignatureAndHashAlgorithms(ClientHello clientHello) {
		SignatureAlgorithmsExtension extension = clientHello.getSupportedSignatureAlgorithms();
		if (extension == null) {
			List<SignatureAndHashAlgorithm> signatures = new ArrayList<>();
			signatures.addAll(supportedSignatureAndHashAlgorithms);
			return signatures;
		} else {
			return SignatureAndHashAlgorithm.getCommonSignatureAlgorithms(
					extension.getSupportedSignatureAndHashAlgorithms(), supportedSignatureAndHashAlgorithms);
		}
	}

	private List<CipherSuite> getCommonCipherSuites(ClientHello clientHello) {
		List<CipherSuite> common = new ArrayList<>();
		for (CipherSuite cipherSuite : clientHello.getCipherSuites()) {
			// NEVER negotiate NULL cipher suite
			if (cipherSuite != CipherSuite.TLS_NULL_WITH_NULL_NULL && supportedCipherSuites.contains(cipherSuite)) {
				common.add(cipherSuite);
			}
		}
		return common;
	}

	private List<CertificateType> getCommonClientCertificateTypes(final ClientHello clientHello) {
		return getCommonCertificateTypes(clientHello.getClientCertificateTypeExtension(),
				supportedClientCertificateTypes);
	}

	private List<CertificateType> getCommonServerCertificateTypes(final ClientHello clientHello) {
		return getCommonCertificateTypes(clientHello.getServerCertificateTypeExtension(),
				supportedServerCertificateTypes);
	}

	/**
	 * Get list of common supported certificate types. If the extension is
	 * available, used it to find a supported certificate type. If the extension
	 * is not available, check, if X_509 is supported.
	 * 
	 * @param certTypeExt certificate type extension. {@code null}, if not
	 *            available.
	 * @param supportedCertificateTypes supported certificate types of peer
	 * @return list of common supported certificate types. Empty, if no common
	 *         certificate type could be found.
	 */
	private static List<CertificateType> getCommonCertificateTypes(CertificateTypeExtension certTypeExt,
			List<CertificateType> supportedCertificateTypes) {
		List<CertificateType> common = new ArrayList<>();
		if (supportedCertificateTypes != null) {
			if (certTypeExt != null) {
				for (CertificateType certType : certTypeExt.getCertificateTypes()) {
					if (supportedCertificateTypes.contains(certType)) {
						common.add(certType);
					}
				}
			} else if (supportedCertificateTypes.contains(CertificateType.X_509)) {
				common.add(CertificateType.X_509);
			}
		}
		return common;
	}

	final CertificateType getNegotiatedClientCertificateType() {
		return selectedCipherSuiteParameters == null ? null
				: selectedCipherSuiteParameters.getSelectedClientCertificateType();
	}

	final CertificateType getNegotiatedServerCertificateType() {
		return selectedCipherSuiteParameters == null ? null
				: selectedCipherSuiteParameters.getSelectedServerCertificateType();
	}

	final SupportedGroup getNegotiatedSupportedGroup() {
		return selectedCipherSuiteParameters == null ? null : selectedCipherSuiteParameters.getSelectedSupportedGroup();
	}

	@Override
	public void destroy() throws DestroyFailedException {
		SecretUtil.destroy(ecdhe);
		ecdhe = null;
	}
}
