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
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;

import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.util.NoPublicAPI;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.CertificateRequest.ClientCertificateType;
import org.eclipse.californium.scandium.dtls.SupportedPointFormatsExtension.ECPointFormat;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuiteParameters;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuiteSelector;
import org.eclipse.californium.scandium.dtls.cipher.DefaultCipherSuiteSelector;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Server handshaker does the protocol handshaking from the point of view of a
 * server. It is message-driven by the parent {@link Handshaker} class. The
 * message flow is depicted in
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
 */
@NoPublicAPI
public class ServerHandshaker extends Handshaker {
	private static final HandshakeState[] CLIENT_HELLO = {
			new HandshakeState(HandshakeType.CLIENT_HELLO) };

	private static final HandshakeState[] CLIENT_CERTIFICATE = {
			new HandshakeState(HandshakeType.CERTIFICATE),
			new HandshakeState(HandshakeType.CLIENT_KEY_EXCHANGE),
			new HandshakeState(HandshakeType.CERTIFICATE_VERIFY),
			new HandshakeState(ContentType.CHANGE_CIPHER_SPEC),
			new HandshakeState(HandshakeType.FINISHED) };

	private static final HandshakeState[] EMPTY_CLIENT_CERTIFICATE = {
			new HandshakeState(HandshakeType.CLIENT_KEY_EXCHANGE),
			new HandshakeState(ContentType.CHANGE_CIPHER_SPEC),
			new HandshakeState(HandshakeType.FINISHED) };

	protected static final HandshakeState[] NO_CLIENT_CERTIFICATE = {
			new HandshakeState(HandshakeType.CLIENT_KEY_EXCHANGE),
			new HandshakeState(ContentType.CHANGE_CIPHER_SPEC),
			new HandshakeState(HandshakeType.FINISHED) };

	// Members ////////////////////////////////////////////////////////
	private final Logger LOGGER_NEGOTIATION = LoggerFactory.getLogger(LOGGER.getName() + ".negotiation");

	/** Does the server use session id? */
	private final boolean useSessionId;

	/** Is the client wanted to authenticate itself? */
	private final boolean clientAuthenticationWanted;

	/** Is the client required to authenticate itself? */
	private final boolean clientAuthenticationRequired;

	/** Is the client's address verified? */
	private final boolean useHelloVerifyRequest;
	/** Is the client's address verified for PSK? */
	private final boolean useHelloVerifyRequestForPsk;

	/**
	 * Cipher suite selector.
	 * 
	 * @since 2.3
	 */
	private final CipherSuiteSelector cipherSuiteSelector;

	/**
	 * The cryptographic options this server supports, e.g. for exchanging keys,
	 * digital signatures etc.
	 */
	private final List<CipherSuite> supportedCipherSuites;

	/**
	 * The supported groups (curves) ordered by preference.
	 * 
	 * @since 2.3
	 */
	private final List<SupportedGroup> supportedGroups;

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

	/** The client's {@link CertificateVerify}. Optional. */
	private CertificateVerify certificateVerifyMessage;

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
	 * @param initialRecordSequenceNo the initial record sequence number (since
	 *            3.0).
	 * @param initialMessageSequenceNo
	 *            the initial message sequence number to expect from the peer
	 *            (this parameter can be used to initialize the <em>receive_next_seq</em>
	 *            counter to another value than 0, e.g. if one or more cookie exchange round-trips
	 *            have been performed with the peer before the handshake starts).
	 * @param recordLayer
	 *            the object to use for sending flights to the peer.
	 * @param timer
	 *            scheduled executor for flight retransmission (since 2.4).
	 * @param connection
	 *            the connection related with the session.
	 * @param config
	 *            the DTLS configuration.
	 * @throws IllegalArgumentException if the initial record or message sequence number
	 *             is negative
	 * @throws NullPointerException if any of the provided parameter is
	 *             {@code null}
	 */
	public ServerHandshaker(long initialRecordSequenceNo, int initialMessageSequenceNo, RecordLayer recordLayer,
			ScheduledExecutorService timer, Connection connection, DtlsConnectorConfig config) {
		super(initialRecordSequenceNo, initialMessageSequenceNo, recordLayer, timer, connection, config);

		this.cipherSuiteSelector = config.getCipherSuiteSelector();
		this.supportedCipherSuites = config.getSupportedCipherSuites();
		this.supportedGroups = config.getSupportedGroups();

		this.clientAuthenticationWanted = config.isClientAuthenticationWanted();
		this.clientAuthenticationRequired = config.isClientAuthenticationRequired();
		this.useSessionId = config.useServerSessionId();
		this.useHelloVerifyRequest = config.useHelloVerifyRequest();
		this.useHelloVerifyRequestForPsk = this.useHelloVerifyRequest && config.useHelloVerifyRequestForPsk();

		// the server handshake uses the config with exchanged roles!
		this.supportedClientCertificateTypes = config.getTrustCertificateTypes();
		this.supportedServerCertificateTypes = config.getIdentityCertificateTypes();
		this.supportedSignatureAndHashAlgorithms = config.getSupportedSignatureAlgorithms();
		setExpectedStates(CLIENT_HELLO);
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	protected boolean isClient() {
		return false;
	}

	public PskPublicInformation getPreSharedKeyIdentity() {
		return preSharedKeyIdentity;
	}

	@Override
	protected void doProcessMessage(HandshakeMessage message) throws HandshakeException {

		switch (message.getMessageType()) {
		case CLIENT_HELLO:
			handshakeStarted();
			receivedClientHello((ClientHello) message);
			break;

		case CERTIFICATE:
			receivedClientCertificate((CertificateMessage) message);
			break;

		case CLIENT_KEY_EXCHANGE:
			switch (getSession().getKeyExchange()) {
			case PSK:
				receivedClientKeyExchange((PSKClientKeyExchange) message);
				break;

			case ECDHE_PSK:
				receivedClientKeyExchange((EcdhPskClientKeyExchange) message);
				break;

			case EC_DIFFIE_HELLMAN:
				SecretKey masterSecret = receivedClientKeyExchange((ECDHClientKeyExchange) message);
				applyMasterSecret(masterSecret);
				SecretUtil.destroy(masterSecret);
				processMasterSecret();
				break;

			default:
				// already checked in HandshakeMessage.readServerKeyExchange
				break;
			}
			break;

		case CERTIFICATE_VERIFY:
			receivedCertificateVerify((CertificateVerify) message);
			if (hasMasterSecret() && otherPeersCertificateVerified) {
				expectChangeCipherSpecMessage();
			}
			break;

		case FINISHED:
			receivedClientFinished((Finished) message);
			break;

		default:
			throw new HandshakeException(
					String.format("Received unexpected %s message from peer %s", message.getMessageType(), peerToLog),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE));
		}
	}

	@Override
	protected void processMasterSecret() {
		if (isExpectedStates(NO_CLIENT_CERTIFICATE) ||
			(isExpectedStates(EMPTY_CLIENT_CERTIFICATE)) ||
			(isExpectedStates(CLIENT_CERTIFICATE) && otherPeersCertificateVerified && certificateVerifyMessage != null)) {
			expectChangeCipherSpecMessage();
		}
	}

	@Override
	protected void processCertificateVerified() {
		if (hasMasterSecret() && certificateVerifyMessage != null) {
			expectChangeCipherSpecMessage();
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
	private void receivedClientCertificate(CertificateMessage message) throws HandshakeException {

		if (message.isEmpty()) {
			if (clientAuthenticationRequired) {
				LOGGER.debug("Client authentication failed: missing certificate!");
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
				throw new HandshakeException("Client Certificate required!", alert);
			}
			// message uses a empty certificate chain 
			setExpectedStates(EMPTY_CLIENT_CERTIFICATE);
		} else {
			verifyCertificate(message);
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
		certificateVerifyMessage = message;
		// remove last message - CertificateVerify itself
		handshakeMessages.remove(handshakeMessages.size() - 1);
		message.verifySignature(otherPeersPublicKey, handshakeMessages);
		// add CertificateVerify again
		handshakeMessages.add(message);

		setOtherPeersSignatureVerified();
		if (otherPeersCertificateVerified) {
			expectChangeCipherSpecMessage();
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
		if (clientAuthenticationRequired && isExpectedStates(EMPTY_CLIENT_CERTIFICATE)) {
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
			throw new HandshakeException("Client did not send required authentication messages.", alert);
		}

		flightNumber += 2;
		DTLSFlight flight = createFlight();

		// create handshake hash
		MessageDigest md = getHandshakeMessageDigest();
		MessageDigest mdWithClientFinished = cloneMessageDigest(md);

		// Verify client's data
		verifyFinished(message, md.digest());
		/*
		 * First, send ChangeCipherSpec
		 */
		ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage();
		wrapMessage(flight, changeCipherSpecMessage);
		setCurrentWriteState();

		/*
		 * Second, send Finished message
		 */
		mdWithClientFinished.update(message.toByteArray());
		Finished finished = createFinishedMessage(mdWithClientFinished.digest());
		wrapMessage(flight, finished);
		sendLastFlight(flight);
		contextEstablished();
	}

	/**
	 * Called after the server receives a {@link ClientHello} handshake message.
	 * 
	 * Determines common security parameters and prepares to create the response.
	 * 
	 * @param clientHello
	 *            the client's hello message.
	 * @throws HandshakeException if the server's response message(s) cannot be created
	 */
	protected void receivedClientHello(ClientHello clientHello) throws HandshakeException {
		negotiateProtocolVersion(clientHello.getClientVersion());

		if (!clientHello.getCompressionMethods().contains(CompressionMethod.NULL)) {
			// abort handshake
			throw new HandshakeException(
					"Client does not support NULL compression method",
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.HANDSHAKE_FAILURE));
		}

		List<CipherSuite> commonCipherSuites = getCommonCipherSuites(clientHello);
		if (useHelloVerifyRequest && !useHelloVerifyRequestForPsk && !clientHello.hasCookie()) {
			SessionId sessionId = getSession().getSessionIdentifier();
			if (sessionId.isEmpty() || !sessionId.equals(clientHello.getSessionId())) {
				// no cookie, no resumption => only PSK to reduce amplification
				List<CipherSuite> common = new ArrayList<>();
				for (CipherSuite cipherSuite : commonCipherSuites) {
					if (cipherSuite.isPskBased()) {
						common.add(cipherSuite);
					}
				}
				commonCipherSuites = common;
			}
		}
		List<CertificateType> commonServerCertTypes = getCommonServerCertificateTypes(clientHello.getServerCertificateTypeExtension());
		List<CertificateType> commonClientCertTypes = getCommonClientCertificateTypes(clientHello.getClientCertificateTypeExtension());
		List<SupportedGroup> commonGroups = getCommonSupportedGroups(clientHello.getSupportedEllipticCurvesExtension());
		List<SignatureAndHashAlgorithm> commonSignatures = getCommonSignatureAndHashAlgorithms(clientHello.getSupportedSignatureAlgorithms());
		ECPointFormat format = negotiateECPointFormat(clientHello.getSupportedPointFormatsExtension());

		CipherSuiteParameters cipherSuiteParameters = new CipherSuiteParameters(
				publicKey, certificateChain, clientAuthenticationRequired, clientAuthenticationWanted,
				commonCipherSuites, commonServerCertTypes, commonClientCertTypes,
				commonGroups, commonSignatures, format);

		negotiateCipherSuite(clientHello, cipherSuiteParameters);

		flightNumber = clientHello.hasCookie() ? 4 : 2;

		DTLSFlight flight = createFlight();

		createServerHello(clientHello, flight);

		createCertificateMessage(flight);

		createServerKeyExchange(flight);

		boolean clientCertificate = createCertificateRequest(flight);

		setExpectedStates(clientCertificate ? CLIENT_CERTIFICATE : NO_CLIENT_CERTIFICATE);

		/*
		 * Last, send ServerHelloDone (mandatory)
		 */
		ServerHelloDone serverHelloDone = new ServerHelloDone();
		wrapMessage(flight, serverHelloDone);
		sendFlight(flight);
	}

	private void createServerHello(ClientHello clientHello, DTLSFlight flight) throws HandshakeException {

		ProtocolVersion serverVersion = negotiateProtocolVersion(clientHello.getClientVersion());

		// store client and server random
		clientRandom = clientHello.getRandom();
		serverRandom = new Random();

		DTLSSession session = getSession();
		boolean useSessionId = this.useSessionId;
		if (extendedMasterSecretMode.is(ExtendedMasterSecretMode.ENABLED) && !clientHello.hasExtendedMasterSecret()) {
			useSessionId = false;
		}
		SessionId sessionId = useSessionId ? new SessionId() : SessionId.emptySessionId();
		session.setSessionIdentifier(sessionId);
		session.setProtocolVersion(serverVersion);
		session.setCompressionMethod(CompressionMethod.NULL);

		ServerHello serverHello = new ServerHello(serverVersion, serverRandom, sessionId,
				session.getCipherSuite(), session.getCompressionMethod());
		addHelloExtensions(clientHello, serverHello);
		if (serverHello.getCipherSuite().isEccBased()) {
			expectEcc();
		}
		wrapMessage(flight, serverHello);
	}

	private void createCertificateMessage(DTLSFlight flight) {

		DTLSSession session = getSession();
		CertificateMessage certificateMessage = null;
		if (session.getCipherSuite().requiresServerCertificateMessage()) {
			if (CertificateType.RAW_PUBLIC_KEY == session.sendCertificateType()) {
				certificateMessage = new CertificateMessage(selectedCipherSuiteParameters.getPublicKey());
			} else if (CertificateType.X_509 == session.sendCertificateType()) {
				certificateMessage = new CertificateMessage(selectedCipherSuiteParameters.getCertificateChain());
			} else {
				throw new IllegalArgumentException("Certificate type " + session.sendCertificateType() + " not supported!");
			}
			wrapMessage(flight, certificateMessage);
		}
	}

	private void createServerKeyExchange(DTLSFlight flight) throws HandshakeException {

		/*
		 * Third, send ServerKeyExchange (if required by key exchange
		 * algorithm)
		 */
		DTLSSession session = getSession();
		KeyExchangeAlgorithm keyExchangeAlgorithm = session.getKeyExchange();

		if (KeyExchangeAlgorithm.ECDHE_PSK == keyExchangeAlgorithm
				|| KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN == keyExchangeAlgorithm) {
			try {
				SupportedGroup ecGroup = selectedCipherSuiteParameters.getSelectedSupportedGroup();
				ecdhe = new XECDHECryptography(ecGroup);
				session.setEcGroup(ecGroup);
			} catch (GeneralSecurityException ex) {
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER);
				throw new HandshakeException("Cannot process handshake message, caused by " + ex.getMessage(), alert,
						ex);
			}
		}

		ServerKeyExchange serverKeyExchange = null;
		switch (keyExchangeAlgorithm) {
		case EC_DIFFIE_HELLMAN:
			serverKeyExchange = new EcdhEcdsaServerKeyExchange(session.getSignatureAndHashAlgorithm(), ecdhe, privateKey, clientRandom, serverRandom);
			break;

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
			serverKeyExchange = new EcdhPskServerKeyExchange(PskPublicInformation.EMPTY, ecdhe);
			break;

		default:
			// NULL does not require the server's key exchange message
			break;
		}

		if (serverKeyExchange != null) {
			wrapMessage(flight, serverKeyExchange);
		}
	}

	private boolean createCertificateRequest(DTLSFlight flight) {
		DTLSSession session = getSession();
		if ((clientAuthenticationWanted || clientAuthenticationRequired)
				&& session.getCipherSuite().requiresServerCertificateMessage()
				&& session.receiveCertificateType() != null) {
			CertificateRequest certificateRequest = new CertificateRequest();
			certificateRequest.addCertificateType(ClientCertificateType.ECDSA_SIGN);
			if (session.receiveCertificateType() == CertificateType.X_509) {
				certificateRequest.addSignatureAlgorithms(supportedSignatureAndHashAlgorithms);
				if (certificateVerifier != null) {
					certificateRequest.addCerticiateAuthorities(certificateVerifier.getAcceptedIssuers());
				}
			} else if (session.receiveCertificateType() == CertificateType.RAW_PUBLIC_KEY) {
				List<SignatureAndHashAlgorithm> ecdsaSignatures = SignatureAndHashAlgorithm
						.getEcdsaCompatibleSignatureAlgorithms(supportedSignatureAndHashAlgorithms);
				certificateRequest.addSignatureAlgorithms(ecdsaSignatures);
			}
			wrapMessage(flight, certificateRequest);
			return true;
		}
		return false;
	}

	/**
	 * Generates the master secret by taking the client's public ecdhe key and
	 * running the ECDHE key agreement.
	 * 
	 * @param message the client's key exchange message.
	 * @return the master secret.
	 * @throws HandshakeException if the ECDHE key agreement fails 
	 */
	private SecretKey receivedClientKeyExchange(ECDHClientKeyExchange message) throws HandshakeException {
		try {
			DTLSSession session = getSession();
			SecretKey premasterSecret = ecdhe.generateSecret(message.getEncodedPoint());
			byte[] seed = generateMasterSecretSeed();
			SecretKey masterSecret = PseudoRandomFunction.generateMasterSecret(
					session.getCipherSuite().getThreadLocalPseudoRandomFunctionMac(), premasterSecret,
					seed, session.useExtendedMasterSecret());
			SecretUtil.destroy(premasterSecret);
			return masterSecret;
		} catch (GeneralSecurityException ex) {
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER);
			throw new HandshakeException("Cannot process handshake message, caused by " + ex.getMessage(), alert, ex);
		}
	}

	/**
	 * Retrieves the preshared key from the identity hint and then generates the
	 * master secret.
	 * 
	 * @param message
	 *            the client's key exchange message.
	 * @throws HandshakeException  if an error occurs
	 */
	private void receivedClientKeyExchange(PSKClientKeyExchange message) throws HandshakeException {
		// use the client's PSK identity to look up the pre-shared key
		preSharedKeyIdentity = message.getIdentity();
		byte[] seed = generateMasterSecretSeed();
		requestPskSecretResult(preSharedKeyIdentity, null, seed);
	}

	/**
	 * Retrieves the preshared key from the identity hint and then generates the
	 * master secret using also the result of the ECDHE key exchange.
	 * 
	 * @param message
	 *            the client's key exchange message.
	 * @throws HandshakeException  if an error occurs
	 */
	private void receivedClientKeyExchange(EcdhPskClientKeyExchange message) throws HandshakeException {
		SecretKey otherSecret = null;
		try {
			// use the client's PSK identity to look up the pre-shared key
			preSharedKeyIdentity = message.getIdentity();
			otherSecret = ecdhe.generateSecret(message.getEncodedPoint());
			byte[] seed = generateMasterSecretSeed();
			requestPskSecretResult(preSharedKeyIdentity, otherSecret, seed);
		} catch (GeneralSecurityException ex) {
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER);
			throw new HandshakeException("Cannot process handshake message, caused by " + ex.getMessage(), alert, ex);
		} finally {
			SecretUtil.destroy(otherSecret);
		}
	}

	/**
	 * Add server's hello extensions.
	 * 
	 * @param serverHello server hello message
	 * @throws HandshakeException if the client extension are in conflict with
	 *             the server
	 * @since 3.0
	 */
	protected void addHelloExtensions(ClientHello clientHello, ServerHello serverHello) throws HandshakeException {

		DTLSSession session = getSession();

		if (clientHello.hasExtendedMasterSecret()) {
			if (extendedMasterSecretMode != ExtendedMasterSecretMode.NONE) {
				session.setExtendedMasterSecret(true);
				serverHello.addExtension(ExtendedMasterSecretExtension.INSTANCE);
			}
		} else if (extendedMasterSecretMode == ExtendedMasterSecretMode.REQUIRED) {
			throw new HandshakeException("Extended Master Secret required!",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE));
		}

		CertificateType certificateType = session.receiveCertificateType();
		if (certificateType != null) {
			if (clientHello.getClientCertificateTypeExtension() != null) {
				ClientCertificateTypeExtension ext = new ClientCertificateTypeExtension(certificateType);
				serverHello.addExtension(ext);
			}
		}

		certificateType = session.sendCertificateType();
		if (certificateType != null) {
			if (clientHello.getServerCertificateTypeExtension() != null) {
				ServerCertificateTypeExtension ext = new ServerCertificateTypeExtension(certificateType);
				serverHello.addExtension(ext);
			}
		}

		if (session.getCipherSuite().isEccBased()) {
			if (clientHello.getSupportedPointFormatsExtension() != null) {
				// if we chose a ECC cipher suite, the server should send the
				// supported point formats extension in its ServerHello
				serverHello.addExtension(SupportedPointFormatsExtension.DEFAULT_POINT_FORMATS_EXTENSION);
			}
		}

		RecordSizeLimitExtension recordSizeLimitExt = clientHello.getRecordSizeLimitExtension();
		if (recordSizeLimitExt != null) {
			session.setRecordSizeLimit(recordSizeLimitExt.getRecordSizeLimit());
			int limit = this.recordSizeLimit == null ? session.getMaxFragmentLength() : this.recordSizeLimit;
			serverHello.addExtension(new RecordSizeLimitExtension(limit));
			LOGGER.debug("Received record size limit [{} bytes] from peer [{}]", limit, peerToLog);
		}

		if (recordSizeLimitExt == null) {
			MaxFragmentLengthExtension maxFragmentLengthExt = clientHello.getMaxFragmentLengthExtension();
			if (maxFragmentLengthExt != null) {
				session.setMaxFragmentLength(maxFragmentLengthExt.getFragmentLength().length());
				serverHello.addExtension(maxFragmentLengthExt);
				LOGGER.debug("Negotiated max. fragment length [{} bytes] with peer [{}]",
						maxFragmentLengthExt.getFragmentLength().length(), peerToLog);
			}
		}

		ServerNameExtension serverNameExt = clientHello.getServerNameExtension();
		if (serverNameExt != null) {
			if (sniEnabled) {
				// store the names indicated by peer for later reference during
				// key exchange
				session.setServerNames(serverNameExt.getServerNames());
				// RFC6066, section 3 requires the server to respond with
				// an empty SNI extension if it might make use of the value(s)
				// provided by the client
				serverHello.addExtension(ServerNameExtension.emptyServerNameIndication());
				session.setSniSupported(true);
				LOGGER.debug("using server name indication received from peer [{}]", peerToLog);
			} else {
				LOGGER.debug("client [{}] included SNI in HELLO but SNI support is disabled", peerToLog);
			}
		}

		if (supportsConnectionId()) {
			ConnectionIdExtension connectionIdExtension = clientHello.getConnectionIdExtension();
			if (connectionIdExtension != null) {
				DTLSContext context = getDtlsContext(); 
				context.setWriteConnectionId(connectionIdExtension.getConnectionId());
				final ConnectionId connectionId = getReadConnectionId();
				context.setReadConnectionId(connectionId);
				ConnectionIdExtension extension = ConnectionIdExtension.fromConnectionId(connectionId);
				serverHello.addExtension(extension);
			}
		}
	}

	/**
	 * Negotiates the version to be used. It will return the lower of that
	 * suggested by the client in the client hello and the highest supported by
	 * the server.
	 * 
	 * @param clientVersion the suggested version by the client.
	 * @return the version to be used in the handshake.
	 * @throws HandshakeException if the client's version is smaller than DTLS
	 *             1.2
	 */
	private ProtocolVersion negotiateProtocolVersion(ProtocolVersion clientVersion) throws HandshakeException {
		if (clientVersion.compareTo(ProtocolVersion.VERSION_DTLS_1_2) >= 0) {
			return ProtocolVersion.VERSION_DTLS_1_2;
		} else {
			ProtocolVersion version = clientVersion;
			if (version.compareTo(ProtocolVersion.VERSION_DTLS_1_0) < 0) {
				version = ProtocolVersion.VERSION_DTLS_1_0;
			}
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.PROTOCOL_VERSION, version);
			throw new HandshakeException("The server only supports DTLS v1.2, not " + clientVersion + "!", alert);
		}
	}

	/**
	 * Selects one of the client's proposed cipher suites.
	 * <p>
	 * Delegates the selection calling
	 * {@link CipherSuiteSelector#select(CipherSuiteParameters)}.
	 * <p>
	 * @param clientHello the <em>CLIENT_HELLO</em> message.
	 * @param cipherSuiteParameters cipher suite parameters
	 * @throws HandshakeException if this server's configuration does not
	 *             support any of the cipher suites proposed by the client.
	 * @see CipherSuiteSelector
	 * @see DefaultCipherSuiteSelector
	 */
	protected void negotiateCipherSuite(ClientHello clientHello, CipherSuiteParameters cipherSuiteParameters) throws HandshakeException {

		if (cipherSuiteSelector.select(cipherSuiteParameters)) {
			DTLSSession session = getSession();
			CipherSuite cipherSuite = cipherSuiteParameters.getSelectedCipherSuite();
			session.setCipherSuite(cipherSuite);
			if (cipherSuite.requiresServerCertificateMessage()) {
				session.setSignatureAndHashAlgorithm(cipherSuiteParameters.getSelectedSignature());
				session.setSendCertificateType(cipherSuiteParameters.getSelectedServerCertificateType());
				CertificateType certificateType = cipherSuiteParameters.getSelectedClientCertificateType();
				if (clientAuthenticationRequired || (clientAuthenticationWanted && certificateType != null)) {
					session.setReceiveCertificateType(certificateType);
				}
			}
			selectedCipherSuiteParameters = cipherSuiteParameters;
			LOGGER.debug("Negotiated cipher suite [{}] with peer [{}]", cipherSuite.name(), peerToLog);
		} else {
			if (LOGGER_NEGOTIATION.isDebugEnabled()) {
				LOGGER_NEGOTIATION.debug("{}", clientHello);
				LOGGER_NEGOTIATION.debug("{}", cipherSuiteParameters.getMismatchDescription());
				LOGGER_NEGOTIATION.trace("Parameters: {}", cipherSuiteParameters);
			}
			String summary = cipherSuiteParameters.getMismatchSummary();
			if (summary == null) {
				summary = "Client proposed unsupported cipher suites or parameters only";
			}
			cipherSuiteParameters = null;
			// if none of the client's proposed cipher suites matches throw exception
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE);
			throw new HandshakeException(summary, alert);
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
	private List<SupportedGroup> getCommonSupportedGroups(SupportedEllipticCurvesExtension clientCurves) {
		List<SupportedGroup> groups = new ArrayList<>();
		if (clientCurves == null) {
			// according to RFC 4492, section 4 (https://tools.ietf.org/html/rfc4492#section-4)
			// we are free to pick any curve in this case
			groups.addAll(supportedGroups);
		} else {
			for (SupportedGroup group : clientCurves.getSupportedGroups()) {
				// use first group proposed by client contained in list of server's preferred groups
				if (supportedGroups.contains(group)) {
					groups.add(group);
				}
			}
		}
		return groups;
	}

	private ECPointFormat negotiateECPointFormat(SupportedPointFormatsExtension clientPointFormats) {
		if (clientPointFormats == null) {
			// according to RFC 4492, section 4
			// (https://tools.ietf.org/html/rfc4492#section-4)
			// we are free to pick any format in this case
			return ECPointFormat.UNCOMPRESSED;
		} else if (clientPointFormats.contains(ECPointFormat.UNCOMPRESSED)) {
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
	private List<SignatureAndHashAlgorithm> getCommonSignatureAndHashAlgorithms(SignatureAlgorithmsExtension clientSignatureAndHashAlgorithms) {
		if (clientSignatureAndHashAlgorithms == null) {
			return new ArrayList<>(supportedSignatureAndHashAlgorithms);
		} else {
			return SignatureAndHashAlgorithm.getCommonSignatureAlgorithms(
					clientSignatureAndHashAlgorithms.getSupportedSignatureAndHashAlgorithms(), supportedSignatureAndHashAlgorithms);
		}
	}

	private List<CipherSuite> getCommonCipherSuites(ClientHello clientHello) {
		List<CipherSuite> supported = supportedCipherSuites;
		CipherSuite sessionCipherSuite = getSession().getCipherSuite();
		if (!sessionCipherSuite.equals(CipherSuite.TLS_NULL_WITH_NULL_NULL)) {
			// resumption, limit handshake to use the same cipher suite
			supported = Arrays.asList(sessionCipherSuite);
		}
		return clientHello.getCommonCipherSuites(supported);
	}

	private List<CertificateType> getCommonClientCertificateTypes(ClientCertificateTypeExtension clientCertificateTypes) {
		List<CertificateType> supported = supportedClientCertificateTypes;
		Principal principal = getSession().getPeerIdentity();
		if (principal != null) {
			// resumption, reconstruct the certificate type
			// including into SessionTicket requires a major release
			supported = new ArrayList<CertificateType>();
			if (principal instanceof RawPublicKeyIdentity) {
				supported.add(CertificateType.RAW_PUBLIC_KEY);
			} else if (principal instanceof X509CertPath) {
				supported.add(CertificateType.X_509);
			}
		}
		return getCommonCertificateTypes(clientCertificateTypes, supported);
	}

	private List<CertificateType> getCommonServerCertificateTypes(ServerCertificateTypeExtension serverCertificateTypes) {
		return getCommonCertificateTypes(serverCertificateTypes, supportedServerCertificateTypes);
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
			final List<CertificateType> supportedCertificateTypes) {
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

	final CipherSuiteParameters getNegotiatedCipherSuiteParameters() {
		return selectedCipherSuiteParameters;
	}

	@Override
	public void destroy() throws DestroyFailedException {
		SecretUtil.destroy(ecdhe);
		ecdhe = null;
	}
}
