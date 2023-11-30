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
import org.eclipse.californium.elements.config.CertificateAuthenticationMode;
import org.eclipse.californium.elements.util.NoPublicAPI;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConfig.DtlsSecureRenegotiation;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.SupportedPointFormatsExtension.ECPointFormat;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuiteParameters;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuiteSelector;
import org.eclipse.californium.scandium.dtls.cipher.DefaultCipherSuiteSelector;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.CertificateKeyAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;
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

	private final Logger LOGGER = LoggerFactory.getLogger(getClass());

	private static final HandshakeState[] CLIENT_HELLO = { new HandshakeState(HandshakeType.CLIENT_HELLO) };

	private static final HandshakeState[] CLIENT_CERTIFICATE = { new HandshakeState(HandshakeType.CERTIFICATE),
			new HandshakeState(HandshakeType.CLIENT_KEY_EXCHANGE), new HandshakeState(HandshakeType.CERTIFICATE_VERIFY),
			new HandshakeState(ContentType.CHANGE_CIPHER_SPEC), new HandshakeState(HandshakeType.FINISHED) };

	private static final HandshakeState[] EMPTY_CLIENT_CERTIFICATE = {
			new HandshakeState(HandshakeType.CLIENT_KEY_EXCHANGE), new HandshakeState(ContentType.CHANGE_CIPHER_SPEC),
			new HandshakeState(HandshakeType.FINISHED) };

	protected static final HandshakeState[] NO_CLIENT_CERTIFICATE = {
			new HandshakeState(HandshakeType.CLIENT_KEY_EXCHANGE), new HandshakeState(ContentType.CHANGE_CIPHER_SPEC),
			new HandshakeState(HandshakeType.FINISHED) };

	private final Logger LOGGER_NEGOTIATION = LoggerFactory.getLogger(LOGGER.getName() + ".negotiation");

	/** Does the server use session id? */
	private final boolean useSessionId;

	/** certificate based client authentication mode */
	private final CertificateAuthenticationMode clientAuthenticationMode;

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
	/**
	 * The supported certificate key types ordered by preference.
	 * 
	 * @since 3.0
	 */
	private final List<CertificateKeyAlgorithm> supportedCertificateKeyAlgorithms;

	/**
	 * Support the deprecated CID extension before version 9 of <a href=
	 * "https://datatracker.ietf.org/doc/draft-ietf-tls-dtls-connection-id/"
	 * target="_blank">Draft dtls-connection-id</a>.
	 * 
	 * @since 3.0
	 */
	private final boolean supportDeprecatedCid;

	private CipherSuiteParameters cipherSuiteParameters;

	/**
	 * Pending client hello while requesting the certificate identity.
	 * 
	 * @since 3.0
	 */
	private ClientHello pendingClientHello;

	/** The client's {@link CertificateVerify}. Optional. */
	private CertificateVerify certificateVerifyMessage;

	private PskPublicInformation preSharedKeyIdentity;

	/**
	 * The helper class to execute the ECDHE key agreement and key generation.
	 * 
	 * @since 2.3
	 */
	private XECDHECryptography ecdhe;

	/**
	 * Creates a handshaker for negotiating a DTLS session with a client
	 * following the full DTLS handshake protocol.
	 * 
	 * @param initialRecordSequenceNo the initial record sequence number (since
	 *            3.0).
	 * @param initialMessageSequenceNo the initial message sequence number to
	 *            expect from the peer (this parameter can be used to initialize
	 *            the <em>receive_next_seq</em> counter to another value than 0,
	 *            e.g. if one or more cookie exchange round-trips have been
	 *            performed with the peer before the handshake starts).
	 * @param recordLayer the object to use for sending flights to the peer.
	 * @param timer scheduled executor for flight retransmission (since 2.4).
	 * @param connection the connection related with the session.
	 * @param config the DTLS configuration.
	 * @throws IllegalArgumentException if the initial record or message
	 *             sequence number is negative
	 * @throws NullPointerException if any of the provided parameter is
	 *             {@code null}
	 */
	@SuppressWarnings("deprecation")
	public ServerHandshaker(long initialRecordSequenceNo, int initialMessageSequenceNo, RecordLayer recordLayer,
			ScheduledExecutorService timer, Connection connection, DtlsConnectorConfig config) {
		super(initialRecordSequenceNo, initialMessageSequenceNo, recordLayer, timer, connection, config);

		this.cipherSuiteSelector = config.getCipherSuiteSelector();
		this.supportedCipherSuites = config.getSupportedCipherSuites();
		this.supportedGroups = config.getSupportedGroups();
		this.secureRenegotiation = config.get(DtlsConfig.DTLS_SECURE_RENEGOTIATION);

		this.clientAuthenticationMode = config.get(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE);
		this.useSessionId = config.get(DtlsConfig.DTLS_SERVER_USE_SESSION_ID);
		this.useHelloVerifyRequest = config.get(DtlsConfig.DTLS_USE_HELLO_VERIFY_REQUEST);
		this.useHelloVerifyRequestForPsk = this.useHelloVerifyRequest && config.get(DtlsConfig.DTLS_USE_HELLO_VERIFY_REQUEST_FOR_PSK);

		// the server handshake uses the config with exchanged roles!
		this.supportedClientCertificateTypes = config.getTrustCertificateTypes();
		this.supportedServerCertificateTypes = config.getIdentityCertificateTypes();
		this.supportedSignatureAndHashAlgorithms = config.getSupportedSignatureAlgorithms();
		this.supportedCertificateKeyAlgorithms = config.getSupportedCertificateKeyAlgorithm();
		this.supportDeprecatedCid = config.get(DtlsConfig.DTLS_SUPPORT_DEPRECATED_CID);
		setExpectedStates(CLIENT_HELLO);
	}

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

	/**
	 * Start initial timeout for internal API calls.
	 * 
	 * Processing the first received flight has no pending timeout for the last
	 * flight. Therefore start an empty dummy flight to schedule a timeout.
	 * 
	 * @since 3.0
	 */
	protected void startInitialTimeout() {
		// Dummy flight for handshake timeout!
		DTLSFlight flight = createFlight();
		flight.setResponseStarted();
		sendFlight(flight);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Checks, if handshake is ready to expect CCS and finish the handshake.
	 */
	@Override
	protected void processMasterSecret() {
		if (isExpectedStates(NO_CLIENT_CERTIFICATE) || (isExpectedStates(EMPTY_CLIENT_CERTIFICATE))
				|| (isExpectedStates(CLIENT_CERTIFICATE) && otherPeersCertificateVerified
						&& certificateVerifyMessage != null)) {
			expectChangeCipherSpecMessage();
		}
	}

	/**
	 * If the server requires mutual authentication, the client must send its
	 * certificate.
	 * 
	 * Calls {@link #processCertificateVerified()} on available verification
	 * result.
	 * 
	 * @param message the client's {@link CertificateMessage}.
	 * @throws HandshakeException if the certificate could not be verified.
	 */
	private void receivedClientCertificate(CertificateMessage message) throws HandshakeException {

		if (message.isEmpty()) {
			if (clientAuthenticationMode == CertificateAuthenticationMode.NEEDED) {
				LOGGER.debug("Client authentication failed: missing certificate!");
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE);
				throw new HandshakeException("Client Certificate required!", alert);
			}
			// message uses a empty certificate chain
			setExpectedStates(EMPTY_CLIENT_CERTIFICATE);
		} else {
			verifyCertificate(message, false);
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Checks, if handshake is ready to expect CCS and finish the handshake.
	 */
	@Override
	protected void processCertificateVerified() {
		if (hasMasterSecret() && certificateVerifyMessage != null) {
			expectChangeCipherSpecMessage();
		}
	}

	/**
	 * Verifies the client's CertificateVerify message signature.
	 * <p>
	 * If verification of signature succeeds, and the certificate chain is
	 * verified as well, the session's <em>peerIdentity</em> property contains a
	 * principal reflecting the client's authenticated identity.
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

		if (setOtherPeersSignatureVerified() && hasMasterSecret()) {
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
	 * @param message the client's {@link Finished} message.
	 * @throws HandshakeException if the client did not send the required
	 *             <em>CLIENT_CERTIFICATE</em> and <em>CERTIFICATE_VERIFY</em>
	 *             messages or if the server's FINISHED message cannot be
	 *             created
	 */
	private void receivedClientFinished(Finished message) throws HandshakeException {

		if (clientAuthenticationMode == CertificateAuthenticationMode.NEEDED
				&& isExpectedStates(EMPTY_CLIENT_CERTIFICATE)) {
			// client sent an empty certificate, but authentication is required.
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
	 * Determines common security parameters and prepares to create the
	 * response. If a certificate based cipher suite is shared, request the
	 * certificate identity and calls {@link #processClientHello(ClientHello)}
	 * on available certificate identity.
	 * 
	 * @param clientHello the client's hello message.
	 * @throws HandshakeException if the server's response message(s) cannot be
	 *             created
	 */
	protected void receivedClientHello(ClientHello clientHello) throws HandshakeException {
		negotiateProtocolVersion(clientHello.getProtocolVersion());

		if (!clientHello.getCompressionMethods().contains(CompressionMethod.NULL)) {
			// abort handshake
			throw new HandshakeException("Client does not support NULL compression method",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE));
		}

		List<CipherSuite> commonCipherSuites = getCommonCipherSuites(clientHello);
		if (commonCipherSuites.isEmpty()) {
			LOGGER.trace("Server cipher suites: {}", supportedCipherSuites);
			// abort handshake
			throw new HandshakeException("Client does not propose a common cipher suite",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE));
		}
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
		List<CertificateType> commonServerCertTypes = getCommonServerCertificateTypes(
				clientHello.getServerCertificateTypeExtension());
		List<CertificateType> commonClientCertTypes = getCommonClientCertificateTypes(
				clientHello.getClientCertificateTypeExtension());
		List<SupportedGroup> commonGroups = getCommonSupportedGroups(clientHello.getSupportedEllipticCurvesExtension());
		List<SignatureAndHashAlgorithm> commonSignatures = getCommonSignatureAndHashAlgorithms(
				clientHello.getSupportedSignatureAlgorithmsExtension());
		ECPointFormat format = negotiateECPointFormat(clientHello.getSupportedPointFormatsExtension());

		ServerNameExtension serverNameExt = clientHello.getServerNameExtension();
		if (serverNameExt != null) {
			if (sniEnabled) {
				// store the names indicated by peer for later reference during
				// key exchange
				DTLSSession session = getSession();
				session.setServerNames(serverNameExt.getServerNames());
				session.setSniSupported(true);
				LOGGER.debug("using server name indication received from peer [{}]", peerToLog);
			} else {
				LOGGER.debug("client [{}] included SNI in HELLO but SNI support is disabled", peerToLog);
			}
		}

		this.cipherSuiteParameters = new CipherSuiteParameters(null, null, clientAuthenticationMode, commonCipherSuites,
				commonServerCertTypes, commonClientCertTypes, commonGroups, commonSignatures, format);
		if (CipherSuite.containsCipherSuiteRequiringCertExchange(commonCipherSuites)) {
			this.pendingClientHello = clientHello;
			ServerNames serverNames = getServerNames();
			List<CertificateKeyAlgorithm> keyAlgorithms = CipherSuite.getCertificateKeyAlgorithms(commonCipherSuites);
			if (requestCertificateIdentity(null, serverNames, keyAlgorithms, commonSignatures, commonGroups)) {
				startInitialTimeout();
			}
		} else {
			processClientHello(clientHello);
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Amend the certificate identity to the security parameter and continue the
	 * processing of the client hello calling
	 * {@link #processClientHello(ClientHello)}.
	 */
	@Override
	protected void processCertificateIdentityAvailable() throws HandshakeException {
		cipherSuiteParameters = new CipherSuiteParameters(publicKey, certificateChain, cipherSuiteParameters);
		ClientHello clientHello = pendingClientHello;
		pendingClientHello = null;
		processClientHello(clientHello);
	}

	/**
	 * Process client hello.
	 * 
	 * @param clientHello the <em>CLIENT_HELLO</em> message.
	 * @throws HandshakeException if the server's response message(s) cannot be
	 *             created
	 */
	protected void processClientHello(ClientHello clientHello) throws HandshakeException {

		negotiateCipherSuite(clientHello);

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

		ProtocolVersion serverVersion = negotiateProtocolVersion(clientHello.getProtocolVersion());

		// store client and server random
		clientRandom = clientHello.getRandom();

		DTLSSession session = getSession();
		boolean useSessionId = this.useSessionId;
		if (extendedMasterSecretMode.is(ExtendedMasterSecretMode.ENABLED) && !clientHello.hasExtendedMasterSecretExtension()) {
			useSessionId = false;
		}
		SessionId sessionId = useSessionId ? new SessionId() : SessionId.emptySessionId();
		session.setSessionIdentifier(sessionId);
		session.setProtocolVersion(serverVersion);
		session.setCompressionMethod(CompressionMethod.NULL);

		ServerHello serverHello = new ServerHello(serverVersion, sessionId, session.getCipherSuite(),
				session.getCompressionMethod());
		addHelloExtensions(clientHello, serverHello);
		if (serverHello.getCipherSuite().isEccBased()) {
			expectEcc();
		}
		wrapMessage(flight, serverHello);
		serverRandom = serverHello.getRandom();
	}

	private void createCertificateMessage(DTLSFlight flight) {

		DTLSSession session = getSession();
		CertificateMessage certificateMessage = null;
		if (session.getCipherSuite().requiresServerCertificateMessage()) {
			CertificateType certificateType = session.sendCertificateType();
			if (CertificateType.RAW_PUBLIC_KEY == certificateType) {
				certificateMessage = new CertificateMessage(cipherSuiteParameters.getPublicKey());
			} else if (CertificateType.X_509 == certificateType) {
				certificateMessage = new CertificateMessage(cipherSuiteParameters.getCertificateChain());
			} else {
				throw new IllegalArgumentException("Certificate type " + certificateType + " not supported!");
			}
			wrapMessage(flight, certificateMessage);
		}
	}

	private void createServerKeyExchange(DTLSFlight flight) throws HandshakeException {

		/*
		 * Third, send ServerKeyExchange (if required by key exchange algorithm)
		 */
		DTLSSession session = getSession();
		KeyExchangeAlgorithm keyExchangeAlgorithm = session.getKeyExchange();

		if (KeyExchangeAlgorithm.ECDHE_PSK == keyExchangeAlgorithm
				|| KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN == keyExchangeAlgorithm) {
			try {
				SupportedGroup ecGroup = cipherSuiteParameters.getSelectedSupportedGroup();
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
			serverKeyExchange = new EcdhSignedServerKeyExchange(session.getSignatureAndHashAlgorithm(), ecdhe,
					privateKey, clientRandom, serverRandom);
			break;

		case PSK:
			/*
			 * If the identity is based on the domain name, servers SHOULD NOT
			 * send an identity hint and clients MUST ignore it. Are there use
			 * cases that different PSKs are used for different actions or time
			 * periods? How to configure the hint then?
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
		CertificateType certificateType = session.receiveCertificateType();
		if (clientAuthenticationMode.useCertificateRequest()
				&& session.getCipherSuite().requiresServerCertificateMessage()
				&& certificateType != null) {
			CertificateRequest certificateRequest = new CertificateRequest();
			List<SignatureAndHashAlgorithm> signatures = supportedSignatureAndHashAlgorithms;
			List<CertificateKeyAlgorithm> keys = supportedCertificateKeyAlgorithms;
			if (CertificateType.X_509 == certificateType) {
				certificateRequest.addSignatureAlgorithms(signatures);
				if (certificateVerifier != null) {
					certificateRequest.addCerticiateAuthorities(certificateVerifier.getAcceptedIssuers());
				}
			} else if (CertificateType.RAW_PUBLIC_KEY == certificateType) {
				CertificateKeyAlgorithm algorithm = CertificateKeyAlgorithm.getAlgorithm(publicKey);
				if (keys.get(0) != algorithm && keys.contains(algorithm)) {
					// move own certificate key algorithm to preferred position 
					keys = new ArrayList<>(keys);
					keys.remove(algorithm);
					keys.add(0, algorithm);
				}
				signatures = SignatureAndHashAlgorithm.getCompatibleSignatureAlgorithms(signatures, keys);
				certificateRequest.addSignatureAlgorithms(signatures);
			}
			LOGGER.trace("Certificate Type: {}", certificateType);
			LOGGER.trace("Signature and hash algorithms {}/{}", signatures, supportedSignatureAndHashAlgorithms);
			LOGGER.trace("Certificate key algorithms {}/{}", keys, supportedCertificateKeyAlgorithms);
			for (CertificateKeyAlgorithm certificateKeyAlgorithm : keys) {
				if (SignatureAndHashAlgorithm.isSupportedAlgorithm(signatures, certificateKeyAlgorithm)) {
					certificateRequest.addCertificateType(certificateKeyAlgorithm);
				}
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
					session.getCipherSuite().getThreadLocalPseudoRandomFunctionMac(), premasterSecret, seed,
					session.useExtendedMasterSecret());
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
	 * Calls {@link #processMasterSecret()} on available credentials.
	 * 
	 * @param message the client's key exchange message.
	 * @throws HandshakeException if an error occurs
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
	 * Calls {@link #processMasterSecret()} on available credentials.
	 * 
	 * @param message the client's key exchange message.
	 * @throws HandshakeException if an error occurs
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
	 * @param clientHello the client hello message with the extensions proposed
	 *            by the client.
	 * @param serverHello the server hello message to add the common supported
	 *            extensions.
	 * @throws HandshakeException if the client extension are in conflict with
	 *             the server
	 * @since 3.0
	 */
	protected void addHelloExtensions(ClientHello clientHello, ServerHello serverHello) throws HandshakeException {

		DTLSSession session = getSession();

		if (clientHello.hasExtendedMasterSecretExtension()) {
			if (extendedMasterSecretMode != ExtendedMasterSecretMode.NONE) {
				session.setExtendedMasterSecret(true);
				serverHello.addExtension(ExtendedMasterSecretExtension.INSTANCE);
			}
		} else if (extendedMasterSecretMode == ExtendedMasterSecretMode.REQUIRED) {
			throw new HandshakeException("Extended Master Secret required!",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE));
		}

		if (clientHello.hasRenegotiationInfo()) {
			if (secureRenegotiation != DtlsSecureRenegotiation.NONE) {
				serverHello.addExtension(RenegotiationInfoExtension.INSTANCE);
				session.setSecureRengotiation(true);
			}
		} else if (secureRenegotiation == DtlsSecureRenegotiation.NEEDED) {
			throw new HandshakeException("Secure renegotiation required!",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE));
		}

		if (session.getCipherSuite().requiresServerCertificateMessage()) {
			if (clientAuthenticationMode.useCertificateRequest()) {
				CertificateType certificateType = session.receiveCertificateType();
				if (certificateType != null) {
					ClientCertificateTypeExtension certificateTypeExtension = clientHello
							.getClientCertificateTypeExtension();
					if (certificateTypeExtension != null && certificateTypeExtension.contains(certificateType)) {
						ClientCertificateTypeExtension ext = new ClientCertificateTypeExtension(certificateType);
						serverHello.addExtension(ext);
					}
				}
			}

			CertificateType certificateType = session.sendCertificateType();
			if (certificateType != null) {
				ServerCertificateTypeExtension certificateTypeExtension = clientHello
						.getServerCertificateTypeExtension();
				if (certificateTypeExtension != null && certificateTypeExtension.contains(certificateType)) {
					ServerCertificateTypeExtension ext = new ServerCertificateTypeExtension(certificateType);
					serverHello.addExtension(ext);
				}
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
		if (serverNameExt != null && sniEnabled) {
			// RFC6066, section 3 requires the server to respond with
			// an empty SNI extension if it might make use of the value(s)
			// provided by the client
			serverHello.addExtension(ServerNameExtension.emptyServerNameIndication());
		}

		if (supportsConnectionId()) {
			ConnectionIdExtension connectionIdExtension = clientHello.getConnectionIdExtension();
			if (connectionIdExtension != null) {
				boolean useDeprecatedCid = connectionIdExtension.useDeprecatedCid();
				if (!useDeprecatedCid || supportDeprecatedCid) {
					ConnectionId connectionId = getReadConnectionId();
					ConnectionIdExtension extension = ConnectionIdExtension.fromConnectionId(connectionId,
							connectionIdExtension.getType());
					serverHello.addExtension(extension);
					DTLSContext context = getDtlsContext();
					context.setWriteConnectionId(connectionIdExtension.getConnectionId());
					context.setReadConnectionId(connectionId);
					context.setDeprecatedCid(useDeprecatedCid);
				}
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
	 * 
	 * @param clientHello the <em>CLIENT_HELLO</em> message.
	 * @throws HandshakeException if this server's configuration does not
	 *             support any of the cipher suites proposed by the client.
	 * @see CipherSuiteSelector
	 * @see DefaultCipherSuiteSelector
	 */
	private void negotiateCipherSuite(ClientHello clientHello) throws HandshakeException {
		LOGGER.trace("Negotiate on: {}", cipherSuiteParameters);
		if (cipherSuiteSelector.select(cipherSuiteParameters)) {
			LOGGER.debug("Negotiated: {}", cipherSuiteParameters);
			DTLSSession session = getSession();
			CipherSuite cipherSuite = cipherSuiteParameters.getSelectedCipherSuite();
			session.setCipherSuite(cipherSuite);
			if (cipherSuite.requiresServerCertificateMessage()) {
				session.setSignatureAndHashAlgorithm(cipherSuiteParameters.getSelectedSignature());
				CertificateType certificateType = cipherSuiteParameters.getSelectedServerCertificateType();
				if (certificateType == null) {
					AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.UNSUPPORTED_CERTIFICATE);
					throw new HandshakeException("No common server certificate type!", alert);
				}
				session.setSendCertificateType(certificateType);
				certificateType = cipherSuiteParameters.getSelectedClientCertificateType();
				if (clientAuthenticationMode == CertificateAuthenticationMode.NEEDED) {
					if (certificateType == null) {
						AlertMessage alert = new AlertMessage(AlertLevel.FATAL,
								AlertDescription.UNSUPPORTED_CERTIFICATE);
						throw new HandshakeException("No common client certificate type!", alert);
					}
					session.setReceiveCertificateType(certificateType);
				} else if (clientAuthenticationMode == CertificateAuthenticationMode.WANTED) {
					if (certificateType != null) {
						session.setReceiveCertificateType(certificateType);
					}
					// if no common certificate type is available,
					// keep x509 but don't send the extension
				}
			}
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
			// if none of the client's proposed cipher suites matches throw
			// exception
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE);
			throw new HandshakeException(summary, alert);
		}
	}

	/**
	 * Determines the elliptic curve to use during the EC based DH key exchange.
	 * 
	 * @param clientCurves the peer's extension containing its preferred
	 *            elliptic curves
	 * @return a list of common supported curves. Maybe empty, if server and
	 *         client have no curves in common
	 * 
	 * @since 3.0 (changed parameter type to SupportedEllipticCurvesExtension)
	 */
	private List<SupportedGroup> getCommonSupportedGroups(SupportedEllipticCurvesExtension clientCurves) {
		List<SupportedGroup> groups = new ArrayList<>();
		if (clientCurves == null) {
			// according to RFC 4492, section 4
			// (https://tools.ietf.org/html/rfc4492#section-4)
			// we are free to pick any curve in this case
			groups.addAll(supportedGroups);
		} else {
			for (SupportedGroup group : clientCurves.getSupportedGroups()) {
				// use first group proposed by client contained in list of
				// server's preferred groups
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
	 * @param clientSignatureAndHashAlgorithms the peer's extension containing
	 *            its preferred signatures and hash algorithms
	 * @return a list of common signatures and hash algorithms. Maybe empty, if
	 *         server and client have no signature and hash algorithm in common
	 * 
	 * @since 3.0 (changed parameter type to SignatureAlgorithmsExtension)
	 */
	private List<SignatureAndHashAlgorithm> getCommonSignatureAndHashAlgorithms(
			SignatureAlgorithmsExtension clientSignatureAndHashAlgorithms) {
		if (clientSignatureAndHashAlgorithms == null) {
			return new ArrayList<>(supportedSignatureAndHashAlgorithms);
		} else {
			return SignatureAndHashAlgorithm.getCommonSignatureAlgorithms(
					clientSignatureAndHashAlgorithms.getSupportedSignatureAndHashAlgorithms(),
					supportedSignatureAndHashAlgorithms);
		}
	}

	private List<CipherSuite> getCommonCipherSuites(ClientHello clientHello) {
		List<CipherSuite> supported = supportedCipherSuites;
		CipherSuite sessionCipherSuite = getSession().getCipherSuite();
		if (sessionCipherSuite.isValidForNegotiation()) {
			// resumption, limit handshake to use the same cipher suite
			supported = Arrays.asList(sessionCipherSuite);
		}
		return CipherSuite.preselectCipherSuites(supported, clientHello.getCipherSuites());
	}

	private List<CertificateType> getCommonClientCertificateTypes(
			ClientCertificateTypeExtension clientCertificateTypes) {
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

	private List<CertificateType> getCommonServerCertificateTypes(
			ServerCertificateTypeExtension serverCertificateTypes) {
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
		if (supportedCertificateTypes != null) {
			if (certTypeExt != null) {
				return certTypeExt.getCommonCertificateTypes(supportedCertificateTypes);
			} else if (supportedCertificateTypes.contains(CertificateType.X_509)) {
				return CertificateTypeExtension.DEFAULT_X509;
			}
		}
		return CertificateTypeExtension.EMPTY;
	}

	final CipherSuiteParameters getNegotiatedCipherSuiteParameters() {
		return cipherSuiteParameters;
	}

	@Override
	public void destroy() throws DestroyFailedException {
		SecretUtil.destroy(ecdhe);
		ecdhe = null;
	}
}
