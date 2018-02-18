/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.scandium.auth.PreSharedKeyIdentity;
import org.eclipse.californium.scandium.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.CertificateTypeExtension.CertificateType;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.util.ByteArrayUtils;
import org.eclipse.californium.scandium.util.ServerNames;

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
	 * The certificate types this server supports for client authentication.
	 */
	protected final List<CertificateType> supportedClientCertificateTypes;
	/**
	 * The certificate types this server supports for server authentication.
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
	protected final ServerNameResolver serverNameResolver;
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
	 * @param sessionListener
	 *            the listener to notify about the session's life-cycle events.
	 * @param config
	 *            the DTLS configuration.
	 * @param maxTransmissionUnit
	 *            the MTU value reported by the network interface the record layer is bound to.
	 * @throws IllegalStateException
	 *            if the message digest required for computing the FINISHED message hash cannot be instantiated.
	 * @throws NullPointerException
	 *            if session, recordLayer or config is <code>null</code>
	 */
	public ClientHandshaker(DTLSSession session, RecordLayer recordLayer, SessionListener sessionListener,
			DtlsConnectorConfig config, int maxTransmissionUnit) {
		super(true, session, recordLayer, sessionListener, config.getTrustStore(), maxTransmissionUnit, 
		        config.getRpkTrustStore());
		this.privateKey = config.getPrivateKey();
		this.certificateChain = config.getCertificateChain();
		this.publicKey = config.getPublicKey();
		this.pskStore = config.getPskStore();
		this.serverNameResolver = config.getServerNameResolver();
		this.preferredCipherSuites = Arrays.asList(config.getSupportedCipherSuites());
		this.maxFragmentLengthCode = config.getMaxFragmentLengthCode();
		this.supportedServerCertificateTypes = new ArrayList<>();
		this.supportedClientCertificateTypes = new ArrayList<>();

		// we only need to include certificate_type extensions in the CLIENT_HELLO
		// if we support a cipher suite that requires a certificate exchange
		if (CipherSuite.containsCipherSuiteRequiringCertExchange(preferredCipherSuites)) {

			// we always support receiving a RawPublicKey from the server
			this.supportedServerCertificateTypes.add(CertificateType.RAW_PUBLIC_KEY);
			if (rootCertificates != null && rootCertificates.length > 0) {
				int index = config.isSendRawKey() ? 1 : 0;
				this.supportedServerCertificateTypes.add(index, CertificateType.X_509);
			}

			if (privateKey != null && publicKey != null) {
				if (certificateChain == null || certificateChain.length == 0) {
					this.supportedClientCertificateTypes.add(CertificateType.RAW_PUBLIC_KEY);
				} else if (config.isSendRawKey()) {
					this.supportedClientCertificateTypes.add(CertificateType.RAW_PUBLIC_KEY);
					this.supportedClientCertificateTypes.add(CertificateType.X_509);
				} else {
					this.supportedClientCertificateTypes.add(CertificateType.X_509);
					this.supportedClientCertificateTypes.add(CertificateType.RAW_PUBLIC_KEY);
				}
			}
		}
	}

	// Methods ////////////////////////////////////////////////////////

	final SignatureAndHashAlgorithm getNegotiatedSignatureAndHashAlgorithm() {
		return negotiatedSignatureAndHashAlgorithm;
	}

	@Override
	protected synchronized void doProcessMessage(DTLSMessage message) throws HandshakeException, GeneralSecurityException {

		// log record now (even if message is still encrypted) in case an Exception
		// is thrown during processing
		if (LOGGER.isDebugEnabled()) {
			StringBuilder msg = new StringBuilder();
			msg.append(String.format(
					"Processing %s message from peer [%s]",
					message.getContentType(), message.getPeer()));
			if (LOGGER.isTraceEnabled()) {
				msg.append(":").append(System.lineSeparator()).append(message);
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
			recordLayer.cancelRetransmissions();
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
					new Object[]{handshakeMsg.getMessageType(), handshakeMsg.getMessageSeq(), handshakeMsg.getPeer()});
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

		message.verifyData(getMasterSecret(), false, handshakeHash);
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
		// update the length (cookie added)
		clientHello.setFragmentLength(clientHello.getMessageLength());

		DTLSFlight flight = new DTLSFlight(getSession());
		flight.addMessage(wrapMessage(clientHello));
		recordLayer.sendFlight(flight);
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
		session.setSendRawPublicKey(CertificateType.RAW_PUBLIC_KEY.equals(serverHello.getClientCertificateType()));
		session.setReceiveRawPublicKey(CertificateType.RAW_PUBLIC_KEY.equals(serverHello.getServerCertificateType()));
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
		DTLSFlight flight = new DTLSFlight(getSession());

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
			String identity = pskStore.getIdentity(getPeerAddress());
			if (identity == null) {
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, session.getPeer());
				throw new HandshakeException("No Identity found for peer: "	+ getPeerAddress(), alert);
			}
			byte[] psk = pskStore.getKey(identity);
			if (psk == null) {
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL,	AlertDescription.HANDSHAKE_FAILURE, session.getPeer());
				throw new HandshakeException("No preshared secret found for identity: " + identity, alert);
			}
			session.setPeerIdentity(new PreSharedKeyIdentity(identity));
			clientKeyExchange = new PSKClientKeyExchange(identity, session.getPeer());
			LOGGER.debug("Using PSK identity: {}", identity);
			premasterSecret = generatePremasterSecretFromPSK(psk);
			generateKeys(premasterSecret);

			break;

		case NULL:
			clientKeyExchange = new NULLClientKeyExchange(session.getPeer());

			// We assume, that the premaster secret is empty
			generateKeys(new byte[] {});
			break;

		default:
			throw new HandshakeException(
					"Unknown key exchange algorithm: " + getKeyExchangeAlgorithm(),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, session.getPeer()));
		}
		flight.addMessage(wrapMessage(clientKeyExchange));

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

			flight.addMessage(wrapMessage(certificateVerify));
		}

		/*
		 * Fourth, send ChangeCipherSpec
		 */
		ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage(session.getPeer());
		flight.addMessage(wrapMessage(changeCipherSpecMessage));
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
		Finished finished = new Finished(getMasterSecret(), isClient, handshakeHash, session.getPeer());
		flight.addMessage(wrapMessage(finished));

		// compute handshake hash with client's finished message also
		// included, used for server's finished message
		mdWithClientFinished.update(finished.toByteArray());
		handshakeHash = mdWithClientFinished.digest();

		recordLayer.sendFlight(flight);
	}

	private void createCertificateMessage(final DTLSFlight flight) throws HandshakeException {

		/*
		 * First, if required by server, send Certificate.
		 */
		if (certificateRequest != null) {

			if (session.sendRawPublicKey()) {
				byte[] rawPublicKeyBytes = new byte[0];
				PublicKey key = determineClientRawPublicKey(certificateRequest);
				if (key != null) {
					rawPublicKeyBytes = key.getEncoded();
				}
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("sending CERTIFICATE message with client RawPublicKey [{}] to server", ByteArrayUtils.toHexString(rawPublicKeyBytes));
				}
				clientCertificate = new CertificateMessage(rawPublicKeyBytes, session.getPeer());
			} else {
				X509Certificate[] clientChain = determineClientCertificateChain(certificateRequest);
				// make sure we only send certs not part of the server's trust anchor
				X509Certificate[] truncatedChain = certificateRequest.removeTrustedCertificates(clientChain);
				LOGGER.debug("sending CERTIFICATE message with client certificate chain [length: {}] to server", truncatedChain.length);
				clientCertificate = new CertificateMessage(truncatedChain, session.getPeer());
			}
			flight.addMessage(wrapMessage(clientCertificate));
		}
	}

	/**
	 * Determines the public key to send to the server based on the constraints conveyed in the server's
	 * <em>CERTIFICATE_REQUEST</em>.
	 * 
	 * @param certRequest The certificate request containing the constraints to match.
	 * @return An appropriate key or {@code null} if this handshaker has not been configured with an appropriate key.
	 * @throws HandshakeException if this handshaker has not been configured with any public key.
	 */
	PublicKey determineClientRawPublicKey(CertificateRequest certRequest) throws HandshakeException {

		if (publicKey == null) {
			throw new HandshakeException("no public key configured",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, getPeerAddress()));
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
	 * @throws HandshakeException if this handshaker has not been configured with any certificate chain.
	 */
	X509Certificate[] determineClientCertificateChain(CertificateRequest certRequest) throws HandshakeException {

		if (certificateChain == null) {
			throw new HandshakeException("no client certificate configured",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, getPeerAddress()));
		} else {
			negotiatedSignatureAndHashAlgorithm = certRequest.getSignatureAndHashAlgorithm(certificateChain);
			if (negotiatedSignatureAndHashAlgorithm == null) {
				return new X509Certificate[0];
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
		if (maxFragmentLengthCode != null) {
			MaxFragmentLengthExtension ext = new MaxFragmentLengthExtension(maxFragmentLengthCode); 
			startMessage.addExtension(ext);
			LOGGER.debug(
					"Indicating max. fragment length [{}] to server [{}]",
					new Object[]{maxFragmentLengthCode, getPeerAddress()});
		}

		addServerNameIndication(startMessage);

		// set current state
		state = startMessage.getMessageType().getCode();

		// store for later calculations
		clientHello = startMessage;
		DTLSFlight flight = new DTLSFlight(session);
		flight.addMessage(wrapMessage(startMessage));

		recordLayer.sendFlight(flight);
	}

	private void addServerNameIndication(final ClientHello helloMessage) {

		if (serverNameResolver != null) {
			indicatedServerNames = serverNameResolver.getServerNames(session.getPeer());
			if (indicatedServerNames != null) {
				helloMessage.addExtension(ServerNameExtension.forServerNames(indicatedServerNames));
			}
		}
	}
}
