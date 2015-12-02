/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.scandium.auth.PreSharedKeyIdentity;
import org.eclipse.californium.scandium.auth.RawPublicKeyIdentity;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.CertificateTypeExtension.CertificateType;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.util.ByteArrayUtils;

/**
 * ClientHandshaker does the protocol handshaking from the point of view of a
 * client. It is driven by handshake messages as delivered by the parent
 * {@link Handshaker} class.
 */
public class ClientHandshaker extends Handshaker {

	private static final Logger LOGGER = Logger.getLogger(ClientHandshaker.class.getName());
	
	// Members ////////////////////////////////////////////////////////

	private ProtocolVersion maxProtocolVersion = new ProtocolVersion();

	
	/** The server's public key from its certificate */
	private PublicKey serverPublicKey;
	
	/** The server's X.509 certificate */
	private X509Certificate peerCertificate;

	/** The server's ephemeral public key, used for key agreement */
	private ECPublicKey ephemeralServerPublicKey;

	/** The client's hello handshake message. Store it, to add the cookie in the second flight. */
	protected ClientHello clientHello = null;

	/** the preferred cipher suites ordered by preference */
	private final CipherSuite[] preferredCipherSuites;

	/** The raw message that triggered the start of the handshake
	 * and needs to be sent once the session is established.
	 * */
	protected final RawData message;

	protected Integer maxFragmentLengthCode;

	/**
	 * The certificate types this server supports for client authentication.
	 */
	protected List<CertificateType> supportedClientCertificateTypes;
	/**
	 * The certificate types this server supports for server authentication.
	 */
	protected List<CertificateType> supportedServerCertificateTypes;

	/*
	 * Store all the message which can possibly be sent by the server. We need
	 * these to compute the handshake hash.
	 */
	/** The server's {@link ServerHello}. Mandatory. */
	protected ServerHello serverHello;
	/** The server's {@link CertificateMessage}. Optional. */
	protected CertificateMessage serverCertificate = null;
	/** The server's {@link CertificateRequest}. Optional. */
	protected CertificateRequest certificateRequest = null;
	/** The server's {@link ServerKeyExchange}. Optional. */
	protected ServerKeyExchange serverKeyExchange = null;
	/** The server's {@link ServerHelloDone}. Mandatory. */
	protected ServerHelloDone serverHelloDone;

	/** The hash of all received handshake messages sent in the finished message. */
	protected byte[] handshakeHash = null;

	/** Used to retrieve identity/pre-shared-key for a given destination */
	protected final PskStore pskStore;

	
	
	// Constructors ///////////////////////////////////////////////////

	/**
	 * Creates a new handshaker for negotiating a DTLS session with a server.
	 * 
	 * @param message
	 *            the first application data message to be sent after the handshake is finished 
	 * @param session
	 *            the session to negotiate with the server
	 * @param sessionListener
	 *            the listener to notify about the session's life-cycle events
	 * @param config
	 *            the DTLS configuration
	 * @param maxTransmissionUnit
	 *            the MTU value reported by the network interface the record layer is bound to
	 * @throws IllegalStateException if the message digest required for computing
	 *            the FINISHED message hash cannot be instantiated
	 * @throws NullPointerException if <code>session</code> or <code>config</code> is <code>null</code>
	 */
	public ClientHandshaker(RawData message, DTLSSession session, SessionListener sessionListener, DtlsConnectorConfig config,
			int maxTransmissionUnit) {
		super(true, session, sessionListener, config.getTrustStore(), maxTransmissionUnit);
		this.message = message;
		this.privateKey = config.getPrivateKey();
		this.certificateChain = config.getCertificateChain();
		this.publicKey = config.getPublicKey();
		this.pskStore = config.getPskStore();
		this.preferredCipherSuites = config.getSupportedCipherSuites();
		this.maxFragmentLengthCode = config.getMaxFragmentLengthCode();
		this.supportedServerCertificateTypes = new ArrayList<>();
		if (rootCertificates != null && rootCertificates.length > 0) {
			this.supportedServerCertificateTypes.add(CertificateType.X_509);
		}
		this.supportedServerCertificateTypes.add(CertificateType.RAW_PUBLIC_KEY);

		this.supportedClientCertificateTypes = new ArrayList<>();
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

	// Methods ////////////////////////////////////////////////////////
	

	@Override
	protected synchronized DTLSFlight doProcessMessage(DTLSMessage message) throws HandshakeException, GeneralSecurityException {
		DTLSFlight flight = null;

		// log record now (even if message is still encrypted) in case an Exception
		// is thrown during processing
		if (LOGGER.isLoggable(Level.FINE)) {
			StringBuilder msg = new StringBuilder();
			msg.append(String.format(
					"Processing %s message from peer [%s]",
					message.getContentType(), message.getPeer()));
			if (LOGGER.isLoggable(Level.FINEST)) {
				msg.append(":\n").append(message);
			}
			LOGGER.fine(msg.toString());
		}
		
		switch (message.getContentType()) {
		case ALERT:
			break;

		case CHANGE_CIPHER_SPEC:
			// TODO check, if all expected messages already received
			setCurrentReadState();
			LOGGER.log(Level.FINE, "Processed {1} message from peer [{0}]",
					new Object[]{message.getPeer(), message.getContentType()});
			break;

		case HANDSHAKE:
			HandshakeMessage handshakeMsg = (HandshakeMessage) message;

			switch (handshakeMsg.getMessageType()) {
			case HELLO_REQUEST:
				flight = receivedHelloRequest();
				break;

			case HELLO_VERIFY_REQUEST:
				flight = receivedHelloVerifyRequest((HelloVerifyRequest) handshakeMsg);
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
				flight = receivedServerHelloDone((ServerHelloDone) handshakeMsg);
				break;

			case FINISHED:
				flight = receivedServerFinished((Finished) handshakeMsg);
				break;

			default:
				throw new HandshakeException(
						String.format("Received unexpected handshake message [%s] from peer %s", handshakeMsg.getMessageType(), handshakeMsg.getPeer()),
						new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE, handshakeMsg.getPeer()));
			}

			incrementNextReceiveSeq();
			LOGGER.log(Level.FINE, "Processed {1} message with sequence no [{2}] from peer [{0}]",
					new Object[]{handshakeMsg.getPeer(), handshakeMsg.getMessageType(), handshakeMsg.getMessageSeq()});
			break;

		default:
			throw new HandshakeException(
					String.format("Received unexpected message [%s] from peer %s", message.getContentType(), message.getPeer()),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, message.getPeer()));
		}

		return flight;
	}

	/**
	 * Called when the client received the server's finished message. If the
	 * data can be verified, encrypted application data can be sent.
	 * 
	 * @param message
	 *            the {@link Finished} message.
	 * @return the list
	 * @throws HandshakeException
	 * @throws GeneralSecurityException if the APPLICATION record cannot be created 
	 */
	private DTLSFlight receivedServerFinished(Finished message) throws HandshakeException, GeneralSecurityException {
		DTLSFlight flight = new DTLSFlight(getSession());

		message.verifyData(getMasterSecret(), false, handshakeHash);

		state = HandshakeType.FINISHED.getCode();
		sessionEstablished();
		handshakeCompleted();
		// received server's Finished message, now able to send encrypted
		// message
		ApplicationMessage applicationMessage = new ApplicationMessage(this.message.getBytes(), session.getPeer());

		flight.addMessage(wrapMessage(applicationMessage));
		// application data is not retransmitted
		flight.setRetransmissionNeeded(false);

		return flight;
	}

	/**
	 * Used by the server to kickstart negotiations.
	 * 
	 * @param message
	 *            the hello request message
	 * @throws HandshakeException if the CLIENT_HELLO record cannot be created
	 */
	private DTLSFlight receivedHelloRequest() throws HandshakeException {
		if (state < HandshakeType.HELLO_REQUEST.getCode()) {
			return getStartHandshakeMessage();
		} else {
			// already started with handshake, drop this message
			return null;
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
	 * @return {@link ClientHello} with server's Cookie set.
	 * @throws HandshakeException if the CLIENT_HELLO record cannot be created
	 */
	protected DTLSFlight receivedHelloVerifyRequest(HelloVerifyRequest message) throws HandshakeException {

		clientHello.setCookie(message.getCookie());
		// update the length (cookie added)
		clientHello.setFragmentLength(clientHello.getMessageLength());

		DTLSFlight flight = new DTLSFlight(getSession());
		flight.addMessage(wrapMessage(clientHello));

		return flight;
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
		serverCertificate.verifyCertificate(rootCertificates);
		serverPublicKey = serverCertificate.getPublicKey();
		if (message.getCertificateChain() != null) {
			peerCertificate = (X509Certificate) message.getCertificateChain()[0];
		}
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
		if (peerCertificate != null) {
			session.setPeerIdentity(peerCertificate.getSubjectX500Principal());
		} else {
			session.setPeerIdentity(new RawPublicKeyIdentity(serverPublicKey));
		}
		// for backwards compatibility only
		session.setPeerRawPublicKey(serverPublicKey);
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
	 * @return the client's next flight to be sent.
	 * @throws HandshakeException
	 * @throws GeneralSecurityException if the client's handshake records cannot be created
	 */
	private DTLSFlight receivedServerHelloDone(ServerHelloDone message) throws HandshakeException, GeneralSecurityException {
		DTLSFlight flight = new DTLSFlight(getSession());
		if (serverHelloDone != null && (serverHelloDone.getMessageSeq() == message.getMessageSeq())) {
			// discard duplicate message
			return flight;
		}
		serverHelloDone = message;

		/*
		 * All possible handshake messages sent in this flight. Used to compute
		 * handshake hash.
		 */
		CertificateMessage clientCertificate = null;
		CertificateVerify certificateVerify = null;

		/*
		 * First, if required by server, send Certificate.
		 */
		if (certificateRequest != null) {
			// TODO load the client's certificate according to the allowed
			// parameters in the CertificateRequest
			if (session.sendRawPublicKey()){
				clientCertificate = new CertificateMessage(publicKey.getEncoded(), session.getPeer());
			} else {
				clientCertificate = new CertificateMessage(certificateChain, session.getPeer());
			}
			flight.addMessage(wrapMessage(clientCertificate));
		}

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
			session.setPeerIdentity(new PreSharedKeyIdentity(identity));
			// for backward compatibility only
			session.setPskIdentity(identity);

			byte[] psk = pskStore.getKey(identity);
			if (psk == null) {
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL,	AlertDescription.HANDSHAKE_FAILURE, session.getPeer());
				throw new HandshakeException("No preshared secret found for identity: " + identity, alert);
			}
			clientKeyExchange = new PSKClientKeyExchange(identity, session.getPeer());
			LOGGER.log(Level.FINER, "Using PSK identity: {0}", identity);
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
		if (certificateRequest != null) {
			// prepare handshake messages
			handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, clientHello.toByteArray());
			handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, serverHello.toByteArray());
			handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, serverCertificate.toByteArray());
			handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, serverKeyExchange.toByteArray());
			handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, certificateRequest.toByteArray());
			handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, serverHelloDone.toByteArray());
			handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, clientCertificate.toByteArray());
			handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, clientKeyExchange.toByteArray());
			
			// TODO make sure, that signature is supported
			SignatureAndHashAlgorithm signatureAndHashAlgorithm = certificateRequest.getSupportedSignatureAlgorithms().get(0);
			certificateVerify = new CertificateVerify(signatureAndHashAlgorithm, privateKey, handshakeMessages, session.getPeer());
			
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
		try {
			// create hash of handshake messages
			// can't do this on the fly, since there is no explicit ordering of
			// messages

			MessageDigest md = MessageDigest.getInstance("SHA-256");
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
				LOGGER.log(Level.SEVERE,"Clone not supported.",e);
			}

			handshakeHash = md.digest();
			Finished finished = new Finished(getMasterSecret(), isClient, handshakeHash, session.getPeer());
			flight.addMessage(wrapMessage(finished));
			
			// compute handshake hash with client's finished message also
			// included, used for server's finished message
			mdWithClientFinished.update(finished.toByteArray());
			handshakeHash = mdWithClientFinished.digest();

		} catch (NoSuchAlgorithmException e) {
			LOGGER.log(Level.SEVERE,"No such Message Digest Algorithm available.",e);
		}

		return flight;

	}

	@Override
	public DTLSFlight getStartHandshakeMessage() throws HandshakeException {
		handshakeStarted();
		ClientHello startMessage = new ClientHello(maxProtocolVersion, new SecureRandom(),
				supportedClientCertificateTypes, supportedServerCertificateTypes, session.getPeer());

		// store client random for later calculations
		clientRandom = startMessage.getRandom();

		// the preferred cipher suites in order of preference
		for (CipherSuite supportedSuite : preferredCipherSuites) {
			startMessage.addCipherSuite(supportedSuite);
		}

		startMessage.addCompressionMethod(CompressionMethod.NULL);
		if (maxFragmentLengthCode != null) {
			MaxFragmentLengthExtension ext = new MaxFragmentLengthExtension(maxFragmentLengthCode); 
			startMessage.addExtension(ext);
			LOGGER.log(
					Level.FINE,
					"Indicating max. fragment length [{0}] to server [{1}]",
					new Object[]{maxFragmentLengthCode, getPeerAddress()});
		}
		// set current state
		state = startMessage.getMessageType().getCode();

		// store for later calculations
		clientHello = startMessage;
		DTLSFlight flight = new DTLSFlight(session);
		flight.addMessage(wrapMessage(startMessage));

		return flight;
	}
}
