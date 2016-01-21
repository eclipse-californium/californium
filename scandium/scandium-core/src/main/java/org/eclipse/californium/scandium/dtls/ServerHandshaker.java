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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.scandium.auth.PreSharedKeyIdentity;
import org.eclipse.californium.scandium.auth.RawPublicKeyIdentity;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.CertificateRequest.ClientCertificateType;
import org.eclipse.californium.scandium.dtls.CertificateRequest.HashAlgorithm;
import org.eclipse.californium.scandium.dtls.CertificateRequest.SignatureAlgorithm;
import org.eclipse.californium.scandium.dtls.CertificateTypeExtension.CertificateType;
import org.eclipse.californium.scandium.dtls.SupportedPointFormatsExtension.ECPointFormat;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.util.ByteArrayUtils;

/**
 * Server handshaker does the protocol handshaking from the point of view of a
 * server. It is message-driven by the parent {@link Handshaker} class.
 */
public class ServerHandshaker extends Handshaker {

	private static final Logger LOGGER = Logger.getLogger(ServerHandshaker.class.getName());
	
	// Members ////////////////////////////////////////////////////////

	/**
	 * The last flight that is sent during this handshake, will not be
	 * retransmitted unless the peer retransmits its last flight.
	 */
	private DTLSFlight lastFlight;

	/** Is the client required to authenticate itself? */
	private boolean clientAuthenticationRequired = false;

	/**
	 * The client's public key from its certificate (only sent when
	 * CertificateRequest sent).
	 */
	private PublicKey clientPublicKey;

	/**
	 * The client's X.509 certificate.
	 */
	private X509Certificate peerCertificate;
	
	
	/**
	 * The cryptographic options this server supports, e.g. for exchanging keys,
	 * digital signatures etc.
	 */
	private List<CipherSuite> supportedCipherSuites;

	/**
	 * The certificate types this server supports for client authentication.
	 */
	private List<CertificateType> supportedClientCertificateTypes;
	/**
	 * The certificate types this server supports for server authentication.
	 */
	private List<CertificateType> supportedServerCertificateTypes;

	private CertificateType negotiatedClientCertificateType;
	private CertificateType negotiatedServerCertificateType;
	private SupportedGroup negotiatedSupportedGroup;
	
	/*
	 * Store all the messages which can possibly be sent by the client. We
	 * need these to compute the handshake hash.
	 */
	/** The client's {@link CertificateMessage}. Optional. */
	protected CertificateMessage clientCertificate = null;
	/** The client's {@link ClientKeyExchange}. mandatory. */
	protected ClientKeyExchange clientKeyExchange;
	/** The client's {@link CertificateVerify}. Optional. */
	protected CertificateVerify certificateVerify = null;
	
	/** Used to retrieve pre-shared-key from a given client identity */
	protected final PskStore pskStore;
	
	
	
	// Constructors ///////////////////////////////////////////////////

	/**
	 * Creates a handshaker for negotiating a DTLS session with a client
	 * following the full DTLS handshake protocol. 
	 * 
	 * @param session
	 *            the session to negotiate with the client
	 * @param sessionListener
	 *            the listener to notify about the session's life-cycle events
	 * @param config
	 *            the DTLS configuration
	 * @param maxTransmissionUnit
	 *            the MTU value reported by the network interface the record layer is bound to
	 * @throws HandshakeException if the handshaker cannot be initialized
	 * @throws NullPointerException if session is <code>null</code>
	 */
	public ServerHandshaker(DTLSSession session, SessionListener sessionListener,
			DtlsConnectorConfig config, int maxTransmissionUnit) throws HandshakeException {
		this(0, session, sessionListener, config, maxTransmissionUnit);
	}
	
	/**
	 * Creates a handshaker for negotiating a DTLS session with a client
	 * following the full DTLS handshake protocol. 
	 * 
	 * @param initialMessageSequenceNo
	 *            the initial message sequence number to expect from the peer
	 *            (this parameter can be used to initialize the <em>receive_next_seq</em>
	 *            counter to another value than 0, e.g. if one or more cookie exchange round-trips
	 *            have been performed with the peer before the handshake starts)
	 * @param session
	 *            the session to negotiate with the client
	 * @param sessionListener
	 *            the listener to notify about the session's life-cycle events
	 * @param config
	 *            the DTLS configuration
	 * @param maxTransmissionUnit
	 *            the MTU value reported by the network interface the record layer is bound to
	 * @throws IllegalStateException if the message digest required for computing
	 *            the FINISHED message hash cannot be instantiated
	 * @throws IllegalArgumentException if the <code>initialMessageSequenceNo</code> is negative
	 * @throws NullPointerException if <code>session</code> or <code>config</code> is <code>null</code>
	 */
	public ServerHandshaker(int initialMessageSequenceNo, DTLSSession session, SessionListener sessionListener,
			DtlsConnectorConfig config, int maxTransmissionUnit) { 
		super(false, initialMessageSequenceNo, session, sessionListener, config.getTrustStore(), maxTransmissionUnit);

		this.supportedCipherSuites = Arrays.asList(config.getSupportedCipherSuites());

		this.pskStore = config.getPskStore();

		this.privateKey = config.getPrivateKey();
		this.certificateChain = config.getCertificateChain();
		this.publicKey = config.getPublicKey();

		this.clientAuthenticationRequired = config.isClientAuthenticationRequired();

		this.supportedClientCertificateTypes = new ArrayList<>();
		this.supportedClientCertificateTypes.add(CertificateType.RAW_PUBLIC_KEY);
		if (rootCertificates != null && rootCertificates.length > 0) {
			this.supportedClientCertificateTypes.add(CertificateType.X_509);
		}

		this.supportedServerCertificateTypes = new ArrayList<>();
		if (privateKey != null && publicKey != null) {
			if (certificateChain == null || certificateChain.length == 0) {
				this.supportedServerCertificateTypes.add(CertificateType.RAW_PUBLIC_KEY);
			} else if (config.isSendRawKey()) {
				this.supportedServerCertificateTypes.add(CertificateType.RAW_PUBLIC_KEY);
				this.supportedServerCertificateTypes.add(CertificateType.X_509);
			} else {
				this.supportedServerCertificateTypes.add(CertificateType.X_509);
				this.supportedServerCertificateTypes.add(CertificateType.RAW_PUBLIC_KEY);
			}
		}
	}

	// Methods ////////////////////////////////////////////////////////
	

	@Override
	protected synchronized DTLSFlight doProcessMessage(DTLSMessage message) throws HandshakeException, GeneralSecurityException {
		if (lastFlight != null) {
			// we already sent the last flight (including our FINISHED message),
			// but the client does not seem to have received it because we received
			// its finished message again, so we simply retransmit our last flight
			LOGGER.log(Level.FINER, "Received client's ({0}) FINISHED message again, retransmitting last flight...",
					getPeerAddress());
			return lastFlight;
		}

		DTLSFlight flight = null;

		// log record now (even if message is still encrypted) in case an Exception
		// is thrown during processing
		if (LOGGER.isLoggable(Level.FINE)) {
			StringBuffer msg = new StringBuffer();
			msg.append(String.format(
					"Processing %s message from peer [%s]",
					message.getContentType(), message.getPeer()));
			if (LOGGER.isLoggable(Level.FINEST)) {
				msg.append(":\n").append(message);
			}
			LOGGER.fine(msg.toString());
		}


		switch (message.getContentType()) {
		case CHANGE_CIPHER_SPEC:
			setCurrentReadState();
			LOGGER.log(Level.FINE, "Processed {1} message from peer [{0}]",
					new Object[]{message.getPeer(), message.getContentType()});
			break;

		case HANDSHAKE:
			HandshakeMessage handshakeMsg = (HandshakeMessage) message;

			switch (handshakeMsg.getMessageType()) {
			case CLIENT_HELLO:
				flight = receivedClientHello((ClientHello) handshakeMsg);
				break;

			case CERTIFICATE:
				receivedClientCertificate((CertificateMessage) handshakeMsg);
				break;

			case CLIENT_KEY_EXCHANGE:
				byte[] premasterSecret;
				switch (getKeyExchangeAlgorithm()) {
				case PSK:
					premasterSecret = receivedClientKeyExchange((PSKClientKeyExchange) handshakeMsg);
					generateKeys(premasterSecret);
					break;

				case EC_DIFFIE_HELLMAN:
					premasterSecret = receivedClientKeyExchange((ECDHClientKeyExchange) handshakeMsg);
					generateKeys(premasterSecret);
					break;

				case NULL:
					premasterSecret = receivedClientKeyExchange((NULLClientKeyExchange) handshakeMsg);
					generateKeys(premasterSecret);
					break;

				default:
					throw new HandshakeException(
							String.format("Unsupported key exchange algorithm %s", getKeyExchangeAlgorithm().name()),
							new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, handshakeMsg.getPeer()));
				}
				handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, clientKeyExchange.getRawMessage());
				break;

			case CERTIFICATE_VERIFY:
				receivedCertificateVerify((CertificateVerify) handshakeMsg);
				break;

			case FINISHED:
				flight = receivedClientFinished((Finished) handshakeMsg);
				break;

			default:
				throw new HandshakeException(
						String.format("Received unexpected %s message from peer %s", handshakeMsg.getMessageType(), handshakeMsg.getPeer()),
						new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE, handshakeMsg.getPeer()));
			}

			incrementNextReceiveSeq();
			LOGGER.log(Level.FINE, "Processed {1} message with message sequence no [{2}] from peer [{0}]",
					new Object[]{message.getPeer(), handshakeMsg.getMessageType(), handshakeMsg.getMessageSeq()});
			break;

		default:
			throw new HandshakeException(
					String.format("Received unexpected %s message from peer %s", message.getContentType(), message.getPeer()),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, message.getPeer()));
		}

		return flight;
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
		if (clientCertificate != null && (clientCertificate.getMessageSeq() == message.getMessageSeq())) {
			// discard duplicate message
			return;
		}

		clientCertificate = message;
		clientCertificate.verifyCertificate(rootCertificates);
		clientPublicKey = clientCertificate.getPublicKey();
		if (message.getCertificateChain() != null && message.getCertificateChain().length > 0) {
			peerCertificate = (X509Certificate) message.getCertificateChain()[0];
		} else {
			// TODO: decide whether the handshake needs to be aborted or can proceed with an unauthenticated client
		}
		// TODO why don't we also update the MessageDigest at this point?
		handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, clientCertificate.getRawMessage());
	}

	/**
	 * Verifies the client's CertificateVerify message and if verification fails,
	 * aborts and sends Alert message.
	 * 
	 * @param message
	 *            the client's CertificateVerify.
	 * @return <code>null</code> if the signature can be verified, otherwise a
	 *         flight containing an Alert.
	 * @throws HandshakeException 
	 */
	private void receivedCertificateVerify(CertificateVerify message) throws HandshakeException {
		certificateVerify = message;

		message.verifySignature(clientPublicKey, handshakeMessages);
		// at this point we have successfully authenticated the client
		if (peerCertificate != null) {
			session.setPeerIdentity(peerCertificate.getSubjectX500Principal());
		} else {
			session.setPeerIdentity(new RawPublicKeyIdentity(clientPublicKey));
		}
		session.setPeerRawPublicKey(clientPublicKey);
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
	 * @return the server's last {@link DTLSFlight}.
	 * @throws HandshakeException if the client did not send the required <em>CLIENT_CERTIFICATE</em>
	 *            and <em>CERTIFICATE_VERIFY</em> messages or if the server's FINISHED message
	 *            cannot be created
	 */
	private DTLSFlight receivedClientFinished(Finished message) throws HandshakeException {
		if (lastFlight != null) {
			return null;
		}
		
		// check if client sent all expected messages
		// (i.e. ClientCertificate/CertificateVerify when server sent CertificateRequest)
		if (CipherSuite.KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN.equals(getKeyExchangeAlgorithm()) && 
				clientAuthenticationRequired && 
				(clientCertificate == null || certificateVerify == null)) {
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, session.getPeer());
			throw new HandshakeException("Client did not send required authentication messages.", alert);
		}

		DTLSFlight flight = new DTLSFlight(getSession());

		// create handshake hash
		if (clientCertificate != null) { // optional
			md.update(clientCertificate.getRawMessage());
		}

		md.update(clientKeyExchange.getRawMessage()); // mandatory

		if (certificateVerify != null) { // optional
			md.update(certificateVerify.getRawMessage());
		}

		MessageDigest mdWithClientFinished = null;
		try {
			/*
			 * the handshake_messages for the Finished message sent by the
			 * client will be different from that for the Finished message sent
			 * by the server, because the one that is sent second will include
			 * the prior one.
			 */
			mdWithClientFinished = (MessageDigest) md.clone();
			mdWithClientFinished.update(message.toByteArray());
		} catch (CloneNotSupportedException e) {
			LOGGER.log(Level.SEVERE, "Cannot compute digest for server's Finish handshake message", e);
		}

		// Verify client's data
		byte[] handshakeHash = md.digest();
		message.verifyData(getMasterSecret(), true, handshakeHash);

		/*
		 * First, send ChangeCipherSpec
		 */
		ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage(session.getPeer());
		flight.addMessage(wrapMessage(changeCipherSpecMessage));
		setCurrentWriteState();

		/*
		 * Second, send Finished message
		 */
		handshakeHash = mdWithClientFinished.digest();
		Finished finished = new Finished(getMasterSecret(), isClient, handshakeHash, session.getPeer());
		flight.addMessage(wrapMessage(finished));

		state = HandshakeType.FINISHED.getCode();

		flight.setRetransmissionNeeded(false);
		// store, if we need to retransmit this flight, see
		// http://tools.ietf.org/html/rfc6347#section-4.2.4
		lastFlight = flight;
		sessionEstablished();
		return flight;
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
	 * @param message
	 *            the client's hello message.
	 * @return the server's next flight to be sent.
	 * @throws HandshakeException if the server's response message(s) cannot be created
	 */
	private DTLSFlight receivedClientHello(ClientHello message) throws HandshakeException {
		
		handshakeStarted();
		DTLSFlight flight = new DTLSFlight(getSession());

		// update the handshake hash
		md.update(message.getRawMessage());
		handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, message.getRawMessage());

		/*
		 * First, send ServerHello (mandatory)
		 */
		ProtocolVersion serverVersion = negotiateProtocolVersion(message.getClientVersion());

		// store client and server random
		clientRandom = message.getRandom();
		serverRandom = new Random();

		SessionId sessionId = new SessionId();
		session.setSessionIdentifier(sessionId);

		CipherSuite cipherSuite = negotiateCipherSuite(message);
		session.setCipherSuite(cipherSuite);

		// currently only NULL compression supported, no negotiation needed
		if (!message.getCompressionMethods().contains(CompressionMethod.NULL)) {
			// abort handshake
			throw new HandshakeException(
					"Client does not support NULL compression method",
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.HANDSHAKE_FAILURE,
							message.getPeer()));
		} else {
			session.setCompressionMethod(CompressionMethod.NULL);
		}

		HelloExtensions serverHelloExtensions = new HelloExtensions();

		MaxFragmentLengthExtension maxFragmentLengthExt = message.getMaxFragmentLengthExtension();
		if (maxFragmentLengthExt != null) {
			session.setMaxFragmentLength(maxFragmentLengthExt.getFragmentLength().length());
			serverHelloExtensions.addExtension(maxFragmentLengthExt);
			LOGGER.log(
					Level.FINE,
					"Negotiated max. fragment length [{0} bytes] with peer [{1}]",
					new Object[]{maxFragmentLengthExt.getFragmentLength().length(), message.getPeer()});
		}

		if (cipherSuite.requiresServerCertificateMessage()) {
			// the negotiated cipher suite requires us (server side) to prove our identity
			// using a certificate
			serverHelloExtensions.addExtension(negotiateServerCertificateType(message));
			if (clientAuthenticationRequired) {
				// we (server side) will request a certificate from the client as well
				// thus we need to indicate the type of certificate we expect
				serverHelloExtensions.addExtension(negotiateClientCertificateType(message));
			}
		}

		if (cipherSuite.isEccBased()) {
			// if we chose a ECC cipher suite, the server should send the
			// supported point formats extension in its ServerHello
			List<ECPointFormat> formats = Arrays.asList(ECPointFormat.UNCOMPRESSED);
			serverHelloExtensions.addExtension(new SupportedPointFormatsExtension(formats));
		}

		ServerHello serverHello = new ServerHello(serverVersion, serverRandom, sessionId,
				cipherSuite, session.getCompressionMethod(), serverHelloExtensions, session.getPeer());
		flight.addMessage(wrapMessage(serverHello));
		
		// update the handshake hash
		md.update(serverHello.toByteArray());
		handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, serverHello.toByteArray());

		/*
		 * Second, send Certificate (if required by key exchange algorithm)
		 */
		CertificateMessage certificateMessage = null;
		if (cipherSuite.requiresServerCertificateMessage()) {
			if (session.sendRawPublicKey()){
				certificateMessage = new CertificateMessage(publicKey.getEncoded(), session.getPeer());
			} else {
				certificateMessage = new CertificateMessage(certificateChain, session.getPeer());
			}

			flight.addMessage(wrapMessage(certificateMessage));
			md.update(certificateMessage.toByteArray());
			handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, certificateMessage.toByteArray());
		}

		/*
		 * Third, send ServerKeyExchange (if required by key exchange
		 * algorithm)
		 */
		ServerKeyExchange serverKeyExchange = null;
		SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
		switch (getKeyExchangeAlgorithm()) {
		case EC_DIFFIE_HELLMAN:
			// TODO SHA256withECDSA is default but should be configurable
			signatureAndHashAlgorithm = new SignatureAndHashAlgorithm(HashAlgorithm.SHA256, SignatureAlgorithm.ECDSA);
			try {
				ecdhe = new ECDHECryptography(negotiatedSupportedGroup.getEcParams());
				serverKeyExchange = new ECDHServerKeyExchange(signatureAndHashAlgorithm, ecdhe, privateKey, clientRandom, serverRandom,
						negotiatedSupportedGroup.getId(), session.getPeer());
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

		default:
			// NULL does not require the server's key exchange message
			break;
		}
		
		if (serverKeyExchange != null) {
			flight.addMessage(wrapMessage(serverKeyExchange));
			md.update(serverKeyExchange.toByteArray());
			handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, serverKeyExchange.toByteArray());
		}

		/*
		 * Fourth, send CertificateRequest for client (if required)
		 */
		if (clientAuthenticationRequired && signatureAndHashAlgorithm != null) {

			CertificateRequest certificateRequest = new CertificateRequest(session.getPeer());
			
			// TODO make this variable, reasonable values
			certificateRequest.addCertificateType(ClientCertificateType.ECDSA_SIGN);
			certificateRequest.addSignatureAlgorithm(new SignatureAndHashAlgorithm(signatureAndHashAlgorithm.getHash(), signatureAndHashAlgorithm.getSignature()));
			certificateRequest.addCertificateAuthorities(rootCertificates);

			flight.addMessage(wrapMessage(certificateRequest));
			md.update(certificateRequest.toByteArray());
			handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, certificateRequest.toByteArray());
		}

		/*
		 * Last, send ServerHelloDone (mandatory)
		 */
		ServerHelloDone serverHelloDone = new ServerHelloDone(session.getPeer());
		flight.addMessage(wrapMessage(serverHelloDone));
		md.update(serverHelloDone.toByteArray());
		handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, serverHelloDone.toByteArray());

		return flight;
	}

	/**
	 * Generates the premaster secret by taking the client's public key and
	 * running the ECDHE key agreement.
	 * 
	 * @param message
	 *            the client's key exchange message.
	 * @return the premaster secret
	 */
	private byte[] receivedClientKeyExchange(ECDHClientKeyExchange message) {
		clientKeyExchange = message;
		byte[] premasterSecret = ecdhe.getSecret(message.getEncodedPoint()).getEncoded();

		return premasterSecret;
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
	private byte[] receivedClientKeyExchange(PSKClientKeyExchange message) throws HandshakeException {
		clientKeyExchange = message;

		// use the client's PSK identity to get right preshared key
		String identity = message.getIdentity();

		byte[] psk = pskStore.getKey(identity);
		
		LOGGER.log(Level.FINER, "Client [{0}] uses PSK identity [{1}]",
				new Object[]{getPeerAddress(), identity});
		
		if (psk == null) {
			throw new HandshakeException(
					String.format("Cannot authenticate client, identity [%s] is unknown", identity),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, session.getPeer()));
		}
		
		session.setPeerIdentity(new PreSharedKeyIdentity(identity));
		// for backwards compatibility only
		session.setPskIdentity(identity);
		
		return generatePremasterSecretFromPSK(psk);
	}

	/**
	 * Returns an empty premaster secret.
	 * 
	 * @param message
	 *            the client's key exchange message.
	 * @return the premaster secret
	 */
	private byte[] receivedClientKeyExchange(NULLClientKeyExchange message) {
		clientKeyExchange = message;

		// by current assumption we take an empty premaster secret
		// to compute the master secret and the resulting keys
		return new byte[] {};
	}

	@Override
	public DTLSFlight getStartHandshakeMessage() throws HandshakeException {
		HelloRequest helloRequest = new HelloRequest(session.getPeer());

		DTLSFlight flight = new DTLSFlight(getSession());
		flight.addMessage(wrapMessage(helloRequest));
		return flight;
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
	 * 
	 * Iterates through the provided (ordered) list of the client's
	 * preferred ciphers until one is found that is also contained
	 * in the {@link #supportedCipherSuites}.
	 * 
	 * If the client proposes an ECC based cipher suite this method also
	 * tries to determine an appropriate <em>Supported Group</em> by means
	 * of invoking the {@link #negotiateNamedCurve(ClientHello)} method.
	 * If a group is found it will be stored in the {@link #negotiatedSupportedGroup}
	 * field. 
	 * 
	 * The <em>SSL_NULL_WITH_NULL_NULL</em> cipher suite is <em>never</em>
	 * negotiated as mandated by <a href="http://tools.ietf.org/html/rfc5246#appendix-A.5">
	 * RFC 5246 Appendix A.5</a>
	 * 
	 * @param clientHello
	 *            the message containing the list of cipher suites the client supports
	 *            (ordered by preference)
	 * @return The single cipher suite selected by the server from the list
	 *         which will be used after handshake completion.
	 * @throws HandshakeException
	 *             if this server does not support any of
	 *             the cipher suites proposed by the client
	 */
	private CipherSuite negotiateCipherSuite(ClientHello clientHello) throws HandshakeException {
		
		for (CipherSuite cipherSuite : clientHello.getCipherSuites()) {
			// NEVER negotiate NULL cipher suite
			if (cipherSuite != CipherSuite.TLS_NULL_WITH_NULL_NULL &&
					supportedCipherSuites.contains(cipherSuite)) {
				if (cipherSuite.isEccBased()) {
					// we also need to check if we can agree on a named curve
					SupportedGroup group = negotiateNamedCurve(clientHello);
					if (group != null) {
						negotiatedSupportedGroup = group;
					} else {
						// try next cipher suite
						continue;
					}
				}
				LOGGER.log(Level.FINER, "Negotiated cipher suite [{0}] with peer [{1}]",
						new Object[]{cipherSuite.name(), getPeerAddress()});
				return cipherSuite;
			}
		}
		// if none of the client's proposed cipher suites matches throw exception
		AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, session.getPeer());
		throw new HandshakeException("Client proposed unsupported cipher suites only", alert);
	}

	/**
	 * Determines the elliptic curve to use during the EC based DH key exchange.
	 * 
	 * @param clientHello
	 *            the peer's <em>CLIENT_HELLO</em> message containing its
	 *            preferred elliptic curves
	 * @return the selected curve
	 */
	private SupportedGroup negotiateNamedCurve(ClientHello clientHello) {
		SupportedGroup result = null;
		List<SupportedGroup> preferredGroups = SupportedGroup.getPreferredGroups();
		SupportedEllipticCurvesExtension extension = clientHello.getSupportedEllipticCurvesExtension();
		if (extension == null) {
			// according to RFC 4492, section 4 (https://tools.ietf.org/html/rfc4492#section-4)
			// we are free to pick any curve in this case
			if (!preferredGroups.isEmpty()) {
				result = preferredGroups.get(0);
			}
		} else {
			for (Integer preferredGroupId : extension.getSupportedGroupIds()) {
				// use first group proposed by client contained in list of server's preferred groups
				SupportedGroup group = SupportedGroup.fromId(preferredGroupId);
				if (group != null && group.isUsable() && preferredGroups.contains(group)) {
					result = group;
					break;
				}
			}
		}
		return result;
	}

	/**
	 * Determines the type of certificate this handshaker expects from the peer
	 * in its <em>CERTIFICATE</em> message.
	 * 
	 * @param clientHello
	 *            the peer's <em>CLIENT_HELLO</em> message containing the
	 *            peer's preferred client certificate types
	 * @return the hello extension containing the selected certificate type
	 * @throws HandshakeException
	 *             if none of the peer's preferred types is supported by this
	 *             handshaker
	 */
	private ClientCertificateTypeExtension negotiateClientCertificateType(ClientHello clientHello)
			throws HandshakeException {
		
		ClientCertificateTypeExtension certTypeExt = clientHello.getClientCertificateTypeExtension();
		if (certTypeExt != null) {
			for (CertificateType certType : certTypeExt.getCertificateTypes()) {
				if (supportedClientCertificateTypes.contains(certType)) {
					negotiatedClientCertificateType = certType;
					break;
				}
			}
		} else if (supportedClientCertificateTypes.contains(CertificateType.X_509)) {
			negotiatedClientCertificateType = CertificateType.X_509;
		}
		if (negotiatedClientCertificateType == null) {
			throw new HandshakeException(
					"Server does not support any of the client's preferred client certificate types",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.UNSUPPORTED_CERTIFICATE, session.getPeer()));
		} else {
			session.setReceiveRawPublicKey(CertificateType.RAW_PUBLIC_KEY.equals(negotiatedClientCertificateType));

			ClientCertificateTypeExtension result = new ClientCertificateTypeExtension(false);
			result.addCertificateType(negotiatedClientCertificateType);
			return result;
		}
	}	

	/**
	 * Determines the type of certificate this handshaker will send to the peer
	 * in its <em>CERTIFICATE</em> message.
	 * 
	 * @param clientHello
	 *            the peer's <em>CLIENT_HELLO</em> message containing the
	 *            peer's preferred server certificate types
	 * @return the hello extension containing the selected certificate type
	 * @throws HandshakeException
	 *             if none of the peer's preferred types is supported by this
	 *             handshaker
	 */
	private ServerCertificateTypeExtension negotiateServerCertificateType(ClientHello clientHello)
			throws HandshakeException {
		ServerCertificateTypeExtension certTypeExt = clientHello.getServerCertificateTypeExtension();
		if (certTypeExt != null) {
			for (CertificateType certType : certTypeExt.getCertificateTypes()) {
				if (supportedServerCertificateTypes.contains(certType)) {
					negotiatedServerCertificateType = certType;
					break;
				}
			}
		} else if (supportedServerCertificateTypes.contains(CertificateType.X_509)) {
			negotiatedServerCertificateType = CertificateType.X_509;
		}
		if (negotiatedServerCertificateType == null) {
			throw new HandshakeException(
					"Server does not support any of the client's preferred server certificate types",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.UNSUPPORTED_CERTIFICATE, session.getPeer()));
		} else {
			session.setSendRawPublicKey(CertificateType.RAW_PUBLIC_KEY.equals(negotiatedServerCertificateType));
			
			ServerCertificateTypeExtension result = new ServerCertificateTypeExtension(false);
			result.addCertificateType(negotiatedServerCertificateType);
			return result;
		}
	}

	final CertificateType getNegotiatedClientCertificateType() {
		return negotiatedClientCertificateType;
	}

	final CertificateType getNegotiatedServerCertificateType() {
		return negotiatedServerCertificateType;
	}

	final SupportedGroup getNegotiatedSupportedGroup() {
		return negotiatedSupportedGroup;
	}

	/**
	 * @return <code>true</code> if the given message is a <em>CLIENT_HELLO</em> message
	 *            and contains the same <em>client random</em> as the <code>clientRandom</code> field.
	 */
	@Override
	protected boolean isFirstMessageReceived(final HandshakeMessage handshakeMessage) {
		if (HandshakeType.CLIENT_HELLO.equals(handshakeMessage.getMessageType())) {
			Random messageRandom = ((ClientHello) handshakeMessage).getRandom();
			return Arrays.equals(clientRandom.getRandomBytes(), messageRandom.getRandomBytes());
		} else {
			return false;
		}
	}
}
