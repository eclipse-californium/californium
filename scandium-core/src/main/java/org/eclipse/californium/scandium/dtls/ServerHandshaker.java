/*******************************************************************************
 * Copyright (c) 2014, 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
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
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.util.ByteArrayUtils;


/**
 * Server handshaker does the protocol handshaking from the point of view of a
 * server. It is message-driven by the parent {@link Handshaker} class.
 */
public class ServerHandshaker extends Handshaker {

	private static final Logger LOGGER = Logger.getLogger(ServerHandshaker.class.getName());
	
	// Members ////////////////////////////////////////////////////////

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
	 * @throws HandshakeException if the handshaker cannot be initialized
	 * @throws NullPointerException if session is <code>null</code>
	 */
	public ServerHandshaker(DTLSSession session, SessionListener sessionListener,
			DtlsConnectorConfig config) throws HandshakeException {
		this(0, session, sessionListener, config);
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
	 * @throws HandshakeException if the handshaker cannot be initialized
	 * @throws NullPointerException if session is <code>null</code>
	 */
	public ServerHandshaker(int initialMessageSequenceNo, DTLSSession session, SessionListener sessionListener,
			DtlsConnectorConfig config) throws HandshakeException { 
		super(false, initialMessageSequenceNo, session, sessionListener, config.getTrustStore(), config.getMaxFragmentLength());

		this.supportedCipherSuites = Arrays.asList(config.getSupportedCipherSuites());
		
		this.pskStore = config.getPskStore();
		
		this.privateKey = config.getPrivateKey();
		this.certificates = config.getCertificateChain();
		this.publicKey = config.getPublicKey();

		this.clientAuthenticationRequired = config.isClientAuthenticationRequired();

		this.supportedClientCertificateTypes = new ArrayList<>();
		this.supportedClientCertificateTypes.add(CertificateType.RAW_PUBLIC_KEY);
		if (rootCertificates != null && rootCertificates.length > 0) {
			this.supportedClientCertificateTypes.add(CertificateType.X_509);
		}

		this.supportedServerCertificateTypes = new ArrayList<>();
		if (privateKey != null && publicKey != null) {
			if (certificates != null) {
				if (config.isSendRawKey()) {
					this.supportedServerCertificateTypes.add(CertificateType.RAW_PUBLIC_KEY);
					this.supportedServerCertificateTypes.add(CertificateType.X_509);
				} else {
					this.supportedServerCertificateTypes.add(CertificateType.X_509);
					this.supportedServerCertificateTypes.add(CertificateType.RAW_PUBLIC_KEY);
				}
			} else {
				this.supportedServerCertificateTypes.add(CertificateType.RAW_PUBLIC_KEY);
			}
		}
	}

	// Methods ////////////////////////////////////////////////////////
	

	@Override
	protected synchronized DTLSFlight doProcessMessage(Record record) throws HandshakeException, GeneralSecurityException {
		if (lastFlight != null) {
			// we already sent the last flight (including our FINISHED message),
			// but the client does not seem to have received it because we received
			// its finished message again, so we simply retransmit our last flight
			LOGGER.log(Level.FINER, "Received client's ({0}) FINISHED message again, retransmitting last flight...",
					getPeerAddress());
			return lastFlight;
		}

		DTLSFlight flight = null;

		if (!processMessageNext(record)) {
			return flight;
		}

		// log record now (even if message is still encrypted) in case an Exception
		// is thrown during processing
		if (LOGGER.isLoggable(Level.FINE)) {
			StringBuffer msg = new StringBuffer();
			msg.append(String.format(
					"Processing %s message from peer [%s]",
					record.getType(), record.getPeerAddress()));
			if (LOGGER.isLoggable(Level.FINEST)) {
				msg.append(":\n").append(record);
			}
			LOGGER.fine(msg.toString());
		}
		
		switch (record.getType()) {
		case CHANGE_CIPHER_SPEC:
			record.getFragment();
			setCurrentReadState();
			LOGGER.log(Level.FINE, "Processed {1} message from peer [{0}]",
					new Object[]{record.getPeerAddress(), record.getType()});
			break;

		case HANDSHAKE:
			HandshakeMessage fragment = (HandshakeMessage) record.getFragment();

			// check for fragmentation
			if (fragment instanceof FragmentedHandshakeMessage) {
				fragment = handleFragmentation((FragmentedHandshakeMessage) fragment);
				if (fragment == null) {
					// fragment could not yet be fully reassembled
					break;
				}
				// continue with the reassembled handshake message
				record.setFragment(fragment);
			}
			
			switch (fragment.getMessageType()) {
			case CLIENT_HELLO:
				flight = receivedClientHello((ClientHello) fragment);
				break;

			case CERTIFICATE:
				receivedClientCertificate((CertificateMessage) fragment);
				break;

			case CLIENT_KEY_EXCHANGE:
				byte[] premasterSecret;
				switch (keyExchange) {
				case PSK:
					premasterSecret = receivedClientKeyExchange((PSKClientKeyExchange) fragment);
					generateKeys(premasterSecret);
					break;

				case EC_DIFFIE_HELLMAN:
					premasterSecret = receivedClientKeyExchange((ECDHClientKeyExchange) fragment);
					generateKeys(premasterSecret);
					break;

				case NULL:
					premasterSecret = receivedClientKeyExchange((NULLClientKeyExchange) fragment);
					generateKeys(premasterSecret);
					break;

				default:
					throw new HandshakeException(
							String.format("Unsupported key exchange algorithm %s", keyExchange.name()),
							new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, session.getPeer()));
				}
				handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, clientKeyExchange.getRawMessage());
				break;

			case CERTIFICATE_VERIFY:
				receivedCertificateVerify((CertificateVerify) fragment);
				break;

			case FINISHED:
				flight = receivedClientFinished((Finished) fragment);
				break;

			default:
				throw new HandshakeException(
						String.format("Received unexpected handshake message [%s] from peer %s", fragment.getMessageType(), record.getPeerAddress()),
						new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE, record.getPeerAddress()));
			}
			LOGGER.log(Level.FINE, "Processed {1} message from peer [{0}]",
					new Object[]{record.getPeerAddress(), fragment.getMessageType()});
			break;

		default:
			throw new HandshakeException(
					String.format("Received unexpected message [%s] from peer %s", record.getType(), record.getPeerAddress()),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, record.getPeerAddress()));
		}
		
		if (flight == null) {
			Record nextMessage = null;
			// check queued message, if it is now their turn
			for (Record queuedMessage : queuedMessages) {
				if (processMessageNext(queuedMessage)) {
					// queuedMessages.remove(queuedMessage);
					nextMessage = queuedMessage;
					break;
				}
			}
			if (nextMessage != null) {
				flight = processMessage(nextMessage);
			}
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
		if (message.getCertificateChain() != null) {
			peerCertificate = (X509Certificate) message.getCertificateChain()[0];
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
		if (keyExchange == CipherSuite.KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN && 
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
		session.setActive(true);

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
		serverRandom = new Random(new SecureRandom());

		SessionId sessionId = new SessionId();
		session.setSessionIdentifier(sessionId);

		CipherSuite cipherSuite = negotiateCipherSuite(message.getCipherSuites());
		setCipherSuite(cipherSuite);

		// currently only NULL compression supported, no negotiation needed
		CompressionMethod compressionMethod = CompressionMethod.NULL;
		setCompressionMethod(compressionMethod);
		
		
		HelloExtensions serverHelloExtensions = new HelloExtensions();

		if (supportedCipherSuites.contains(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)) {
			// we only need to add certificate extensions if we support
			// a certificate based key exchange algorithm
			ClientCertificateTypeExtension clientCertificateTypeExtension = message
					.getClientCertificateTypeExtension();
			if (clientCertificateTypeExtension != null) {
				// choose certificate type from client's list
				// of preferred client certificate types
				CertificateType certType = negotiateCertificateType(
						clientCertificateTypeExtension,
						supportedClientCertificateTypes);
				// the certificate type requested from the client
				CertificateTypeExtension ext1 = new ClientCertificateTypeExtension(false);
				ext1.addCertificateType(certType);

				serverHelloExtensions.addExtension(ext1);

				if (certType == CertificateType.RAW_PUBLIC_KEY) {
					session.setReceiveRawPublicKey(true);
				}
			}
			
			CertificateTypeExtension serverCertificateTypeExtension = message.getServerCertificateTypeExtension();
			if (serverCertificateTypeExtension != null) {
				// choose certificate type from client's list
				// of preferred server certificate types
				CertificateType certType = negotiateCertificateType(
						serverCertificateTypeExtension,
						supportedServerCertificateTypes);
				// the certificate type found in the attached certificate
				// payload
				CertificateTypeExtension ext2 = new ServerCertificateTypeExtension(false);
				ext2.addCertificateType(certType);

				serverHelloExtensions.addExtension(ext2);

				if (certType == CertificateType.RAW_PUBLIC_KEY) {
					session.setSendRawPublicKey(true);
				}
			}
		}

		if (keyExchange == CipherSuite.KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN) {
			// if we chose a ECC cipher suite, the server should send the
			// supported point formats extension in its ServerHello
			List<ECPointFormat> formats = Arrays.asList(ECPointFormat.UNCOMPRESSED);

			HelloExtension ext3 = new SupportedPointFormatsExtension(formats);
			serverHelloExtensions.addExtension(ext3);
		}

		ServerHello serverHello = new ServerHello(serverVersion, serverRandom, sessionId, cipherSuite, compressionMethod,
				serverHelloExtensions, session.getPeer());
		flight.addMessage(wrapMessage(serverHello));
		
		// update the handshake hash
		md.update(serverHello.toByteArray());
		handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, serverHello.toByteArray());

		/*
		 * Second, send Certificate (if required by key exchange algorithm)
		 */
		CertificateMessage certificateMessage = null;
		switch (keyExchange) {
		case EC_DIFFIE_HELLMAN:
			if (session.sendRawPublicKey()){
				certificateMessage = new CertificateMessage(publicKey.getEncoded(), session.getPeer());
			} else {
				certificateMessage = new CertificateMessage(certificates, session.getPeer());
			}
			break;

		default:
			// NULL and PSK do not require the Certificate message
			// See http://tools.ietf.org/html/rfc4279#section-2
			break;
		}
		if (certificateMessage != null) {
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
		switch (keyExchange) {
		case EC_DIFFIE_HELLMAN:
			// TODO SHA256withECDSA is default but should be configurable
			signatureAndHashAlgorithm = new SignatureAndHashAlgorithm(HashAlgorithm.SHA256, SignatureAlgorithm.ECDSA);
			int namedCurveId = negotiateNamedCurve(message.getSupportedEllipticCurvesExtension());
			ecdhe = new ECDHECryptography(namedCurveId);
			serverKeyExchange = new ECDHServerKeyExchange(signatureAndHashAlgorithm, ecdhe, privateKey, clientRandom, serverRandom,
					namedCurveId, session.getPeer());
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
	 * The <em>SSL_NULL_WITH_NULL_NULL</em> cipher suite is <em>never</em>
	 * negotiated as mandated by <a href="http://tools.ietf.org/html/rfc5246#appendix-A.5">
	 * RFC 5246 Appendix A.5</a>
	 * 
	 * @param cipherSuites
	 *            the list of cipher suites the client supports
	 *            (ordered by preference)
	 * @return The single cipher suite selected by the server from the list
	 *         which will be used after handshake completion.
	 * @throws HandshakeException
	 *             if this server does not support any of
	 *             the cipher suites proposed by the client
	 */
	private CipherSuite negotiateCipherSuite(List<CipherSuite> cipherSuites) throws HandshakeException {
		for (CipherSuite cipherSuite : cipherSuites) {
			// NEVER negotiate NULL cipher suite
			if (cipherSuite != CipherSuite.TLS_NULL_WITH_NULL_NULL &&
					supportedCipherSuites.contains(cipherSuite)) {
				return cipherSuite;
			}
		}
		// if none of the client's proposed cipher suites matches throw exception
		AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, session.getPeer());
		throw new HandshakeException("Client proposed unsupported cipher suites only", alert);
	}

	/**
	 * Chooses a elliptic curve from the client's supported list.
	 * 
	 * @param extension
	 *            the supported elliptic curves extension.
	 * @return the chosen elliptic curve identifier.
	 * @throws HandshakeException
	 *             if no extension present in the ClientHello.
	 */
	private int negotiateNamedCurve(SupportedEllipticCurvesExtension extension) throws HandshakeException {
		if (extension != null) {
			for (Integer curveID : extension.getEllipticCurveList()) {
				// choose first proposal which is supported
				if (ECDHServerKeyExchange.NAMED_CURVE_PARAMETERS.get(curveID) != null) {
					return curveID;
				}
			}
		} else {
			// extension was not present in ClientHello, we can't continue the handshake
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, session.getPeer());
			throw new HandshakeException("The client did not provide the supported elliptic curves extension although ECC cipher suite chosen.", alert);
		}
		AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, session.getPeer());
		throw new HandshakeException("No proposed elliptic curve supported.", alert);

	}
	
	/**
	 * Chooses the certificate type which will be used in the rest of the
	 * handshake.
	 * 
	 * @param extension
	 *            the certificate types preferred by the client
	 * @param supportedTypes
	 *            the certificate types supported by this server
	 * @return the certificate type selected (and supported) by this server
	 * @throws HandshakeException
	 *             if none of the client's preferred types is supported by this
	 *             server
	 */
	private CertificateType negotiateCertificateType(
			CertificateTypeExtension extension,
			List<CertificateType> supportedTypes) throws HandshakeException {
		for (CertificateType preferredType : extension.getCertificateTypes()) {
			if (supportedTypes.contains(preferredType)) {
				return preferredType;
			}
		}
		throw new HandshakeException("No supported certificate type found",
				new AlertMessage(AlertLevel.FATAL, AlertDescription.UNSUPPORTED_CERTIFICATE, session.getPeer()));

	}	

}
