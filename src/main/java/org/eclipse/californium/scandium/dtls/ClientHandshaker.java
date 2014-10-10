/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.logging.Level;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.scandium.DTLSConnectorConfig;
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

	// Members ////////////////////////////////////////////////////////

	private ProtocolVersion maxProtocolVersion = new ProtocolVersion();

	/** The server's public key from its certificate */
	private PublicKey serverPublicKey;

	/** The server's ephemeral public key, used for key agreement */
	private ECPublicKey ephemeralServerPublicKey;

	/** The client's hello handshake message. Store it, to add the cookie in the second flight. */
	protected ClientHello clientHello = null;

	/** the preferred cipher suite, to be placed first in the advertised list of supported chiper suite */
	private final CipherSuite preferredCipherSuite;

	/** whether the certificate message should only contain the peer's public key or the full X.509 certificate */
	private final boolean useRawPublicKey;
	
	/*
	 * Store all the message which can possibly be sent by the server.
	 * We need these to compute the handshake hash.
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
	 * 
	 * 
	 * @param endpointAddress
	 *            the endpoint address
	 * @param message
	 *            the message
	 * @param session
	 *            the session
	 */
	public ClientHandshaker(InetSocketAddress endpointAddress, RawData message, DTLSSession session,Certificate[] rootCerts, DTLSConnectorConfig config) {
		super(endpointAddress, true, session,rootCerts);
		this.message = message;
		this.privateKey = config.privateKey;
		this.certificates = config.certChain;
		this.pskStore = config.pskStore;
		this.useRawPublicKey = config.sendRawKey;
		this.preferredCipherSuite = config.preferredCipherSuite;
	}

	// Methods ////////////////////////////////////////////////////////
	

	@Override
	public synchronized DTLSFlight processMessage(Record record) throws HandshakeException {
		DTLSFlight flight = null;
		if (!processMessageNext(record)) {
			return null;
		}

		switch (record.getType()) {
		case ALERT:
			record.getFragment();
			// TODO react according to alert message: close connection or abort
			break;

		case CHANGE_CIPHER_SPEC:
			// TODO check, if all expected messages already received
			record.getFragment();
			setCurrentReadState();
			session.incrementReadEpoch();
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
			case HELLO_REQUEST:
				flight = receivedHelloRequest((HelloRequest) fragment);
				break;

			case HELLO_VERIFY_REQUEST:
				flight = receivedHelloVerifyRequest((HelloVerifyRequest) fragment);
				break;

			case SERVER_HELLO:
				receivedServerHello((ServerHello) fragment);
				break;

			case CERTIFICATE:
				receivedServerCertificate((CertificateMessage) fragment);
				break;

			case SERVER_KEY_EXCHANGE:

				switch (keyExchange) {
				case EC_DIFFIE_HELLMAN:
					receivedServerKeyExchange((ECDHServerKeyExchange) fragment);
					break;

				case PSK:
					serverKeyExchange = (PSKServerKeyExchange) fragment;
					break;
					
				case NULL:
					LOGGER.info("Received unexpected ServerKeyExchange message in NULL key exchange mode.");
					break;

				default:
					AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE);
					throw new HandshakeException("Not supported server key exchange algorithm: " + keyExchange, alert);
				}
				break;

			case CERTIFICATE_REQUEST:
				// save for later, will be handled by server hello done
				certificateRequest = (CertificateRequest) fragment;
				break;

			case SERVER_HELLO_DONE:
				flight = receivedServerHelloDone((ServerHelloDone) fragment);
				break;

			case FINISHED:
				flight = receivedServerFinished((Finished) fragment);
				break;

			default:
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE);
				throw new HandshakeException("Client received unexpected handshake message:\n" + fragment.toString(), alert);
			}
			break;

		default:
			AlertMessage alertMessage = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE);
			throw new HandshakeException("Client received not supported record:\n" + record.toString(), alertMessage);
		}
		if (flight == null) {
			Record nextMessage = null;
			// check queued message, if it is now their turn
			for (Record queuedMessage : queuedMessages) {
				if (processMessageNext(queuedMessage)) {
					// queuedMessages.remove(queuedMessage);
					nextMessage = queuedMessage;
				}
			}
			if (nextMessage != null) {
				flight = processMessage(nextMessage);
			}
		}
		if (LOGGER.isLoggable(Level.FINE)) {
		    LOGGER.fine("DTLS Message processed (" + endpointAddress.toString() + "):\n" + record.toString());
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
	 */
	private DTLSFlight receivedServerFinished(Finished message) throws HandshakeException {
		DTLSFlight flight = new DTLSFlight();

		message.verifyData(getMasterSecret(), false, handshakeHash);

		state = HandshakeType.FINISHED.getCode();
		session.setActive(true);

		// received server's Finished message, now able to send encrypted
		// message
		ApplicationMessage applicationMessage = new ApplicationMessage(this.message.getBytes());

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
	 */
	private DTLSFlight receivedHelloRequest(HelloRequest message) {
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
	 * @return {@link ClientHello} with server's {@link Cookie} set.
	 */
	private DTLSFlight receivedHelloVerifyRequest(HelloVerifyRequest message) {

		clientHello.setCookie(message.getCookie());
		// update the length (cookie added)
		clientHello.setFragmentLength(clientHello.getMessageLength());

		DTLSFlight flight = new DTLSFlight();
		flight.addMessage(wrapMessage(clientHello));

		return flight;
	}

	/**
	 * Stores the negotiated security parameters.
	 * 
	 * @param message
	 *            the {@link ServerHello} message.
	 */
	private void receivedServerHello(ServerHello message) {
		if (serverHello != null && (message.getMessageSeq() == serverHello.getMessageSeq())) {
			// received duplicate version (retransmission), discard it
			return;
		}
		serverHello = message;

		// store the negotiated values
		usedProtocol = message.getServerVersion();
		serverRandom = message.getRandom();
		session.setSessionIdentifier(message.getSessionId());
		setCipherSuite(message.getCipherSuite());
		setCompressionMethod(message.getCompressionMethod());
		
		ClientCertificateTypeExtension clientCertType = serverHello.getClientCertificateTypeExtension();
		// check what the server indicates for the certificate's type
		if (clientCertType != null && clientCertType.getCertificateTypes().get(0) == CertificateType.RAW_PUBLIC_KEY) {
			session.setReceiveRawPublicKey(true);
		}

		ServerCertificateTypeExtension serverCertType = serverHello.getServerCertificateTypeExtension();
		// check what the client should send
		if (serverCertType != null && serverCertType.getCertificateTypes().get(0) == CertificateType.RAW_PUBLIC_KEY) {
			session.setSendRawPublicKey(true);
		}
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
		serverPublicKey = serverCertificate.getPublicKey();
		serverCertificate.verifyCertificate(rootCertificates);
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
	 * @throws HandshakeException if the message can't be verified.
	 */
	private void receivedServerKeyExchange(ECDHServerKeyExchange message) throws HandshakeException {
		if (serverKeyExchange != null && (serverKeyExchange.getMessageSeq() == message.getMessageSeq())) {
			// discard duplicate message
			return;
		}

		serverKeyExchange = message;
		message.verifySignature(serverPublicKey, clientRandom, serverRandom);
		
		// get the curve parameter spec by the named curve id
		ECParameterSpec params = ECDHServerKeyExchange.NAMED_CURVE_PARAMETERS.get(message.getCurveId());
		if (params == null) {
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE);
			throw new HandshakeException("Server used unsupported elliptic curve for ECDH", alert);
		}
		
		ephemeralServerPublicKey = message.getPublicKey(params);
		ecdhe = new ECDHECryptography(ephemeralServerPublicKey.getParams());
	}

	/**
	 * The ServerHelloDone message is sent by the server to indicate the end of
	 * the ServerHello and associated messages. The client prepares all
	 * necessary messages (depending on server's previous flight) and returns
	 * the next flight.
	 * 
	 * @return the client's next flight to be sent.
	 * @throws HandshakeException
	 */
	private DTLSFlight receivedServerHelloDone(ServerHelloDone message) throws HandshakeException {
		DTLSFlight flight = new DTLSFlight();
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
		ClientKeyExchange clientKeyExchange = null;
		CertificateVerify certificateVerify = null;

		/*
		 * First, if required by server, send Certificate.
		 */
		if (certificateRequest != null) {
			// TODO load the client's certificate according to the allowed
			// parameters in the CertificateRequest
			clientCertificate = new CertificateMessage(certificates, session.sendRawPublicKey());

			flight.addMessage(wrapMessage(clientCertificate));
		}

		/*
		 * Second, send ClientKeyExchange as specified by the key exchange
		 * algorithm.
		 */
		byte[] premasterSecret;
		switch (keyExchange) {
		case EC_DIFFIE_HELLMAN:
			clientKeyExchange = new ECDHClientKeyExchange(ecdhe.getPublicKey());
			premasterSecret = ecdhe.getSecret(ephemeralServerPublicKey).getEncoded();

			generateKeys(premasterSecret);

			break;

		case PSK:
			String identity = pskStore.getIdentity(endpointAddress);
			if (identity == null) {
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE);
				throw new HandshakeException("No Identity found for peer: "	+ endpointAddress, alert);
			}
			session.setPskIdentity(identity);

			byte[] psk = pskStore.getKey(identity);
			if (psk == null) {
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL,	AlertDescription.HANDSHAKE_FAILURE);
				throw new HandshakeException("No preshared secret found for identity: " + identity, alert);
			}
			clientKeyExchange = new PSKClientKeyExchange(psk);
			if (LOGGER.isLoggable(Level.INFO)) {
				LOGGER.info("Using PSK identity: " + identity);
			}
			premasterSecret = generatePremasterSecretFromPSK(psk);
			generateKeys(premasterSecret);

			break;

		case NULL:
			clientKeyExchange = new NULLClientKeyExchange();

			// We assume, that the premaster secret is empty
			generateKeys(new byte[] {});
			break;

		default:
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE);
			throw new HandshakeException("Unknown key exchange algorithm: " + keyExchange, alert);
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
			certificateVerify = new CertificateVerify(signatureAndHashAlgorithm, privateKey, handshakeMessages);
			
			flight.addMessage(wrapMessage(certificateVerify));
		}

		/*
		 * Fourth, send ChangeCipherSpec
		 */
		ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage();
		flight.addMessage(wrapMessage(changeCipherSpecMessage));
		setCurrentWriteState();
		session.incrementWriteEpoch();

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
			Finished finished = new Finished(getMasterSecret(), isClient, handshakeHash);
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
	public DTLSFlight getStartHandshakeMessage() {
		ClientHello message = new ClientHello(maxProtocolVersion, new SecureRandom(), useRawPublicKey);

		// store client random for later calculations
		clientRandom = message.getRandom();

		// the mandatory to implement ciphersuites, the preferred one should be first in the list
		if (preferredCipherSuite == CipherSuite.TLS_PSK_WITH_AES_128_CCM_8) {
			message.addCipherSuite(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8);
			message.addCipherSuite(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
		} else {
			message.addCipherSuite(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
			message.addCipherSuite(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8);
		}
		
		message.addCompressionMethod(CompressionMethod.NULL);

		// set current state
		state = message.getMessageType().getCode();

		// store for later calculations
		clientHello = message;
		DTLSFlight flight = new DTLSFlight();
		flight.addMessage(wrapMessage(message));

		return flight;
	}

}
