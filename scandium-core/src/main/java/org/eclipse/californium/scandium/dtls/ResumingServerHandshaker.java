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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - small improvements
 *    Kai Hudalla (Bosch Software Innovations GmbH) - notify SessionListener about start and completion
 *                                                    of handshake
 *    Kai Hudalla (Bosch Software Innovations GmbH) - consolidate and fix record buffering and message re-assembly
 *    Kai Hudalla (Bosch Software Innovations GmbH) - replace Handshaker's compressionMethod and cipherSuite
 *                                                    properties with corresponding properties in DTLSSession
 *    Kai Hudalla (Bosch Software Innovations GmbH) - derive max fragment length from network MTU
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use SessionListener to trigger sending of pending
 *                                                    APPLICATION messages
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - add dtls flight number
 *    Achim Kraus (Bosch Software Innovations GmbH) - adjust dtls flight number
 *                                                    for short resumption
 *    Achim Kraus (Bosch Software Innovations GmbH) - redesign DTLSFlight and RecordLayer
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;

import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The resuming server handshaker executes an abbreviated handshake when
 * receiving a ClientHello with a set session identifier.
 * 
 * It checks whether such a session still exists and if so,
 * generates the new keys from the previously established master secret.
 * The message flow is depicted in <a
 * href="http://tools.ietf.org/html/rfc5246#section-7.3">Figure 2</a>.
 */
public class ResumingServerHandshaker extends ServerHandshaker {

	private static final Logger LOGGER = LoggerFactory.getLogger(ResumingServerHandshaker.class.getName());

	// Members ////////////////////////////////////////////////////////

	/** The handshake hash used in the Finished messages. */
	private byte[] handshakeHash;

	// Constructor ////////////////////////////////////////////////////

	/**
	 * Creates a new handshaker for resuming an existing session with a client.
	 * 
	 * @param sequenceNumber
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
	 *            the DTLS configuration parameters to use for the handshake.
	 * @param maxTransmissionUnit
	 *            the MTU value reported by the network interface the record layer is bound to.
	 * @throws IllegalArgumentException
	 *            if the given session does not contain an identifier.
	 * @throws IllegalStateException
	 *            if the message digest required for computing the FINISHED message hash cannot be instantiated.
	 * @throws NullPointerException
	 *            if session, recordLayer or config is <code>null</code>
	 */
	public ResumingServerHandshaker(int sequenceNumber, DTLSSession session, RecordLayer recordLayer, Connection connection, DtlsConnectorConfig config, int maxTransmissionUnit) {
		super(sequenceNumber, session, recordLayer, connection, config, maxTransmissionUnit);
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	protected void doProcessMessage(DTLSMessage message) throws HandshakeException, GeneralSecurityException {

		// log record now (even if message is still encrypted) in case an Exception
		// is thrown during processing
		if (LOGGER.isDebugEnabled()) {
			StringBuilder msg = new StringBuilder();
			msg.append("Processing {} message from peer [{}]");
			if (LOGGER.isTraceEnabled()) {
				msg.append(":").append(StringUtil.lineSeparator()).append(message);
			}
			LOGGER.debug(msg.toString(), message.getContentType(), message.getPeer());
		}

		switch (message.getContentType()) {
		case ALERT:
			break;

		case CHANGE_CIPHER_SPEC:
			setCurrentReadState();
			LOGGER.debug("Processed {} message from peer [{}]", message.getContentType(),
					message.getPeer());
			break;

		case HANDSHAKE:
			HandshakeMessage handshakeMsg = (HandshakeMessage) message;
			switch (handshakeMsg.getMessageType()) {
			case CLIENT_HELLO:
				receivedClientHello((ClientHello) handshakeMsg);
				expectChangeCipherSpecMessage();
				break;

			case FINISHED:
				receivedClientFinished((Finished) handshakeMsg);
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
	 * The server generates new keys from the old master secret and sends
	 * ChangeCipherSpec and Finished message. The ClientHello contains a fresh
	 * random value which will be needed to generate the new keys.
	 * 
	 * @param clientHello
	 *            the client's hello message.
	 * @throws HandshakeException if the server's handshake records cannot be created
	 */
	private void receivedClientHello(ClientHello clientHello) throws HandshakeException {

		handshakeStarted();
		if (!clientHello.getCipherSuites().contains(session.getCipherSuite())) {
			throw new HandshakeException(
					"Client wants to change cipher suite in resumed session",
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.ILLEGAL_PARAMETER,
							clientHello.getPeer()));
		} else if (!clientHello.getCompressionMethods().contains(session.getCompressionMethod())) {
			throw new HandshakeException(
					"Client wants to change compression method in resumed session",
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.ILLEGAL_PARAMETER,
							clientHello.getPeer()));
		} else {
			clientRandom = clientHello.getRandom();
			serverRandom = new Random(new SecureRandom());

			HelloExtensions serverHelloExtensions = new HelloExtensions();
			processHelloExtensions(clientHello, serverHelloExtensions);

			initMessageDigest();

			flightNumber += 2;
			DTLSFlight flight = new DTLSFlight(getSession(), flightNumber);
			md.update(clientHello.getRawMessage());

			ServerHello serverHello = new ServerHello(clientHello.getClientVersion(), serverRandom, session.getSessionIdentifier(),
					session.getCipherSuite(), session.getCompressionMethod(), serverHelloExtensions, clientHello.getPeer());
			wrapMessage(flight, serverHello);
			md.update(serverHello.toByteArray());

			calculateKeys(session.getMasterSecret());

			ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage(clientHello.getPeer());
			wrapMessage(flight, changeCipherSpecMessage);
			setCurrentWriteState();

			MessageDigest mdWithServerFinished = null;
			try {
				mdWithServerFinished = (MessageDigest) md.clone();
			} catch (CloneNotSupportedException e) {
				throw new HandshakeException(
						"Cannot create FINISHED message hash",
						new AlertMessage(
								AlertLevel.FATAL,
								AlertDescription.INTERNAL_ERROR,
								clientHello.getPeer()));
			}

			handshakeHash = md.digest();
			String prfMacName = session.getCipherSuite().getPseudoRandomFunctionMacName();
			Finished finished = new Finished(prfMacName, session.getMasterSecret(), false, handshakeHash, clientHello.getPeer());
			wrapMessage(flight, finished);

			mdWithServerFinished.update(finished.toByteArray());
			handshakeHash = mdWithServerFinished.digest();
			sendFlight(flight);
		}
	}

	/**
	 * Verifies the client's Finished message. If valid, encrypted application
	 * data can be sent, otherwise an Alert must be sent.
	 * 
	 * @param message
	 *            the client's Finished message.
	 * @throws HandshakeException
	 *             if the client's Finished message can not be verified.
	 */
	private void receivedClientFinished(Finished message) throws HandshakeException {
		String prfMacName = session.getCipherSuite().getPseudoRandomFunctionMacName();
		message.verifyData(prfMacName, session.getMasterSecret(), true, handshakeHash);
		sessionEstablished();
		handshakeCompleted();
	}
}
