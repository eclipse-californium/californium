/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;

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

	private static final Logger LOGGER = Logger.getLogger(ResumingServerHandshaker.class.getName());

	// Members ////////////////////////////////////////////////////////

	/** The handshake hash used in the Finished messages. */
	private byte[] handshakeHash;

	// Constructor ////////////////////////////////////////////////////

	public ResumingServerHandshaker(int sequenceNumber, DTLSSession session, RecordLayer recordLayer, SessionListener sessionListener,
			DtlsConnectorConfig config, int maxTransmissionUnit) {
		super(sequenceNumber, session, recordLayer, sessionListener, config, maxTransmissionUnit);
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	protected synchronized void doProcessMessage(DTLSMessage message) throws HandshakeException, GeneralSecurityException {

		// log record now (even if message is still encrypted) in case an Exception
		// is thrown during processing
		if (LOGGER.isLoggable(Level.FINE)) {
			StringBuilder msg = new StringBuilder();
			msg.append(String.format(
					"Processing %s message from peer [%s]",
					message.getContentType(), message.getPeer()));
			if (LOGGER.isLoggable(Level.FINEST)) {
				msg.append(":").append(System.lineSeparator()).append(message);
			}
			LOGGER.fine(msg.toString());
		}

		switch (message.getContentType()) {
		case ALERT:
			break;

		case CHANGE_CIPHER_SPEC:
			setCurrentReadState();
			LOGGER.log(Level.FINE, "Processed {1} message from peer [{0}]",
					new Object[]{message.getPeer(), message.getContentType()});
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
			LOGGER.log(Level.FINE, "Processed {1} message with sequence no [{2}] from peer [{0}]",
					new Object[]{handshakeMsg.getPeer(), handshakeMsg.getMessageType(), handshakeMsg.getMessageSeq()});
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
			DTLSFlight flight = new DTLSFlight(getSession());
			md.update(clientHello.getRawMessage());

			clientRandom = clientHello.getRandom();
			serverRandom = new Random(new SecureRandom());

			ServerHello serverHello = new ServerHello(clientHello.getClientVersion(), serverRandom, session.getSessionIdentifier(),
					session.getCipherSuite(), session.getCompressionMethod(), null, clientHello.getPeer());
			flight.addMessage(wrapMessage(serverHello));
			md.update(serverHello.toByteArray());

			calculateKeys(session.getMasterSecret());

			ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage(clientHello.getPeer());
			flight.addMessage(wrapMessage(changeCipherSpecMessage));
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
			Finished finished = new Finished(session.getMasterSecret(), false, handshakeHash, clientHello.getPeer());
			flight.addMessage(wrapMessage(finished));

			mdWithServerFinished.update(finished.toByteArray());
			handshakeHash = mdWithServerFinished.digest();

			recordLayer.sendFlight(flight);
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
		message.verifyData(session.getMasterSecret(), true, handshakeHash);
		sessionEstablished();
		handshakeCompleted();
	}

//	@Override
//	protected boolean isChangeCipherSpecMessageDue() {
//
//		// in an abbreviated handshake we immediately expect the client's ChangeCipherSpec message
//		return true;
//	}
}
