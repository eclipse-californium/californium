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
 *    Kai Hudalla (Bosch Software Innovtions GmbH) - small improvements
 *    Kai Hudalla (Bosch Software Innovations GmbH) - notify SessionListener about start and completion
 *                                                    of handshake
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;


/**
 * The resuming client handshaker executes a abbreviated handshake by adding a
 * valid session identifier into its ClientHello message. The message flow is
 * depicted in <a href="http://tools.ietf.org/html/rfc5246#section-7.3">Figure
 * 2</a>. The new keys will be generated from the master secret established from a
 * previous full handshake.
 */
public class ResumingClientHandshaker extends ClientHandshaker {
	
	private static final Logger LOGGER = Logger.getLogger(ResumingClientHandshaker.class.getName());
	
	// Constructor ////////////////////////////////////////////////////

	/**
	 * Creates a new handshaker for resuming an existing session with a server.
	 * 
	 * @param message the application layer message to send once the session has
	 *            been resumed
	 * @param session the session to resume
	 * @param sessionListener
	 *            the listener to notify about the session's life-cycle events
	 * @param config the DTLS configuration parameters to use for the handshake
	 * @throws HandshakeException if the handshaker could not be initialized
	 * @throws IllegalArgumentException if the given session does not contain an identifier
	 */
	public ResumingClientHandshaker(RawData message, DTLSSession session, SessionListener sessionListener, DtlsConnectorConfig config)
			throws HandshakeException {
		super(message, session, sessionListener, config);
		if (session.getSessionIdentifier() == null) {
			throw new IllegalArgumentException("Session must contain the ID of the session to resume");
		}
	}
	
	// Methods ////////////////////////////////////////////////////////

	@Override
	protected synchronized DTLSFlight doProcessMessage(Record record) throws HandshakeException, GeneralSecurityException {
		if (lastFlight != null) {
			// we already sent the last flight, but the client did not receive
			// it, since we received its finished message again, so we
			// retransmit our last flight
			LOGGER.finer("Received server's finished message again, retransmit the last flight.");
			return lastFlight;
		}

		DTLSFlight flight = null;

		if (!processMessageNext(record)) {
			return null;
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
		case ALERT:
			record.getFragment();
			break;

		case CHANGE_CIPHER_SPEC:
			record.getFragment();
			setCurrentReadState();
			LOGGER.log(Level.FINE, "Processed {1} message from peer [{0}]",
					new Object[]{record.getPeerAddress(), record.getType()});
			break;

		case HANDSHAKE:
			HandshakeMessage fragment = (HandshakeMessage) record.getFragment();
			switch (fragment.getMessageType()) {

			case SERVER_HELLO:
				// TODO if server's session ID does not match, make full handshake
				serverHello = (ServerHello) fragment;
				break;

			case FINISHED:
				flight = receivedServerFinished((Finished) fragment);
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
				}
			}
			if (nextMessage != null) {
				flight = processMessage(nextMessage);
			}
		}
		return flight;
	}

	/**
	 * When the client received the server's finished message, it verifies the
	 * finished message and sends the third and last flight of the short
	 * handshake: it contains the ChangeCipherSpec and the Finished message.
	 * 
	 * @param message
	 *            the server's finished message.
	 * @return the last flight of the short handshake.
	 * @throws HandshakeException if the server's FINISHED message could not be
	 *            verified or if the client's handshake messages cannot be created
	 */
	private DTLSFlight receivedServerFinished(Finished message) throws HandshakeException {
		if (lastFlight != null) {
			// the server retransmitted its last flight, therefore retransmit
			// this last flight
			return null;
		}
		DTLSFlight flight = new DTLSFlight(getSession());

		// update the handshake hash
		md.update(clientHello.toByteArray());
		md.update(serverHello.toByteArray());

		MessageDigest mdWithServerFinish = null;
		try {
			// the client's finished verify_data must also contain the server's
			// finished message
			mdWithServerFinish = (MessageDigest) md.clone();
		} catch (Exception e) {
			LOGGER.severe("Clone not supported.");
			e.printStackTrace();
		}
		mdWithServerFinish.update(message.toByteArray());

		// the handshake hash to check the server's verify_data (without the
		// server's finished message included)
		handshakeHash = md.digest();
		message.verifyData(getMasterSecret(), false, handshakeHash);
		
		clientRandom = clientHello.getRandom();
		serverRandom = serverHello.getRandom();
		generateKeys(session.getMasterSecret());

		ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage(session.getPeer());
		flight.addMessage(wrapMessage(changeCipherSpecMessage));
		setCurrentWriteState();

		handshakeHash = mdWithServerFinish.digest();
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

	@Override
	public DTLSFlight getStartHandshakeMessage() throws HandshakeException {
		handshakeStarted();
		ClientHello message = new ClientHello(new ProtocolVersion(), new SecureRandom(), session);

		message.addCipherSuite(session.getCipherSuite());
		message.addCompressionMethod(session.getCompressionMethod());

		state = message.getMessageType().getCode();
		clientHello = message;

		DTLSFlight flight = new DTLSFlight(getSession());
		flight.addMessage(wrapMessage(message));

		return flight;
	}

}
