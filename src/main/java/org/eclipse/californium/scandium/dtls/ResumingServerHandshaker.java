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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - notify SessionListener about start and completion
 *                                                    of handshake
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

	public ResumingServerHandshaker(DTLSSession session, SessionListener sessionListener, DtlsConnectorConfig config)
			throws HandshakeException {
		super(session, sessionListener, config);
		setSessionToResume(session);
	}
	
	// Methods ////////////////////////////////////////////////////////
	
	/**
	 * Resets the state of a session, such that it can be used to resume it.
	 * 
	 * @param session
	 *            the session to be resumed.
	 */
	private void setSessionToResume(DTLSSession session) {
		session.setActive(false);
		session.setWriteEpoch(0);
		session.setReadEpoch(0);
	}
	
	@Override
	protected synchronized DTLSFlight doProcessMessage(Record record) throws HandshakeException, GeneralSecurityException {
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
			case CLIENT_HELLO:
				flight = receivedClientHello((ClientHello) fragment);
				break;

			case FINISHED:
				receivedClientFinished((Finished) fragment);
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
	 * The server generates new keys from the old master secret and sends
	 * ChangeCipherSpec and Finished message. The ClientHello contains a fresh
	 * random value which will be needed to generate the new keys.
	 * 
	 * @param message
	 *            the client's hello message.
	 * @return the server's last flight.
	 * @throws HandshakeException if the server's handshake records cannot be created
	 */
	private DTLSFlight receivedClientHello(ClientHello message) throws HandshakeException {

		handshakeStarted();
		DTLSFlight flight = new DTLSFlight(getSession());
		
		md.update(message.toByteArray());

		clientRandom = message.getRandom();
		serverRandom = new Random(new SecureRandom());

		ServerHello serverHello = new ServerHello(message.getClientVersion(), serverRandom, session.getSessionIdentifier(),
				session.getCipherSuite(), session.getCompressionMethod(), null, session.getPeer());
		flight.addMessage(wrapMessage(serverHello));
		md.update(serverHello.toByteArray());

		generateKeys(session.getMasterSecret());

		ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage(session.getPeer());
		flight.addMessage(wrapMessage(changeCipherSpecMessage));
		setCurrentWriteState();

		MessageDigest mdWithServerFinished = null;
		try {
			mdWithServerFinished = (MessageDigest) md.clone();
		} catch (Exception e) {
			LOGGER.severe("Clone not supported.");
			e.printStackTrace();
		}

		handshakeHash = md.digest();
		Finished finished = new Finished(getMasterSecret(), isClient, handshakeHash, session.getPeer());
		flight.addMessage(wrapMessage(finished));

		mdWithServerFinished.update(finished.toByteArray());
		handshakeHash = mdWithServerFinished.digest();
			
		return flight;
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

		message.verifyData(getMasterSecret(), false, handshakeHash);
		sessionEstablished();
	}

}
