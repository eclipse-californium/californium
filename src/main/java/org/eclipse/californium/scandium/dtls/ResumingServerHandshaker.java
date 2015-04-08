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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.logging.Level;

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
	
	// Members ////////////////////////////////////////////////////////
	
	/** The handshake hash used in the Finished messages. */
	private byte[] handshakeHash;
	
	// Constructor ////////////////////////////////////////////////////

	public ResumingServerHandshaker(DTLSSession session, DtlsConnectorConfig config) throws HandshakeException {
		super(session, null, config);
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
	protected synchronized DTLSFlight doProcessMessage(Record record) throws HandshakeException {
		DTLSFlight flight = null;

		if (!processMessageNext(record)) {
			return null;
		}

		switch (record.getType()) {
		case ALERT:
			record.getFragment();
			break;

		case CHANGE_CIPHER_SPEC:
			record.getFragment();
			setCurrentReadState();
			session.incrementReadEpoch();
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
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE);
				throw new HandshakeException("Server received unexpected resuming handshake message:\n" + fragment.toString(), alert);
			}

			break;

		default:
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE);
			throw new HandshakeException("Server received not supported record:\n" + record.toString(), alert);
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
		LOGGER.log(Level.FINE, "Processed DTLS record from peer [{0}]:\n{1}", new Object[]{getPeerAddress(), record});
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
	 */
	private DTLSFlight receivedClientHello(ClientHello message) {

		DTLSFlight flight = new DTLSFlight(getSession());
		
		md.update(message.toByteArray());

		clientRandom = message.getRandom();
		serverRandom = new Random(new SecureRandom());

		ServerHello serverHello = new ServerHello(message.getClientVersion(), serverRandom, session.getSessionIdentifier(), session.getCipherSuite(), session.getCompressionMethod(), null);
		flight.addMessage(wrapMessage(serverHello));
		md.update(serverHello.toByteArray());

		generateKeys(session.getMasterSecret());

		ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage();
		flight.addMessage(wrapMessage(changeCipherSpecMessage));
		setCurrentWriteState();
		session.incrementWriteEpoch();

		MessageDigest mdWithServerFinished = null;
		try {
			mdWithServerFinished = (MessageDigest) md.clone();
		} catch (Exception e) {
			LOGGER.severe("Clone not supported.");
			e.printStackTrace();
		}

		handshakeHash = md.digest();
		Finished finished = new Finished(getMasterSecret(), isClient, handshakeHash);
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
	}

}
