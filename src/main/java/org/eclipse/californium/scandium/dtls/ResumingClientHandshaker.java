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
import java.security.SecureRandom;
import java.security.cert.Certificate;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.scandium.DTLSConnectorConfig;
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
	
	// Constructor ////////////////////////////////////////////////////

	public ResumingClientHandshaker(InetSocketAddress endpointAddress, RawData message, DTLSSession session, Certificate[] rootCerts, DTLSConnectorConfig config) {
		super(endpointAddress, message, session, rootCerts, config);
	}
	
	// Methods ////////////////////////////////////////////////////////

	@Override
	public synchronized DTLSFlight processMessage(Record record) throws HandshakeException {
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

			case SERVER_HELLO:
				// TODO if server's session ID does not match, make full handshake
				serverHello = (ServerHello) fragment;
				break;

			case FINISHED:
				flight = receivedServerFinished((Finished) fragment);
				break;

			default:
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE);
				throw new HandshakeException("Client received unexpected resuming handshake message:\n" + fragment.toString(), alert);
			}
			break;

		default:
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE);
			throw new HandshakeException("Client received not supported record:\n" + record.toString(), alert);
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
		LOGGER.fine("DTLS Message processed (" + endpointAddress.toString() + "):\n" + record.toString());
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
	 * @throws HandshakeException
	 *             if the server's Finished message could not be verified.
	 */
	private DTLSFlight receivedServerFinished(Finished message) throws HandshakeException {
		if (lastFlight != null) {
			// the server retransmitted its last flight, therefore retransmit
			// this last flight
			return null;
		}
		DTLSFlight flight = new DTLSFlight();

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

		ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage();
		flight.addMessage(wrapMessage(changeCipherSpecMessage));
		setCurrentWriteState();
		session.incrementWriteEpoch();

		handshakeHash = mdWithServerFinish.digest();
		Finished finished = new Finished(getMasterSecret(), isClient, handshakeHash);
		flight.addMessage(wrapMessage(finished));

		state = HandshakeType.FINISHED.getCode();
		session.setActive(true);

		flight.setRetransmissionNeeded(false);
		// store, if we need to retransmit this flight, see
		// http://tools.ietf.org/html/rfc6347#section-4.2.4
		lastFlight = flight;
		return flight;
	}

	@Override
	public DTLSFlight getStartHandshakeMessage() {
		ClientHello message = new ClientHello(new ProtocolVersion(), new SecureRandom(), session);

		message.addCipherSuite(session.getCipherSuite());
		message.addCompressionMethod(session.getCompressionMethod());

		state = message.getMessageType().getCode();
		clientHello = message;

		DTLSFlight flight = new DTLSFlight();
		flight.addMessage(wrapMessage(message));

		return flight;
	}

}
