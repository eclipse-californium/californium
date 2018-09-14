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
 *    Achim Kraus (Bosch Software Innovations GmbH) - don't ignore retransmission of last flight
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix NullPointerException, if ccs is processed 
 *                                                    before the SERVER_HELLO.
 *                                                    move expectChangeCipherSpecMessage after
 *                                                    receiving SERVER_HELLO.
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
 * The resuming client handshaker executes a abbreviated handshake by adding a
 * valid session identifier into its ClientHello message. The message flow is
 * depicted in <a href="http://tools.ietf.org/html/rfc5246#section-7.3">Figure
 * 2</a>. The new keys will be generated from the master secret established from a
 * previous full handshake.
 */
public class ResumingClientHandshaker extends ClientHandshaker {
	
	private static final Logger LOGGER = Logger.getLogger(ResumingClientHandshaker.class.getName());

	// flag to indicate if we must do a full handshake or an abbreviated one
	private boolean fullHandshake = false;

	/**
	 * The last flight that is sent during this handshake, will not be
	 * retransmitted unless the peer retransmits its last flight.
	 */
	private DTLSFlight lastFlight;

	// Constructor ////////////////////////////////////////////////////

	/**
	 * Creates a new handshaker for resuming an existing session with a server.
	 * 
	 * @param session
	 *            the session to resume.
	 * @param recordLayer
	 *            the object to use for sending flights to the peer.
	 * @param sessionListener
	 *            the listener to notify about the session's life-cycle events.
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
	public ResumingClientHandshaker(DTLSSession session, RecordLayer recordLayer, SessionListener sessionListener,
			DtlsConnectorConfig config, int maxTransmissionUnit) {
		super(session, recordLayer, sessionListener, config, maxTransmissionUnit);
		if (session.getSessionIdentifier() == null) {
			throw new IllegalArgumentException("Session must contain the ID of the session to resume");
		}
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	protected synchronized void doProcessMessage(DTLSMessage message) throws HandshakeException, GeneralSecurityException {
		if (fullHandshake){
			// handshake resumption was refused by the server
			// we do a full handshake
			super.doProcessMessage(message);
			return;
		}

		if (lastFlight != null) {
			// we already sent the last flight, but the server does not seem to have received
			// it since it sent its FINISHED message again, so we simply retransmit our last flight
			LOGGER.log(
				Level.FINER,
				"Received server's [{0}] FINISHED message again, retransmitting last flight...",
				message.getPeer());
			lastFlight.incrementTries();
			lastFlight.setNewSequenceNumbers();
			recordLayer.sendFlight(lastFlight);
			return;
		}

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

		case CHANGE_CIPHER_SPEC:
			calculateKeys(session.getMasterSecret());
			setCurrentReadState();
			LOGGER.log(Level.FINE, "Processed {1} message from peer [{0}]",
					new Object[]{message.getPeer(), message.getContentType()});
			break;

		case HANDSHAKE:
			HandshakeMessage handshakeMsg = (HandshakeMessage) message;
			switch (handshakeMsg.getMessageType()) {

			case HELLO_VERIFY_REQUEST:
				receivedHelloVerifyRequest((HelloVerifyRequest) message);
				break;

			case SERVER_HELLO:
				ServerHello serverHello = (ServerHello) message;
				if (!session.getSessionIdentifier().equals(serverHello.getSessionId()))
				{
					LOGGER.log(
							Level.FINER,
							"Server [{0}] refuses to resume session [{1}], performing full handshake instead...",
							new Object[]{serverHello.getPeer(), session.getSessionIdentifier()});
					// Server refuse to resume the session, go for a full handshake
					fullHandshake  = true;
					super.receivedServerHello(serverHello);
				} else if (!serverHello.getCompressionMethod().equals(session.getCompressionMethod())) {
					throw new HandshakeException(
							"Server wants to change compression method in resumed session",
							new AlertMessage(
									AlertLevel.FATAL,
									AlertDescription.ILLEGAL_PARAMETER,
									serverHello.getPeer()));
				} else if (!serverHello.getCipherSuite().equals(session.getCipherSuite())) {
					throw new HandshakeException(
							"Server wants to change cipher suite in resumed session",
							new AlertMessage(
									AlertLevel.FATAL,
									AlertDescription.ILLEGAL_PARAMETER,
									serverHello.getPeer()));
				} else {
					this.serverHello = serverHello;
					serverRandom = serverHello.getRandom();
					expectChangeCipherSpecMessage();
				}
				break;

			case FINISHED:
				receivedServerFinished((Finished) handshakeMsg);
				break;

			default:
				throw new HandshakeException(
						String.format("Received unexpected handshake message [%s] from peer %s", handshakeMsg.getMessageType(), handshakeMsg.getPeer()),
						new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE, handshakeMsg.getPeer()));
			}

			if (lastFlight == null) {
				// only increment for ongoing handshake flights, not for the last flight!
				// not ignore a server FINISHED retransmission caused by lost client FINISHED
				incrementNextReceiveSeq();
			}
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
	 * When the client received the server's finished message, it verifies the
	 * finished message and sends the third and last flight of the short
	 * handshake: it contains the ChangeCipherSpec and the Finished message.
	 * 
	 * @param message
	 *            the server's finished message.
	 * @throws HandshakeException if the server's FINISHED message could not be
	 *            verified or if the client's handshake messages cannot be created
	 */
	private void receivedServerFinished(Finished message) throws HandshakeException {
		if (lastFlight != null) {
			// the server retransmitted its last flight, therefore retransmit
			// this last flight
			return;
		}
		DTLSFlight flight = new DTLSFlight(getSession());

		// update the handshake hash
		md.update(clientHello.toByteArray());
		md.update(serverHello.getRawMessage());

		MessageDigest mdWithServerFinish = null;
		try {
			// the client's finished verify_data must also contain the server's
			// finished message
			mdWithServerFinish = (MessageDigest) md.clone();
		} catch (CloneNotSupportedException e) {
			throw new HandshakeException(
					"Cannot create FINISHED message hash",
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.INTERNAL_ERROR,
							message.getPeer()));
		}
		mdWithServerFinish.update(message.getRawMessage());

		// the handshake hash to check the server's verify_data (without the
		// server's finished message included)
		handshakeHash = md.digest();
		message.verifyData(session.getMasterSecret(), false, handshakeHash);
		
		ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage(message.getPeer());
		flight.addMessage(wrapMessage(changeCipherSpecMessage));
		setCurrentWriteState();

		handshakeHash = mdWithServerFinish.digest();
		Finished finished = new Finished(session.getMasterSecret(), isClient, handshakeHash, message.getPeer());
		flight.addMessage(wrapMessage(finished));
		state = HandshakeType.FINISHED.getCode();

		flight.setRetransmissionNeeded(false);
		// store, if we need to retransmit this flight, see
		// http://tools.ietf.org/html/rfc6347#section-4.2.4
		lastFlight = flight;
		recordLayer.sendFlight(flight);
		sessionEstablished();
	}

	@Override
	public void startHandshake() throws HandshakeException {
		handshakeStarted();
		ClientHello message = new ClientHello(new ProtocolVersion(), new SecureRandom(), session,
				supportedClientCertificateTypes, supportedServerCertificateTypes);

		clientRandom = message.getRandom();

		message.addCipherSuite(session.getCipherSuite());
		message.addCompressionMethod(session.getCompressionMethod());
		if (maxFragmentLengthCode != null) {
			MaxFragmentLengthExtension ext = new MaxFragmentLengthExtension(maxFragmentLengthCode); 
			message.addExtension(ext);
			LOGGER.log(
					Level.FINE,
					"Indicating max. fragment length [{0}] to server [{1}]",
					new Object[]{maxFragmentLengthCode, getPeerAddress()});
		}

		state = message.getMessageType().getCode();
		clientHello = message;

		DTLSFlight flight = new DTLSFlight(getSession());
		flight.addMessage(wrapMessage(message));

		recordLayer.sendFlight(flight);
	}

//	@Override
//	protected boolean isChangeCipherSpecMessageDue() {
//
//		// in an abbreviated handshake we immediately expect the server's ChangeCipherSpec message
//		return true;
//	}
}
