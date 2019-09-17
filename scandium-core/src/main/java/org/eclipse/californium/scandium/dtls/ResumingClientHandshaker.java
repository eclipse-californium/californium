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
 *    Achim Kraus (Bosch Software Innovations GmbH) - don't ignore retransmission of last flight
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix NullPointerException, if ccs is processed 
 *                                                    before the SERVER_HELLO.
 *                                                    move expectChangeCipherSpecMessage after
 *                                                    receiving SERVER_HELLO.
 *    Achim Kraus (Bosch Software Innovations GmbH) - reset master secret, when
 *                                                    session resumption is refused.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add dtls flight number
 *    Achim Kraus (Bosch Software Innovations GmbH) - adjust dtls flight number
 *                                                    for short resumption
 *    Achim Kraus (Bosch Software Innovations GmbH) - redesign DTLSFlight and RecordLayer
******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The resuming client handshaker executes a abbreviated handshake by adding a
 * valid session identifier into its ClientHello message. The message flow is
 * depicted in <a href="http://tools.ietf.org/html/rfc5246#section-7.3">Figure
 * 2</a>. The new keys will be generated from the master secret established from a
 * previous full handshake.
 */
public class ResumingClientHandshaker extends ClientHandshaker {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(ResumingClientHandshaker.class.getName());

	private static HandshakeState[] RESUME = { new HandshakeState(HandshakeType.HELLO_VERIFY_REQUEST, true),
			new HandshakeState(HandshakeType.SERVER_HELLO), new HandshakeState(ContentType.CHANGE_CIPHER_SPEC),
			new HandshakeState(HandshakeType.FINISHED) };

	// flag to indicate if we must do a full handshake or an abbreviated one
	private boolean fullHandshake = false;

	// Constructor ////////////////////////////////////////////////////

	/**
	 * Creates a new handshaker for resuming an existing session with a server.
	 * 
	 * @param session
	 *            the session to resume.
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
	public ResumingClientHandshaker(DTLSSession session, RecordLayer recordLayer, Connection connection,
			DtlsConnectorConfig config, int maxTransmissionUnit) {
		super(session, recordLayer, connection, config, maxTransmissionUnit);
		if (session.getSessionIdentifier() == null) {
			throw new IllegalArgumentException("Session must contain the ID of the session to resume");
		}
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	protected void doProcessMessage(HandshakeMessage message) throws HandshakeException, GeneralSecurityException {
		if (fullHandshake){
			// handshake resumption was refused by the server
			// we do a full handshake
			super.doProcessMessage(message);
			return;
		}

		switch (message.getMessageType()) {

		case HELLO_VERIFY_REQUEST:
			receivedHelloVerifyRequest((HelloVerifyRequest) message);
			break;

		case SERVER_HELLO:
			receivedServerHello((ServerHello)message);
			break;

		case FINISHED:
			receivedServerFinished((Finished) message);
			break;

		default:
			throw new HandshakeException(
					String.format("Received unexpected handshake message [%s] from peer %s", message.getMessageType(), message.getPeer()),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE, message.getPeer()));
		}
	}

	/**
	 * Stores the negotiated security parameters.
	 * 
	 * @param message
	 *            the {@link ServerHello} message.
	 * @throws HandshakeException if the ServerHello message cannot be processed,
	 * 	e.g. because the server selected an unknown or unsupported cipher suite
	 */
	protected void receivedServerHello(ServerHello message) throws HandshakeException {
		if (!session.getSessionIdentifier().equals(message.getSessionId()))
		{
			LOGGER.debug(
					"Server [{}] refuses to resume session [{}], performing full handshake instead...",
					message.getPeer(), session.getSessionIdentifier());
			// Server refuse to resume the session, go for a full handshake
			fullHandshake  = true;
			states = SEVER_CERTIFICATE;
			super.receivedServerHello(message);
		} else if (!message.getCompressionMethod().equals(session.getCompressionMethod())) {
			throw new HandshakeException(
					"Server wants to change compression method in resumed session",
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.ILLEGAL_PARAMETER,
							message.getPeer()));
		} else if (!message.getCipherSuite().equals(session.getCipherSuite())) {
			throw new HandshakeException(
					"Server wants to change cipher suite in resumed session",
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.ILLEGAL_PARAMETER,
							message.getPeer()));
		} else {
			verifyServerHelloExtensions(message);
			serverRandom = message.getRandom();
			if (connectionIdGenerator != null) {
				ConnectionIdExtension extension = message.getConnectionIdExtension();
				if (extension != null) {
					ConnectionId connectionId = extension.getConnectionId();
					session.setWriteConnectionId(connectionId);
				}
			}
			expectChangeCipherSpecMessage();
			calculateKeys(session.getMasterSecret());
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

		flightNumber += 2;
		DTLSFlight flight = new DTLSFlight(getSession(), flightNumber);

		// update the handshake hash
		MessageDigest md = getHandshakeMessageDigest();

		MessageDigest mdWithServerFinish;
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

		// the handshake hash to check the server's verify_data (without the
		// server's finished message included)
		message.verifyData(session.getCipherSuite().getThreadLocalPseudoRandomFunctionMac(), session.getMasterSecret(), false, md.digest());
		
		ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage(message.getPeer());
		wrapMessage(flight, changeCipherSpecMessage);
		setCurrentWriteState();

		mdWithServerFinish.update(message.getRawMessage());
		handshakeHash = mdWithServerFinish.digest();
		Finished finished = new Finished(session.getCipherSuite().getThreadLocalPseudoRandomFunctionMac(), session.getMasterSecret(), isClient, handshakeHash, message.getPeer());
		wrapMessage(flight, finished);
		sendLastFlight(flight);
		sessionEstablished();
	}

	@Override
	public void startHandshake() throws HandshakeException {
		handshakeStarted();
		ClientHello message = new ClientHello(new ProtocolVersion(), session,
				supportedClientCertificateTypes, supportedServerCertificateTypes);

		clientRandom = message.getRandom();

		message.addCompressionMethod(session.getCompressionMethod());

		addConnectionId(message);
		addMaxFragmentLength(message);
		addServerNameIndication(message);

		clientHello = message;

		flightNumber = 1;
		DTLSFlight flight = new DTLSFlight(getSession(), flightNumber);
		wrapMessage(flight, message);
		sendFlight(flight);
		states = RESUME;
		statesIndex = 0;
	}
}
