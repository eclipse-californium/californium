/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
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

import java.security.MessageDigest;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.elements.util.NoPublicAPI;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

/**
 * The resuming server handshaker executes an abbreviated handshake when
 * receiving a ClientHello with a set session identifier.
 * 
 * It checks whether such a session still exists and if so,
 * generates the new keys from the previously established master secret.
 * The message flow is depicted in <a
 * href="http://tools.ietf.org/html/rfc5246#section-7.3">Figure 2</a>.
 */
@NoPublicAPI
public class ResumingServerHandshaker extends ServerHandshaker {

	// Members ////////////////////////////////////////////////////////

	/** The handshake hash used in the Finished messages. */
	private byte[] handshakeHash;

	// Constructor ////////////////////////////////////////////////////

	/**
	 * Creates a new handshaker for resuming an existing session with a client.
	 * 
	 * @param initialRecordSequenceNo the initial record sequence number (since
	 *            3.0).
	 * @param sequenceNumber the initial message sequence number to expect from
	 *            the peer (this parameter can be used to initialize the
	 *            <em>receive_next_seq</em> counter to another value than 0,
	 *            e.g. if one or more cookie exchange round-trips have been
	 *            performed with the peer before the handshake starts).
	 * @param session the session to negotiate with the client.
	 * @param recordLayer the object to use for sending flights to the peer.
	 * @param timer scheduled executor for flight retransmission (since 2.4).
	 * @param connection the connection related with the session.
	 * @param config the DTLS configuration parameters to use for the handshake.
	 * @throws IllegalArgumentException if the given session does not contain an
	 *             identifier, or the initial record or message sequence number
	 *             is negative
	 * @throws NullPointerException if any of the provided parameter is
	 *             {@code null}
	 */
	public ResumingServerHandshaker(long initialRecordSequenceNo, int sequenceNumber, DTLSSession session,
			RecordLayer recordLayer, ScheduledExecutorService timer, Connection connection,
			DtlsConnectorConfig config) {
		super(initialRecordSequenceNo, sequenceNumber, session, recordLayer, timer, connection, config);
		SessionId sessionId = session.getSessionIdentifier();
		if (sessionId == null || sessionId.isEmpty()) {
			throw new IllegalArgumentException("Session must contain the ID of the session to resume");
		}
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	protected void doProcessMessage(HandshakeMessage message) throws HandshakeException {

		switch (message.getMessageType()) {
		case CLIENT_HELLO:
			receivedClientHello((ClientHello) message);
			expectChangeCipherSpecMessage();
			break;

		case FINISHED:
			receivedClientFinished((Finished) message);
			break;

		default:
			throw new HandshakeException(
					String.format("Received unexpected handshake message [%s] from peer %s", message.getMessageType(), peerToLog),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE));
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
		DTLSSession session = getSession();
		CipherSuite cipherSuite = session.getCipherSuite();
		CompressionMethod compressionMethod = session.getCompressionMethod();
		if (!clientHello.getCipherSuites().contains(cipherSuite)) {
			throw new HandshakeException(
					"Client wants to change cipher suite in resumed session",
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.ILLEGAL_PARAMETER));
		} else if (!clientHello.getCompressionMethods().contains(compressionMethod)) {
			throw new HandshakeException(
					"Client wants to change compression method in resumed session",
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.ILLEGAL_PARAMETER));
		} else if (extendedMasterSecretMode.is(ExtendedMasterSecretMode.ENABLED)
				&& !clientHello.hasExtendedMasterSecret()) {
			// https://tools.ietf.org/html/rfc7627#section-5.3
			//
			// If the original session used the
			// "extended_master_secret" extension but the new
			// ClientHello does not contain it, the server
			// MUST abort the abbreviated handshake
			//
			// If neither the original session nor the new
			// ClientHello uses the extension, the server SHOULD
			// abort the handshake. If it continues with an
			// abbreviated handshake in order to support legacy
			// insecure resumption, the connection is no longer
			// protected by the mechanisms in this document, and the
			// server should follow the guidelines in Section 5.4.
			throw new HandshakeException(
					"Client wants to resume without extended master secret",
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.ILLEGAL_PARAMETER));
		} else if (extendedMasterSecretMode == ExtendedMasterSecretMode.OPTIONAL
				&& session.useExtendedMasterSecret() && !clientHello.hasExtendedMasterSecret()) {
			// https://tools.ietf.org/html/rfc7627#section-5.3
			//
			// If the original session used the
			// "extended_master_secret" extension but the new
			// ClientHello does not contain it, the server
			// MUST abort the abbreviated handshake
			throw new HandshakeException(
					"Client wants to resume without extended master secret",
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.ILLEGAL_PARAMETER));
		} else {
			clientRandom = clientHello.getRandom();
			serverRandom = new Random();

			HelloExtensions serverHelloExtensions = new HelloExtensions();
			negotiateCipherSuite(clientHello, serverHelloExtensions);
			processHelloExtensions(clientHello, serverHelloExtensions);

			flightNumber += 2;
			DTLSFlight flight = createFlight();

			ServerHello serverHello = new ServerHello(clientHello.getClientVersion(), serverRandom, session.getSessionIdentifier(),
					cipherSuite, compressionMethod, serverHelloExtensions);
			wrapMessage(flight, serverHello);

			ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage();
			wrapMessage(flight, changeCipherSpecMessage);

			MessageDigest md = getHandshakeMessageDigest();

			MessageDigest mdWithServerFinished;
			try {
				mdWithServerFinished = (MessageDigest) md.clone();
			} catch (CloneNotSupportedException e) {
				throw new HandshakeException(
						"Cannot create FINISHED message hash",
						new AlertMessage(
								AlertLevel.FATAL,
								AlertDescription.INTERNAL_ERROR));
			}

			masterSecret = session.getMasterSecret();
			calculateKeys(masterSecret);

			setCurrentWriteState();

			Finished finished = new Finished(cipherSuite.getThreadLocalPseudoRandomFunctionMac(), masterSecret, false, md.digest());
			wrapMessage(flight, finished);

			mdWithServerFinished.update(finished.toByteArray());
			handshakeHash = mdWithServerFinished.digest();
			sendFlight(flight);
			states = NO_CLIENT_CERTIFICATE;
			statesIndex = 0;
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
		message.verifyData(getSession().getCipherSuite().getThreadLocalPseudoRandomFunctionMac(), masterSecret, true, handshakeHash);
		contextEstablished();
		handshakeCompleted();
	}
}
