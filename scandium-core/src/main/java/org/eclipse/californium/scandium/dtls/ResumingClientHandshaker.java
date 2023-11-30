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

import java.security.MessageDigest;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.elements.util.NoPublicAPI;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The resuming client handshaker executes a abbreviated handshake by adding a
 * valid session identifier into its ClientHello message.
 * 
 * The message flow is depicted in
 * <a href="https://tools.ietf.org/html/rfc6347#page-21" target="_blank">Figure
 * 2</a>. The new keys will be generated from the master secret established from
 * a previous full handshake.
 * 
 * <pre>
 *   Client                                          Server
 *   ------                                          ------
 *
 *   ClientHello             --------&gt;                          Flight 1
 *
 *                                              ServerHello    \
 *                                       [ChangeCipherSpec]     Flight 2
 *                           &lt;--------             Finished    /
 *
 *   [ChangeCipherSpec]                                        \Flight 3
 *   Finished                --------&gt;                         /
 * </pre>
 * 
 * If the server denies to resume the session with
 * the provided session id, the handshaker falls back to a full-handshake,
 * depicted in
 * <a href="https://tools.ietf.org/html/rfc6347#page-21" target="_blank">Figure
 * 1</a>, see {@link ClientHandshaker}.
 * 
 * <p>
 * This implementation offers a probing mode.
 * 
 * If a mobile peer doesn't get a ACK or response that may have two different
 * causes:
 * </p>
 * 
 * <ol>
 * <li>server has lost session (association)</li>
 * <li>connectivity is lost</li>
 * </ol>
 * 
 * <p>
 * The second is sometime hard to detect; the peer's state is connected, but
 * effectively it's not working. In that case, after some retransmissions, the
 * peer starts a handshake. Without the probing mode starting a handshake
 * removes on the client the session. If the handshake timesout (though the
 * connection is not working), the peer still requires a new handshake after the
 * connectivity is established again.
 * 
 * With probing mode, the handshake starts without removing the session. If some
 * data is received, the session is removed and the handshake gets completed. If
 * no data is received, the peer assumes, that the connectivity is lost (even if
 * it's own state indicates connectivity) and just timesout the request. If the
 * connectivity is established again, just a new request could be send without a
 * handshake.
 * </p>
 */
@NoPublicAPI
public class ResumingClientHandshaker extends ClientHandshaker {

	private static final Logger LOGGER = LoggerFactory.getLogger(ResumingClientHandshaker.class);

	private static final HandshakeState[] ABBREVIATED_HANDSHAKE = { 
			new HandshakeState(ContentType.CHANGE_CIPHER_SPEC),
			new HandshakeState(HandshakeType.FINISHED) };

	// flag to indicate if we must do a full handshake or an abbreviated one
	private volatile boolean fullHandshake = false;

	/**
	 * Creates a new handshaker for resuming an existing session with a server.
	 * 
	 * @param session
	 *            the session to resume.
	 * @param recordLayer
	 *            the object to use for sending flights to the peer.
	 * @param timer
	 *            scheduled executor for flight retransmission (since 2.4).
	 * @param connection
	 *            the connection related with the session.
	 * @param config
	 *            the DTLS configuration parameters to use for the handshake.
	 * @param probe {@code true} enable probing for this resumption handshake,
	 *            {@code false}, not probing handshake.
	 * @throws IllegalArgumentException
	 *            if the given session does not contain an identifier.
	 * @throws NullPointerException if any of the provided parameter is
	 *             {@code null}
	 */
	public ResumingClientHandshaker(DTLSSession session, RecordLayer recordLayer, ScheduledExecutorService timer, Connection connection,
			DtlsConnectorConfig config, boolean probe) {
		super(null, recordLayer, timer, connection, config, probe);
		SessionId sessionId = session.getSessionIdentifier();
		if (sessionId == null || sessionId.isEmpty()) {
			throw new IllegalArgumentException("Session must contain the ID of the session to resume");
		}
		getSession().set(session);
	}

	@Override
	protected void doProcessMessage(HandshakeMessage message) throws HandshakeException {
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
					String.format("Received unexpected handshake message [%s] from peer %s", message.getMessageType(), peerToLog),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE));
		}
	}

	/**
	 * Check, if the server want an abbreviated or full handshake.
	 * 
	 * Stores the negotiated security parameters.
	 * 
	 * @param message the {@link ServerHello} message.
	 * @throws HandshakeException if the ServerHello message cannot be
	 *             processed, e.g. because the server selected an unknown or
	 *             unsupported cipher suite
	 */
	protected void receivedServerHello(ServerHello message) throws HandshakeException {
		DTLSSession session = getSession();
		if (!session.getSessionIdentifier().equals(message.getSessionId())) {
			LOGGER.debug(
					"Server [{}] refuses to resume session [{}], performing full handshake instead...",
					peerToLog, session.getSessionIdentifier());
			// Server refuse to resume the session, go for a full handshake
			fullHandshake  = true;
			SecretUtil.destroy(session);
			super.receivedServerHello(message);
		} else if (!message.getCompressionMethod().equals(session.getCompressionMethod())) {
			throw new HandshakeException(
					"Server wants to change compression method in resumed session",
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.ILLEGAL_PARAMETER));
		} else if (!message.getCipherSuite().equals(session.getCipherSuite())) {
			throw new HandshakeException(
					"Server wants to change cipher suite in resumed session",
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.ILLEGAL_PARAMETER));
		} else if (session.useExtendedMasterSecret() && !message.hasExtendedMasterSecretExtension()) {
			throw new HandshakeException(
					"Server wants to change extended master secret in resumed session",
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.ILLEGAL_PARAMETER));
		} else if (!session.getProtocolVersion().equals(message.getProtocolVersion())) {
			throw new HandshakeException(
					"Server wants to change protocol version in resumed session",
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.ILLEGAL_PARAMETER));
		} else {
			verifyServerHelloExtensions(message);
			serverRandom = message.getRandom();
			if (supportsConnectionId()) {
				receivedConnectionIdExtension(message.getConnectionIdExtension());
			}
			setExpectedStates(ABBREVIATED_HANDSHAKE);
			expectChangeCipherSpecMessage();
			resumeMasterSecret();
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
		DTLSFlight flight = createFlight();

		// update the handshake hash
		MessageDigest md = getHandshakeMessageDigest();
		MessageDigest mdWithServerFinish = cloneMessageDigest(md);

		// the handshake hash to check the server's verify_data (without the
		// server's finished message included)
		verifyFinished(message, md.digest());

		ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage();
		wrapMessage(flight, changeCipherSpecMessage);
		setCurrentWriteState();

		mdWithServerFinish.update(message.toByteArray());
		Finished finished = createFinishedMessage(mdWithServerFinish.digest());
		wrapMessage(flight, finished);
		sendLastFlight(flight);
		contextEstablished();
	}

	@Override
	public void startHandshake() throws HandshakeException {
		handshakeStarted();

		DTLSSession session = getSession();
		ClientHello message = new ClientHello(ProtocolVersion.VERSION_DTLS_1_2, session, supportedSignatureAlgorithms,
				supportedClientCertificateTypes, supportedServerCertificateTypes, supportedGroups);
		if (CipherSuite.containsEccBasedCipherSuite(message.getCipherSuites())) {
			expectEcc();
		}

		clientRandom = message.getRandom();

		if (session.useExtendedMasterSecret()) {
			// https://tools.ietf.org/html/rfc7627#section-5.3
			// "When offering an abbreviated handshake, the client
			// MUST send the "extended_master_secret" extension in
			// its ClientHello."
			// For "MUST", configure extended master secret required
			message.addExtension(ExtendedMasterSecretExtension.INSTANCE);
		}

		addConnectionId(message);
		addRecordSizeLimit(message);
		addMaxFragmentLength(message);
		addServerNameIndication(message);

		// keep client_hello for a hello_verify_request.
		clientHello = message;

		flightNumber = 1;
		DTLSFlight flight = createFlight();
		wrapMessage(flight, message);
		sendFlight(flight);
		setExpectedStates(INIT);
	}

	@Override
	public boolean isFullHandshake() {
		return fullHandshake;
	}
}
