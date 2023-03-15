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
import java.util.Objects;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.elements.util.NoPublicAPI;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.resumption.ResumptionVerifier;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The resuming server handshaker executes an abbreviated handshake when
 * receiving a ClientHello with a set session identifier.
 * 
 * It checks, whether such a session still exists and is valid for resumption
 * using
 * {@link ResumptionVerifier#verifyResumptionRequest(ConnectionId, org.eclipse.californium.scandium.util.ServerNames, SessionId)}
 * and the relevant hello extensions are matching.
 * 
 * If so, it generates the new keys from the previously established master
 * secret. The message flow is depicted in
 * <a href="https://tools.ietf.org/html/rfc6347#page-21" target= "_blank">Figure
 * 2</a>.
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
 * 
 * If not, it falls back to a full handshake. The message flow of this is
 * depicted in
 * <a href="https://tools.ietf.org/html/rfc6347#page-21" target= "_blank">Figure
 * 1</a>, see {@link ServerHandshaker}.
 * 
 * @since 3.0 supports {@link ResumptionVerifier} and fall back to
 *        full-handshakes
 */
@NoPublicAPI
public class ResumingServerHandshaker extends ServerHandshaker {
	private static final Logger LOGGER = LoggerFactory.getLogger(ResumingServerHandshaker.class);

	private static final HandshakeState[] ABBREVIATED_HANDSHAKE = { 
			new HandshakeState(ContentType.CHANGE_CIPHER_SPEC),
			new HandshakeState(HandshakeType.FINISHED) };

	private final ResumptionVerifier resumptionHandler;

	/**
	 * Pending client hello, waiting for result of {@link ResumptionVerifier}.
	 * 
	 * @since 3.0
	 */
	private ClientHello pendingClientHello;

	/**
	 * Flag to indicate if we must do a full handshake or an abbreviated one
	 * 
	 * @since 3.0
	 */
	private boolean fullHandshake;

	/** The handshake hash used in the Finished messages. */
	private byte[] handshakeHash;

	/**
	 * Creates a new handshaker for resuming an session with a client.
	 * 
	 * @param initialRecordSequenceNo the initial record sequence number (since
	 *            3.0).
	 * @param sequenceNumber the initial message sequence number to expect from
	 *            the peer (this parameter can be used to initialize the
	 *            <em>receive_next_seq</em> counter to another value than 0,
	 *            e.g. if one or more cookie exchange round-trips have been
	 *            performed with the peer before the handshake starts).
	 * @param recordLayer the object to use for sending flights to the peer.
	 * @param timer scheduled executor for flight retransmission (since 2.4).
	 * @param connection the connection related with the session.
	 * @param config the DTLS configuration parameters to use for the handshake.
	 * @throws IllegalArgumentException if no resumption verifier is configured.
	 * @throws NullPointerException if any of the provided parameter is
	 *             {@code null}
	 */
	public ResumingServerHandshaker(long initialRecordSequenceNo, int sequenceNumber, RecordLayer recordLayer,
			ScheduledExecutorService timer, Connection connection, DtlsConnectorConfig config) {
		super(initialRecordSequenceNo, sequenceNumber, recordLayer, timer, connection, config);
		this.resumptionHandler = config.getResumptionVerifier();
		if (resumptionHandler == null) {
			throw new IllegalArgumentException("Resumption verifier missing!");
		}
	}

	@Override
	protected void doProcessMessage(HandshakeMessage message) throws HandshakeException {
		if (fullHandshake) {
			// handshake resumption was refused
			// we do a full handshake
			super.doProcessMessage(message);
			return;
		}

		switch (message.getMessageType()) {
		case CLIENT_HELLO:
			handshakeStarted();
			receivedResumingClientHello((ClientHello) message);
			break;

		case FINISHED:
			receivedClientFinished((Finished) message);
			break;

		default:
			throw new HandshakeException(String.format("Received unexpected handshake message [%s] from peer %s",
					message.getMessageType(), peerToLog),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE));
		}

	}

	/**
	 * Check, if a session for the session id is available and valid.
	 * 
	 * Calls
	 * {@link #processResumptionVerificationResult(ResumptionVerificationResult)}
	 * on available resumption result.
	 * 
	 * @param clientHello the client's hello message.
	 * @throws HandshakeException if the server's handshake records creation
	 *             fails
	 * @throws IllegalArgumentException if the client hello doesn't contain a
	 *             session id
	 * @see ResumptionVerifier#verifyResumptionRequest(ConnectionId,
	 *      org.eclipse.californium.scandium.util.ServerNames, SessionId)
	 * @since 3.0
	 */
	private void receivedResumingClientHello(ClientHello clientHello) throws HandshakeException {
		if (!clientHello.hasSessionId()) {
			throw new IllegalArgumentException("Client hello doesn't contain session id required for resumption!");
		}
		pendingClientHello = clientHello;
		ResumptionVerificationResult result = resumptionHandler.verifyResumptionRequest(
				getConnection().getConnectionId(), clientHello.getServerNames(), clientHello.getSessionId());
		if (result != null) {
			LOGGER.debug("Process client hello synchronous");
			processResumptionVerificationResult(result);
		} else {
			startInitialTimeout();
		}
	}

	/**
	 * Verifies the client's Finished message. If valid, encrypted application
	 * data can be sent, otherwise an Alert must be sent.
	 * 
	 * @param message the client's Finished message.
	 * @throws HandshakeException if the client's Finished message can not be
	 *             verified.
	 */
	private void receivedClientFinished(Finished message) throws HandshakeException {
		verifyFinished(message, handshakeHash);
		contextEstablished();
		handshakeCompleted();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Additionally check, if a call to {@link ResumptionVerifier} is pending.
	 */
	protected boolean hasPendingApiCall() {
		return pendingClientHello != null || super.hasPendingApiCall();
	}

	@Override
	public void processAsyncHandshakeResult(HandshakeResult handshakeResult) throws HandshakeException {
		if (handshakeResult instanceof ResumptionVerificationResult) {
			LOGGER.debug("Process client hello asynchronous");
			ensureUndestroyed();
			processResumptionVerificationResult((ResumptionVerificationResult) handshakeResult);
		}
		super.processAsyncHandshakeResult(handshakeResult);
	}

	/**
	 * Process resumption verification result.
	 * 
	 * If a valid session is available and the relevant hello extensions are
	 * matching, use an abbreviated-handshake. Otherwise, switch back to a
	 * full-handshake.
	 * 
	 * @param resumptionResult resumption result
	 * @throws HandshakeException if the server's handshake records creation
	 *             fails
	 * @throws IllegalStateException if no resumption verification is pending
	 * @since 3.0
	 */
	private void processResumptionVerificationResult(ResumptionVerificationResult resumptionResult)
			throws HandshakeException {
		if (pendingClientHello == null) {
			throw new IllegalStateException("resumption verification not pending!");
		}
		ClientHello clientHello = pendingClientHello;
		pendingClientHello = null;
		DTLSSession session = resumptionResult.getDTLSSession();
		fullHandshake = !validateResumption(session, clientHello, sniEnabled, extendedMasterSecretMode);
		if (fullHandshake) {
			LOGGER.debug("DTLS session {} not available, switch to full-handshake with peer [{}]!",
					clientHello.getSessionId(), peerToLog);
			SecretUtil.destroy(session);
			receivedClientHello(clientHello);
		} else {
			getSession().set(session);
			SecretUtil.destroy(session);
			setCustomArgument(resumptionResult);
			processResumingClientHello(clientHello);
		}
	}

	/**
	 * Process client hello resuming the available and valid session.
	 * 
	 * The server generates new keys from the old master secret and sends
	 * ChangeCipherSpec and Finished message. The ClientHello contains a fresh
	 * random value which will be needed to generate the new keys.
	 * 
	 * @param clientHello the client's hello message.
	 * @throws HandshakeException if the server's handshake records cannot be
	 *             created
	 * @since 3.0
	 */
	private void processResumingClientHello(ClientHello clientHello) throws HandshakeException {
		DTLSSession session = getSession();
		CipherSuite cipherSuite = session.getCipherSuite();

		LOGGER.debug("Start resumption-handshake with peer [{}].", peerToLog);
		clientRandom = clientHello.getRandom();

		flightNumber += 2;
		DTLSFlight flight = createFlight();

		ServerHello serverHello = new ServerHello(clientHello.getProtocolVersion(),
				session.getSessionIdentifier(), cipherSuite, session.getCompressionMethod());
		addHelloExtensions(clientHello, serverHello);
		wrapMessage(flight, serverHello);
		serverRandom = serverHello.getRandom();

		ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage();
		wrapMessage(flight, changeCipherSpecMessage);

		MessageDigest md = getHandshakeMessageDigest();

		MessageDigest mdWithServerFinished = cloneMessageDigest(md);

		resumeMasterSecret();

		setCurrentWriteState();

		Finished finished = createFinishedMessage(md.digest());
		wrapMessage(flight, finished);

		mdWithServerFinished.update(finished.toByteArray());
		handshakeHash = mdWithServerFinished.digest();
		sendFlight(flight);
		setExpectedStates(ABBREVIATED_HANDSHAKE);
		expectChangeCipherSpecMessage();
	}

	@Override
	public boolean isFullHandshake() {
		return fullHandshake;
	}

	/**
	 * Checks, if the session and client hello are valid for an resumption
	 * handshake.
	 * 
	 * @param session the DTLS session to resume.
	 * @param clientHello the client's hello message.
	 * @param sniEnabled {@code true}, if SNI is enabled, {@code false},
	 *            otherwise.
	 * @param extendedMasterSecretMode the extended master secret mode.
	 * @return {@code true}, the session and client hello are valid for
	 *         resumption, {@code false}, if not and a fall back to a
	 *         full-handshake is required.
	 * @since 3.6
	 */
	public static boolean validateResumption(DTLSSession session, ClientHello clientHello, boolean sniEnabled,
			ExtendedMasterSecretMode extendedMasterSecretMode) {
		if (session == null) {
			LOGGER.debug("DTLS session {} not available, switch to full-handshake!", clientHello.getSessionId());
			return false;
		}
		CipherSuite cipherSuite = session.getCipherSuite();
		CompressionMethod compressionMethod = session.getCompressionMethod();
		if (!clientHello.getCipherSuites().contains(cipherSuite)) {
			LOGGER.debug("Cipher-suite {} changed by client hello, switch to full-handshake!", cipherSuite);
			return false;
		} else if (!session.getProtocolVersion().equals(clientHello.getProtocolVersion())) {
			LOGGER.debug("Protocol version {} changed by client hello {}, switch to full-handshake!",
					session.getProtocolVersion(), clientHello.getProtocolVersion());
			return false;
		} else if (!clientHello.getCompressionMethods().contains(compressionMethod)) {
			LOGGER.debug("Compression method {} changed by client hello, switch to full-handshake!",
					session.getCompressionMethod());
			return false;
		} else if (extendedMasterSecretMode.is(ExtendedMasterSecretMode.ENABLED)
				&& !clientHello.hasExtendedMasterSecretExtension()) {
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
			LOGGER.debug("Missing extended master secret extension in client hello, switch to full-handshake!");
			return false;
		} else if (extendedMasterSecretMode == ExtendedMasterSecretMode.OPTIONAL && session.useExtendedMasterSecret()
				&& !clientHello.hasExtendedMasterSecretExtension()) {
			// https://tools.ietf.org/html/rfc7627#section-5.3
			//
			// If the original session used the
			// "extended_master_secret" extension but the new
			// ClientHello does not contain it, the server
			// MUST abort the abbreviated handshake
			LOGGER.debug("Disabled extended master secret extension in client hello, switch to full-handshake!");
			return false;
		} else if (sniEnabled) {
			ServerNames serverNames = session.getServerNames();
			ServerNames clientServerNames = clientHello.getServerNames();
			if (!Objects.equals(serverNames, clientServerNames)) {
				LOGGER.debug("SNI {} changed by client hello {}, switch to full-handshake!", serverNames,
						clientServerNames);
				return false;
			}
		}
		return true;
	}
}
