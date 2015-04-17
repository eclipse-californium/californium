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
 *    Julien Vermillard - Sierra Wireless
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add duplicate record detection
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 462463
 *    Kai Hudalla (Bosch Software Innovations GmbH) - re-factor configuration
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 464383
 ******************************************************************************/
package org.eclipse.californium.scandium;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.channels.ClosedByInterruptException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig.Builder;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.ApplicationMessage;
import org.eclipse.californium.scandium.dtls.ClientHandshaker;
import org.eclipse.californium.scandium.dtls.ClientHello;
import org.eclipse.californium.scandium.dtls.CompressionMethod;
import org.eclipse.californium.scandium.dtls.ContentType;
import org.eclipse.californium.scandium.dtls.Cookie;
import org.eclipse.californium.scandium.dtls.DTLSFlight;
import org.eclipse.californium.scandium.dtls.DTLSMessage;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.FragmentedHandshakeMessage;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.HandshakeMessage;
import org.eclipse.californium.scandium.dtls.Handshaker;
import org.eclipse.californium.scandium.dtls.HelloVerifyRequest;
import org.eclipse.californium.scandium.dtls.InMemorySessionStore;
import org.eclipse.californium.scandium.dtls.ProtocolVersion;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.ResumingClientHandshaker;
import org.eclipse.californium.scandium.dtls.ResumingServerHandshaker;
import org.eclipse.californium.scandium.dtls.ServerHandshaker;
import org.eclipse.californium.scandium.dtls.SessionId;
import org.eclipse.californium.scandium.dtls.SessionListener;
import org.eclipse.californium.scandium.dtls.SessionStore;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.util.ByteArrayUtils;


/**
 * A {@link Connector} using <em>Datagram TLS</em> (DTLS) as specified in
 * <a href="http://tools.ietf.org/html/rfc6347">RFC 6347</a> for securing data
 * exchanged between networked clients and a server application.	
 * 
 */
public class DTLSConnector implements Connector {
	
	private final static Logger LOGGER = Logger.getLogger(DTLSConnector.class.getCanonicalName());

	/** all the configuration options for the DTLS connector */ 
	private final DtlsConnectorConfig config;

	private DatagramSocket socket;
	
	/** The timer daemon to schedule retransmissions. */
	private final Timer timer = new Timer(true); // run as daemon
	
	/** The thread that receives messages */
	private Worker receiver;
	
	/** The thread that sends messages */
	private Worker sender;
	
	private final SessionStore sessionStore;
	
	/** The queue of outgoing block (for sending). */
	private final BlockingQueue<RawData> outboundMessages; // Messages to send
	
	/** Storing handshakers according to peer-addresses. */
	private Map<InetSocketAddress, Handshaker> handshakers = new ConcurrentHashMap<>();

	/** Storing flights according to peer-addresses. */
	private Map<InetSocketAddress, DTLSFlight> flights = new ConcurrentHashMap<>();
	
	/** Indicates whether the connector has started and not stopped yet */
	private boolean running;
	
	private RawDataChannel messageHandler;
	
	private SessionListener sessionListener;
	
	/**
	 * Creates a DTLS connector from a given configuration object
	 * using the standard in-memory <code>SessionStore</code>. 
	 * 
	 * @param configuration the configuration options
	 * @throws NullPointerException if the configuration is <code>null</code>
	 */
	public DTLSConnector(DtlsConnectorConfig configuration) {
		this(configuration, null);
	}
	
	/**
	 * Creates a DTLS connector from a given configuration object.
	 * 
	 * @param configuration the configuration options
	 * @param sessionStore the store to use for keeping track of session information,
	 *       if <code>null</code> session information is kept in-memory
	 * @throws NullPointerException if the configuration is <code>null</code>
	 */
	public DTLSConnector(DtlsConnectorConfig configuration, SessionStore sessionStore) {
		if (configuration == null) {
			throw new NullPointerException("Configuration must not be null");
		} else {
			this.config = configuration;
		}
		this.outboundMessages = new LinkedBlockingQueue<RawData>(config.getOutboundMessageBufferSize());
		if (sessionStore != null) {
			this.sessionStore = sessionStore;
		} else {
			this.sessionStore = new InMemorySessionStore();
		}
		
		setSessionListener();
	}
	
	/**
	 * Creates a DTLS connector for PSK based authentication only.
	 * 
	 * @param address the IP address and port to bind to
	 * @deprecated Use {@link #DTLSConnector(DtlsConnectorConfig, SessionStore)} instead
	 */
	public DTLSConnector(InetSocketAddress address) {
		this(address, null);
	}

	/**
	 * Creates a DTLS connector that can also do certificate based authentication.
	 * 
	 * @param address the address to bind
	 * @param rootCertificates list of trusted root certificates, e.g. from well known
	 * Certificate Authorities or self-signed certificates.
	 * @deprecated Use {@link #DTLSConnector(DtlsConnectorConfig, SessionStore)} instead
	 */
	public DTLSConnector(InetSocketAddress address, Certificate[] rootCertificates) {
		this(address, rootCertificates, null, null);
	}
	
	/**
	 * Creates a DTLS connector that can also do certificate based authentication.
	 * 
	 * @param address the address to bind
	 * @param rootCertificates list of trusted root certificates, e.g. from well known
	 * Certificate Authorities or self-signed certificates (may be <code>null</code>)
	 * @param sessionStore the store to use for keeping track of session information,
	 *       if <code>null</code> session information is kept in-memory
	 * @deprecated Use {@link #DTLSConnector(DtlsConnectorConfig, SessionStore)} instead
	 */
	public DTLSConnector(InetSocketAddress address, Certificate[] rootCertificates,
			SessionStore sessionStore, DTLSConnectorConfig config) {
		Builder builder = new Builder(address);
		if (config != null) {
			builder.setMaxFragmentLength(config.getMaxFragmentLength());
			builder.setMaxPayloadSize(config.getMaxPayloadSize());
			builder.setMaxRetransmissions(config.getMaxRetransmit());
			builder.setRetransmissionTimeout(config.getRetransmissionTimeout());
			if (rootCertificates != null) {
				builder.setTrustStore(rootCertificates);
			}
			if (config.pskStore != null) {
				builder.setPskStore(config.pskStore);
			} else if (config.certChain != null) {
				builder.setIdentity(config.privateKey, config.certChain, config.sendRawKey);
			} else {
				builder.setIdentity(config.privateKey, config.publicKey);
			}
		}
		this.config = builder.build();
		// TODO define maximum capacity
		this.outboundMessages = new LinkedBlockingQueue<RawData>();
		if (sessionStore != null) {
			this.sessionStore = sessionStore;
		} else {
			this.sessionStore = new InMemorySessionStore();
		}
		setSessionListener();
	}
	
	private void setSessionListener() {
		this.sessionListener = new SessionListener() {
			
			@Override
			public void handshakeCompleted(Handshaker handshaker, DTLSSession session) {
				if (handshaker != null) {
					if (session != null && session.isActive()) {
						DTLSSession existingSession = DTLSConnector.this.sessionStore.store(session);
						removeHandshaker(handshaker.getPeerAddress());
						if (existingSession == null) {
							LOGGER.log(Level.FINER, "Putting newly established session with peer [{0}] into session store",
									handshaker.getPeerAddress());
						} else {
							LOGGER.log(Level.FINER, "Replacing existing session with peer [{0}] in session store",
									handshaker.getPeerAddress());
						}
					}
				}
			}
		};
	}
	
	private Handshaker getHandshaker(InetSocketAddress peerAddress) {
		return handshakers.get(peerAddress);
	}
	
	private Handshaker removeHandshaker(InetSocketAddress peerAddress) {
		if (peerAddress != null) {
			return handshakers.remove(peerAddress);
		} else {
			return null;
		}
	}
	
	private Handshaker storeHandshaker(Handshaker handshaker) {
		if (handshaker != null) {
			return handshakers.put(handshaker.getPeerAddress(), handshaker);
		} else {
			return null;
		}
	}
	
	private DTLSFlight getFlight(InetSocketAddress peerAddress) {
		return flights.get(peerAddress);
	}
	
	private DTLSFlight storeFlight(DTLSFlight flight) {
		if (flight != null) {
			return flights.put(flight.getPeerAddress(), flight);
		} else {
			return null;
		}
	}
	
	private DTLSFlight removeFlight(InetSocketAddress peerAddress) {
		if (peerAddress != null) {
			return flights.remove(peerAddress);
		} else {
			return null;
		}
	}
	
	/**
	 * Closes all DTLS sessions with all peers.
	 * 
	 * According to the DTLS spec this means that a <em>CLOSE_NOTIFY</em>
	 * message is sent to each of the peers.
	 */
	private void close() {
		// while this certainly is nice behavior
		// I wonder how long this takes if we have
		// millions of active sessions ...
		for (DTLSSession session : sessionStore.getAll()) {
			this.close(session.getPeer());
		}
	}
	
	/**
	 * Closes a connection with a given peer.
	 * 
	 * The connection is gracefully shut down, i.e. a final
	 * <em>CLOSE_NOTIFY</em> alert message is sent to the peer
	 * prior to removing all session state.
	 * 
	 * @param peerAddress the address of the peer to close the connection to
	 */
	public final void close(InetSocketAddress peerAddress) {
		// (Kai Hudalla) I think this method should be made private because managing sessions
		// should be the sole responsibility of the DTLSConnector. We should probably
		// add a housekeeping thread that closes stale sessions after a certain time.
		try {
			cancelPreviousFlight(peerAddress);
			DTLSSession session = getSessionByAddress(peerAddress);

			if (session != null) {
				DTLSMessage closeNotify = new AlertMessage(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);

				DTLSFlight flight = new DTLSFlight(session);
				flight.addMessage(new Record(ContentType.ALERT, session.getWriteEpoch(), session.getSequenceNumber(), closeNotify, session));
				flight.setRetransmissionNeeded(false);
				
				LOGGER.log(Level.FINE, "Sending CLOSE_NOTIFY to peer [{0}]", peerAddress);
				sendFlight(flight);
			} else {
				LOGGER.log(Level.FINE, "Session with peer [{0}] not found. Maybe already closed by peer?",
						peerAddress);
			}
		} finally {
			// clear session
			connectionClosed(peerAddress);
		}
	}
	
	@Override
	public final synchronized void start() throws IOException {
		if (running) {
			return;
		}
		socket = new DatagramSocket(null);
		// make it easier to stop/start a server consecutively without delays
		socket.setReuseAddress(true);
		socket.bind(config.getAddress());
		running = true;

		sender = new Worker("DTLS-Sender-" + config.getAddress()) {
				public void doWork() throws Exception { sendNextMessageOverNetwork(); }
			};

		receiver = new Worker("DTLS-Receiver-" + config.getAddress()) {
				public void doWork() throws Exception { receiveNextDatagramFromNetwork(); }
			};
		
		receiver.start();
		sender.start();
		LOGGER.log(Level.CONFIG, "DLTS connector listening on [{0}]", config.getAddress());
	}
	
	/**
	 * Stops the sender and receiver threads and closes the socket
	 * used for sending and receiving datagrams.
	 */
	final synchronized void releaseSocket() {
		running = false;
		sender.interrupt();
		receiver.interrupt();
		outboundMessages.clear();
		if (socket != null) {
			socket.close();
		}
	}
	
	@Override
	public final synchronized void stop() {
		if (!running) {
			return;
		}
		// TODO re-consider graceful closing (millions of) connections since this might take some time
		this.close();
		releaseSocket();
	}
	
	/**
	 * Destroys the connector.
	 * 
	 * The only thing this method currently does, is invoking {@link #stop()}.
	 * Thus, contrary to {@link Connector#destroy()}'s JavaDoc, this connector
	 * can be re-started.
	 */
	@Override
	public final synchronized void destroy() {
		stop();
	}
	
	private void receiveNextDatagramFromNetwork() throws IOException {
		byte[] buffer = new byte[config.getMaxPayloadSize()];
		DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
		synchronized (socket) {
			socket.receive(packet);
		}
		
		if (packet.getLength() == 0) {
			// nothing to do
			return;
		}
		InetSocketAddress peerAddress = new InetSocketAddress(packet.getAddress(), packet.getPort());
		
		byte[] data = Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getLength());
		List<Record> records = Record.fromByteArray(data);

		try {
			for (Record record : records) {
				LOGGER.log(Level.FINEST, "Received DTLS record of type [{0}]", record.getType());
				
				switch(record.getType()) {
				case APPLICATION_DATA:
					processApplicationDataRecord(peerAddress, record);
					break;
				case ALERT:
					processAlertRecord(peerAddress, record);
					break;
				case CHANGE_CIPHER_SPEC:
					processChangeCipherSpecRecord(peerAddress, record);
					break;
				case HANDSHAKE:
					processHandshakeRecord(peerAddress, record);
				}
			}
		} catch (HandshakeException e) {
			if (AlertLevel.FATAL.equals(e.getAlert().getLevel())) {
				terminateConnection(peerAddress, e.getAlert());
			} else {
				LOGGER.log(Level.FINE,
						String.format("Cannot process DTLS record from peer [%s]", peerAddress)
						, e);
			}
		}
	}
	

	/**
	 * Immediately terminates a connection with a peer.
	 * 
	 * Terminating the connection includes
	 * <ul>
	 * <li>canceling any pending retransmissions to the peer</li>
	 * <li>destroying a cached session with the peer</li>
	 * <li>destroying any handshakers for the peer</li>
	 * <li>optionally sending a final ALERT to the peer (if a session exists with the peer)</li>
	 * </ul>
	 * 
	 * @param peerAddress the peer to terminate the connection to
	 * @param alert the message to send to the peer (may be <code>null</code>)
	 */
	private void terminateConnection(InetSocketAddress peerAddress, AlertMessage alert) {

		LOGGER.log(Level.FINE, "Terminating connection with peer [{0}], reason [{1}]",
				new Object[]{peerAddress, alert.getDescription()});
		cancelPreviousFlight(peerAddress);
		DTLSSession session = getSessionByAddress(peerAddress);
		if (session != null) {
			if (alert != null) {
				DTLSFlight flight = new DTLSFlight(session);
				flight.setRetransmissionNeeded(false);
				flight.addMessage(new Record(ContentType.ALERT, session.getWriteEpoch(), session.getSequenceNumber(), alert, session));
				sendFlight(flight);
			}
			
			// prevent processing of additional records
			session.setActive(false);
		}
		// clear session & (pending) handshaker
		connectionClosed(peerAddress);
	}
	
	
	private void processApplicationDataRecord(InetSocketAddress peerAddress, Record record) {

		DTLSSession session = getSessionByAddress(peerAddress);
		
		if (session != null && session.isActive()) {
			// The DTLS 1.2 spec (section 4.1.2.6) advises to do replay detection
			// before MAC validation based on the record's sequence numbers
			// see http://tools.ietf.org/html/rfc6347#section-4.1.2.6
			if (session.isRecordProcessable(record.getEpoch(), record.getSequenceNumber())) {
				// APPLICATION_DATA can only be processed within the context of
				// an established, i.e. fully negotiated, session
				record.setSession(session);
				try {
					ApplicationMessage message = (ApplicationMessage) record.getFragment();
					if (messageHandler != null) {
						messageHandler.receiveData(new RawData(message.getData(), peerAddress, session.getPeerIdentity()));
					}
					// the fragment could be processed
					// thus, the session seems to have been established successfully with
					// peer and it's safe to remove the (now obsolete) handshaker
					removeHandshaker(peerAddress);
					session.markRecordAsRead(record.getEpoch(), record.getSequenceNumber());
				} catch (HandshakeException e) {
					// this means that the fragment from the record could not be verified and de-crypted
					// mybe because the record has been sent in a forged UDP datagram by an attacker
					// the DTLS 1.2 spec section 4.1.2.7 (see http://tools.ietf.org/html/rfc6347#section-4.1.2.7)
					// advises to silently discard such records
					LOGGER.log(Level.FINE, "Discarding (supposedly) forged APPLICATION_DATA record from peer {[0]}",
							peerAddress);
				}
			} else {
				LOGGER.log(Level.FINER, "Discarding duplicate APPLICATION_DATA record received from peer [{0}]",
						peerAddress);
			}
		} else {
			// discard record
			LOGGER.log(Level.FINER,
					"Discarding APPLICATION_DATA record received from peer [{0}] without an active session",
					new Object[]{peerAddress});

		}
	}
	
	private void processAlertRecord(InetSocketAddress peerAddress, Record record) {
		
		// An ALERT can be processed at all times. If the ALERT level is fatal
		// the connection with the peer must be terminated and all session or handshake
		// state (keys, session identifier etc) must be destroyed.
		record.setSession(getSessionByAddress(peerAddress));
		try {
			AlertMessage alert = (AlertMessage) record.getFragment();
			LOGGER.log(Level.FINER, "Received ALERT record [{0}] from [{1}]",
					new Object[]{alert, peerAddress});
			if (AlertLevel.FATAL.equals(alert.getLevel())) {
				// according to section 7.2 of the TLS 1.2 spec
				// (http://tools.ietf.org/html/rfc5246#section-7.2)
				// the connection needs to be terminated immediately
				cancelPreviousFlight(peerAddress);
				
				AlertMessage bye = null;
				switch (alert.getDescription()) {
				case CLOSE_NOTIFY:
					// respond with CLOSE_NOTIFY as mandated by TLS 1.2, section 7.2.1
					// http://tools.ietf.org/html/rfc5246#section-7.2.1
					bye = new AlertMessage(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);
				default:
					terminateConnection(peerAddress, bye);
					//TODO somehow tell application layer to cancel
				}
			} else {
				// alert is not fatal, ignore for now
			}
		} catch (HandshakeException e) {
			// this means that the fragment from the record could not be verified and de-crypted
			// maybe because the record has been sent in a forged UDP datagram by an attacker
			// the DTLS 1.2 spec section 4.1.2.7 (see http://tools.ietf.org/html/rfc6347#section-4.1.2.7)
			// advises to silently discard such records
			LOGGER.log(Level.FINE, "Discarding (supposedly) forged ALERT record from peer {[0]}",
					peerAddress);
		}
	}
	
	private void processChangeCipherSpecRecord(InetSocketAddress peerAddress, Record record) throws HandshakeException {
		Handshaker handshaker = getHandshaker(peerAddress);
		if (handshaker == null) {
			// change cipher spec can only be processed within the
			// context of an existing handshake -> ignore record
			LOGGER.log(Level.FINE,
					"Discarding CHANGE_CIPHER_SPEC record from peer [{0}], no handshake in progress...",
					peerAddress);
		} else {
			// processing a CCS message does not result in any additional flight to be sent
			handshaker.processMessage(record);
		}		
	}
	
	private void processHandshakeRecord(InetSocketAddress peerAddress, Record record) throws HandshakeException {

		LOGGER.log(Level.FINER, "Received HANDSHAKE record from peer [{0}]", peerAddress);
		Handshaker handshaker = getHandshaker(peerAddress);
		DTLSFlight flight = null;
		if (handshaker != null) {
			// we are already in an ongoing handshake
			// simply delegate the processing of the record
			// to the handshaker
			flight = handshaker.processMessage(record);
		} else {
			
			HandshakeMessage handshake = (HandshakeMessage) record.getFragment();

			switch (handshake.getMessageType()) {
			case HELLO_REQUEST:
				// Peer (server) wants us (client) to initiate (re-)negotiation of session
				flight = processHelloRequest(peerAddress, record);
				break;

			case CLIENT_HELLO:
				// Peer (client) wants to either resume an existing session
				// or wants to negotiate a new session with us (server)
				flight = processClientHello(peerAddress, record);
				break;

			default:
				LOGGER.log(Level.FINER, "Discarding unexpected handshake message of type [{0}] from peer [{1}]",
						new Object[]{handshake.getMessageType(), peerAddress});
			}
		}

		if (flight != null) {
			cancelPreviousFlight(peerAddress);

			if (flight.isRetransmissionNeeded()) {
				storeFlight(flight);
				scheduleRetransmission(flight);
			}

			sendFlight(flight);
		}
		
	}
	
	private DTLSFlight processHelloRequest(InetSocketAddress peerAddress, Record record) throws HandshakeException {
		DTLSSession session = getSessionByAddress(peerAddress);
		// Peer (server) wants us (client) to initiate a re-negotiation of the session
		if (session == null) {
			session = new DTLSSession(peerAddress, true);
		}
		Handshaker handshaker = new ClientHandshaker(null, session, config);
		storeHandshaker(handshaker);
		return handshaker.getStartHandshakeMessage();
	}
	
	private DTLSFlight processClientHello(InetSocketAddress peerAddress, Record record) throws HandshakeException {
		
		DTLSFlight nextFlight = null;
		HandshakeMessage handshake = (HandshakeMessage) record.getFragment();
		// Peer (client) wants to either resume an existing session
		// or wants to negotiate a new session with us (server)

		if (handshake instanceof FragmentedHandshakeMessage) {
			// this should not happen because a ClientHello message
			// does not contain much data and should therefore rarely
			// need to be fragmented
			LOGGER.log(Level.INFO, "Discarding fragmented CLIENT_HELLO message from peer [{0}]", peerAddress);
			return null;
		}
		
		ClientHello clientHello = (ClientHello) handshake;
		
		if (record.getEpoch() == 0) {
			// client tries to negotiate fresh session
			// verify client's ability to respond on given IP address
			// by exchanging a cookie as described in section 4.2.1 of the DTLS 1.2 spec
			// see http://tools.ietf.org/html/rfc6347#section-4.2.1
			Cookie expectedCookie = generateCookie(peerAddress, clientHello);
			if (!expectedCookie.equals(clientHello.getCookie())) {
				LOGGER.log(Level.FINE, "Processing CLIENT_HELLO from peer [{0}]:\n{1}", new Object[]{peerAddress, record});
				// send CLIENT_HELLO_VERIFY with cookie in order to prevent
				// DOS attack as described in DTLS 1.2 spec
				LOGGER.log(Level.FINER, "Verifying client IP address [{0}] using HELLO_VERIFY_REQUEST", peerAddress);
				HelloVerifyRequest msg = new HelloVerifyRequest(new ProtocolVersion(), expectedCookie);
				// because we do not have a handshaker in place yet that
				// manages message_seq numbers, we need to set it explicitly
				// use message_seq from CLIENT_HELLO in order to allow for
				// multiple consequtive cookie exchanges with a client
				msg.setMessageSeq(clientHello.getMessageSeq());
				// use epoch 0 and sequence no from CLIENT_HELLO record as
				// mandated by section 4.2.1 of the DTLS 1.2 spec
				// see http://tools.ietf.org/html/rfc6347#section-4.2.1
				Record helloVerify = new Record(ContentType.HANDSHAKE, 0, record.getSequenceNumber(), msg, null);
				nextFlight = new DTLSFlight(peerAddress);
				nextFlight.addMessage(helloVerify);
			} else {
				LOGGER.log(Level.FINER,
						"Successfully verified client IP address [{0}] using cookie exchange",
						peerAddress);
				// check if message contains a session identifier
				SessionId sessionId = clientHello.getSessionId().length() > 0 ? clientHello.getSessionId() : null;

				if (sessionId == null) {
					// this is the standard case
					// use the record sequence number from CLIENT_HELLO as initial sequence number
					// for records sent to the client (see section 4.2.1 of RFC 6347 (DTLS 1.2))
					DTLSSession newSession = new DTLSSession(peerAddress, false, record.getSequenceNumber());
					// initialize handshaker based on CLIENT_HELLO (this accounts
					// for the case that multiple cookie exchanges have taken place)
					Handshaker handshaker = new ServerHandshaker(clientHello.getMessageSeq(),
							newSession, sessionListener, config);
					storeHandshaker(handshaker);
					nextFlight = handshaker.processMessage(record);
				} else {
					// client wants to resume a cached session
					LOGGER.log(Level.FINER, "Client [{0}] wants to resume session with ID [{1}]",
							new Object[]{peerAddress, ByteArrayUtils.toHexString(sessionId.getSessionId())});
					DTLSSession session = getSessionByIdentifier(sessionId);
					if (session != null) {
						// session has been found in cache, resume session
						// TODO check if client still has same address
						Handshaker handshaker = new ResumingServerHandshaker(session, config);
						storeHandshaker(handshaker);
						nextFlight = handshaker.processMessage(record);
					} else {
						LOGGER.log(Level.FINER, "Client [{0}] tries to resume non-existing session with ID [{1}], starting new handshake...",
								new Object[]{peerAddress, ByteArrayUtils.toHexString(sessionId.getSessionId())});
						DTLSSession newSession = new DTLSSession(peerAddress, false, record.getSequenceNumber());
						Handshaker handshaker = new ServerHandshaker(1, newSession, null, config);
						storeHandshaker(handshaker);
						nextFlight = handshaker.processMessage(record);
					}
				}
			}
		} else {
			// client tries to re-negotiate new crypto params for existing session
			DTLSSession session = getSessionByAddress(peerAddress);
			if (session != null) {
				// let handshaker figure out whether CLIENT_HELLO is from correct
				// epoch and client uses correct crypto params
				Handshaker handshaker = new ServerHandshaker(session, sessionListener, config);
					storeHandshaker(handshaker);
					nextFlight = handshaker.processMessage(record);
			} else {
			// no existing session found, ignore request
			}
		}
		
		return nextFlight;
	}
		
	private byte[] getSecretForCookies() {
		// TODO change secret periodically
		return "generate cookie".getBytes();
	}
	
	/**
	 * Generates a cookie in such a way that they can be verified without
	 * retaining any per-client state on the server.
	 * 
	 * <pre>
	 * Cookie = HMAC(Secret, Client - IP, Client - Parameters)
	 * </pre>
	 * 
	 * as suggested <a
	 * href="http://tools.ietf.org/html/rfc6347#section-4.2.1">here</a>.
	 * 
	 * @return the cookie generated from the client's parameters.
	 */
	private Cookie generateCookie(InetSocketAddress peerAddress, ClientHello clientHello)
		throws HandshakeException {

		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");

			// Cookie = HMAC(Secret, Client-IP, Client-Parameters)
			byte[] secret = getSecretForCookies();

			// Client-IP
			md.update(peerAddress.toString().getBytes());

			// Client-Parameters
			md.update((byte) clientHello.getClientVersion().getMajor());
			md.update((byte) clientHello.getClientVersion().getMinor());
			md.update(clientHello.getRandom().getRandomBytes());
			md.update(clientHello.getSessionId().getSessionId());
			md.update(CipherSuite.listToByteArray(clientHello.getCipherSuites()));
			md.update(CompressionMethod.listToByteArray(clientHello.getCompressionMethods()));

			byte[] data = md.digest();

			return new Cookie(Handshaker.doHMAC(md, secret, data));
		} catch (NoSuchAlgorithmException e) {
			LOGGER.log(Level.SEVERE,"Could not instantiate message digest algorithm for cookie creation.", e);
			throw new HandshakeException("Internal error", new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR));
		}
	}
	
	@Override
	public final void send(RawData msg) {
		if (msg == null) {
			LOGGER.finest("Ignoring NULL msg ...");
		} else {
			boolean queueFull = !outboundMessages.offer(msg);
			if (queueFull) {
				LOGGER.log(Level.WARNING, "Outbound message queue is full! Dropping outbound message to peer [{0}]",
						msg.getInetSocketAddress());
			}
		}
	}
	
	private void sendNextMessageOverNetwork() throws HandshakeException {

		RawData message;
		try {
			message = outboundMessages.take(); // Blocking
		} catch (InterruptedException e) {
			// this means that the worker thread for sending
			// outbound messages has been interrupted, most
			// probably because the connector is shutting down
			return;
		}
		
		InetSocketAddress peerAddress = message.getInetSocketAddress();
		LOGGER.log(Level.FINER, "Sending application layer message to peer [{0}]", peerAddress);
		DTLSSession session = getSessionByAddress(peerAddress);
		
		/*
		 * When the DTLS layer receives a message from an upper layer, there is
		 * either already a DTLS session established with the peer or a new
		 * handshake must be initiated. If a session is available and active, the
		 * message will be encrypted and sent to the peer, otherwise a short
		 * handshake will be initiated.
		 */
		Handshaker handshaker = null;
		DTLSFlight flight = null;

		if (session == null) {
			// no session with peer available, create new empty session &
			// start fresh handshake
			session = new DTLSSession(peerAddress, true);
			sessionStore.store(session);
			handshaker = new ClientHandshaker(message, session, config);
			
		} else {

			if (session.isActive()) {
				// session to peer is active, send encrypted message
				
				// TODO What about PMTU? 
				DTLSMessage fragment = new ApplicationMessage(message.getBytes());
				Record record = new Record(ContentType.APPLICATION_DATA, session.getWriteEpoch(), session.getSequenceNumber(), fragment, session);
				flight = new DTLSFlight(session);
				flight.addMessage(record);				
			} else {
				// try to resume the existing session
				handshaker = new ResumingClientHandshaker(message, session, config);
			}
			
		}
		
		// start DTLS handshake protocol
		if (handshaker != null) {
			// get starting handshake message
			storeHandshaker(handshaker);
			flight = handshaker.getStartHandshakeMessage();
			storeFlight(flight);
			scheduleRetransmission(flight);
		}
		sendFlight(flight);
	}

	/**
	 * Returns the {@link DTLSSession} related to the given peer address.
	 * 
	 * @param address the peer address
	 * @return the {@link DTLSSession} or <code>null</code> if no session found.
	 */
	public final DTLSSession getSessionByAddress(InetSocketAddress address) {
		if (address == null) {
			return null;
		}
		return sessionStore.get(address);
	}

	/**
	 * Finds a cached session by its identifier.
	 * 
	 * Note that not all cached session necessarily have a session identifier
	 * assigned, e.g. if the handshake for that session has not been completed (yet).

	 * Searches through all stored sessions and returns that session which
	 * matches the session identifier or <code>null</code> if no such session
	 * available. This method is used when the server receives a
	 * <code>ClientHello</code> containing a session identifier indicating that the
	 * client wants to resume a previous session. If a matching session is
	 * found, the server will resume the session with a abbreviated handshake,
	 * otherwise a full handshake (with new session identifier in
	 * <code>ServerHello</code>) is conducted.
	 * 
	 * @param sessionId
	 *            the session identifier to look up
	 * @return the corresponding session or <code>null</code> if none of
	 *            the cached sessions has the given identifier
	 */
	private DTLSSession getSessionByIdentifier(SessionId sessionId) {
		return sessionStore.find(sessionId);
	}
	
	private void sendFlight(DTLSFlight flight) {
		byte[] payload = new byte[] {};
		LOGGER.log(Level.FINER, "Sending flight of [{0}] messages to peer[{1}]",
				new Object[]{flight.getMessages().size(), flight.getPeerAddress()});
		// put as many records into one datagram as allowed by the block size
		List<DatagramPacket> datagrams = new ArrayList<DatagramPacket>();

		for (Record record : flight.getMessages()) {
			if (flight.getTries() > 0) {
				// adjust the record sequence number
				int epoch = record.getEpoch();
				record.setSequenceNumber(flight.getSession().getSequenceNumber(epoch));
			}
			
			LOGGER.log(Level.FINEST, "Sending record to peer [{0}]:\n{1}", new Object[]{flight.getPeerAddress(), record});
			
			byte[] recordBytes = record.toByteArray();
			if (payload.length + recordBytes.length > config.getMaxPayloadSize()) {
				// can't add the next record, send current payload as datagram
				DatagramPacket datagram = new DatagramPacket(payload, payload.length, flight.getPeerAddress().getAddress(), flight.getPeerAddress().getPort());
				datagrams.add(datagram);
				payload = new byte[] {};
			}

			// retrieve payload
			payload = ByteArrayUtils.concatenate(payload, recordBytes);
		}
		DatagramPacket datagram = new DatagramPacket(payload, payload.length,
				flight.getPeerAddress().getAddress(), flight.getPeerAddress().getPort());
		datagrams.add(datagram);

		// send it over the UDP socket
		try {
			for (DatagramPacket datagramPacket : datagrams) {
				if (!socket.isClosed()) {
					socket.send(datagramPacket);
				} else {
					LOGGER.log(Level.FINE, "Socket [{0}] is closed, discarding packet ...", config.getAddress());
				}
			}
			
		} catch (IOException e) {
			LOGGER.log(Level.WARNING, "Could not send datagram", e);
		}
	}
	
	private void handleTimeout(DTLSFlight flight) {

		// set DTLS retransmission maximum
		final int max = config.getMaxRetransmissions();

		// check if limit of retransmissions reached
		if (flight.getTries() < max) {

			flight.incrementTries();

		sendFlight(flight);

			// schedule next retransmission
			scheduleRetransmission(flight);

		} else {
			LOGGER.fine("Maximum retransmissions reached.");
		}
	}

	private void scheduleRetransmission(DTLSFlight flight) {

		// cancel existing schedule (if any)
		if (flight.getRetransmitTask() != null) {
			flight.getRetransmitTask().cancel();
		}

		if (flight.isRetransmissionNeeded()) {
			// create new retransmission task
			flight.setRetransmitTask(new RetransmitTask(flight));
			
			// calculate timeout using exponential back-off
			if (flight.getTimeout() == 0) {
				// use initial timeout
				flight.setTimeout(config.getRetransmissionTimeout());
			} else {
				// double timeout
				flight.incrementTimeout();
			}
	
			// schedule retransmission task
			timer.schedule(flight.getRetransmitTask(), flight.getTimeout());
		}
	}
	
	/**
	 * Cancels the retransmission timer of the previous flight (if available).
	 * 
	 * @param peerAddress the peer's IP address and port
	 */
	private void cancelPreviousFlight(InetSocketAddress peerAddress) {
		DTLSFlight previousFlight = getFlight(peerAddress);
		if (previousFlight != null) {
			previousFlight.getRetransmitTask().cancel();
			previousFlight.setRetransmitTask(null);
			removeFlight(peerAddress);
		}
	}

	@Override
	public final InetSocketAddress getAddress() {
		if (socket == null) {
			return config.getAddress();
		} else {
			return new InetSocketAddress(socket.getLocalAddress(), socket.getLocalPort());
		}
	}
	
	public final boolean isRunning() {
		return running;
	}

	private class RetransmitTask extends TimerTask {

		private DTLSFlight flight;

		RetransmitTask(DTLSFlight flight) {
			this.flight = flight;
		}

		@Override
		public void run() {
			handleTimeout(flight);
		}
	}
	
	/**
	 * A worker thread for continuously doing repetitive tasks.
	 */
	private abstract class Worker extends Thread {

		/**
		 * Instantiates a new worker.
		 *
		 * @param name the name, e.g., of the transport protocol
		 */
		private Worker(String name) {
			super(name);
			setDaemon(true);
		}

		public void run() {
			try {
				LOGGER.log(Level.CONFIG, "Starting worker thread [{0}]", getName());
				while (running) {
					try {
						doWork();
					} catch (ClosedByInterruptException e) {
						LOGGER.log(Level.CONFIG, "Worker thread [{0}] has been interrupted", getName());
					} catch (Exception e) {
						if (running) {
							LOGGER.log(Level.FINE, "Exception thrown by worker thread [" + getName() + "]", e);
						}
					}
				}
			} finally {
				LOGGER.log(Level.CONFIG, "Worker thread [{0}] has terminated", getName());
			}
		}

		/**
		 * Does the actual work.
		 * 
		 * Subclasses should do the repetitive work here.
		 * 
		 * @throws Exception if something goes wrong
		 */
		protected abstract void doWork() throws Exception;
	}

	@Override
	public void setRawDataReceiver(RawDataChannel messageHandler) {
		this.messageHandler = messageHandler;
	}

	private void connectionClosed(InetSocketAddress peerAddress) {
		if (peerAddress != null) {
			sessionStore.remove(peerAddress);
			removeHandshaker(peerAddress);
		}
	}
}
