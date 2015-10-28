/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add support for stale
 *                                                    session expiration (466554)
 *    Kai Hudalla (Bosch Software Innovations GmbH) - replace SessionStore with ConnectionStore
 *                                                    keeping all information about the connection
 *                                                    to a peer in a single place
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 472196
 *    Achim Kraus, Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 478538
 *    Kai Hudalla (Bosch Software Innovations GmbH) - derive max datagram size for outbound messages
 *                                                    from network MTU
 ******************************************************************************/
package org.eclipse.californium.scandium;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.nio.channels.ClosedByInterruptException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.ConnectionStore;
import org.eclipse.californium.scandium.dtls.ContentType;
import org.eclipse.californium.scandium.dtls.DTLSFlight;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.HandshakeMessage;
import org.eclipse.californium.scandium.dtls.Handshaker;
import org.eclipse.californium.scandium.dtls.HelloVerifyRequest;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.eclipse.californium.scandium.dtls.MaxFragmentLengthExtension;
import org.eclipse.californium.scandium.dtls.ProtocolVersion;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.ResumingClientHandshaker;
import org.eclipse.californium.scandium.dtls.ResumingServerHandshaker;
import org.eclipse.californium.scandium.dtls.ServerHandshaker;
import org.eclipse.californium.scandium.dtls.SessionAdapter;
import org.eclipse.californium.scandium.dtls.SessionId;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.InvalidMacException;
import org.eclipse.californium.scandium.util.ByteArrayUtils;


/**
 * A {@link Connector} using <em>Datagram TLS</em> (DTLS) as specified in
 * <a href="http://tools.ietf.org/html/rfc6347">RFC 6347</a> for securing data
 * exchanged between networked clients and a server application.
 */
public class DTLSConnector implements Connector {
	
	private final static Logger LOGGER = Logger.getLogger(DTLSConnector.class.getCanonicalName());
	private final static int MAX_PLAINTEXT_FRAGMENT_LENGTH = 16384; // max. DTLSPlaintext.length (2^14 bytes)
	private final static int MAX_CIPHERTEXT_EXPANSION =
			CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256.getMaxCiphertextExpansion(); // CBC cipher has largest expansion
	private final static int MAX_DATAGRAM_BUFFER_SIZE = MAX_PLAINTEXT_FRAGMENT_LENGTH
			+ 12 // DTLS message headers
			+ 13 // DTLS record headers
			+ MAX_CIPHERTEXT_EXPANSION;

	private InetSocketAddress lastBindAddress;
	private int maximumTransmissionUnit = 1280; // min. IPv6 MTU
	private int inboundDatagramBufferSize = MAX_DATAGRAM_BUFFER_SIZE;

	// guard access to cookieMacKey
	private Object cookieMacKeyLock = new Object();
	// last time when the master key was generated
	private long lastGenerationDate = System.currentTimeMillis();
	private SecretKey cookieMacKey = new SecretKeySpec(randomBytes(), "MAC");
	
	/** all the configuration options for the DTLS connector */ 
	private final DtlsConnectorConfig config;

	private DatagramSocket socket;
	
	/** The timer daemon to schedule retransmissions. */
	private Timer timer;
	
	/** The thread that receives messages */
	private Worker receiver;
	
	/** The thread that sends messages */
	private Worker sender;
	
	private final ConnectionStore connectionStore;
	
	/** A queue for buffering outgoing messages */
	private final BlockingQueue<RawData> outboundMessages;
	
	/** Indicates whether the connector has started and not stopped yet */
	private boolean running;
	
	private RawDataChannel messageHandler;

	private ErrorHandler errorHandler;
	
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
	 * @param connectionStore the store to use for keeping track of connection information,
	 *       if <code>null</code> connection information is kept in-memory
	 * @throws NullPointerException if the configuration is <code>null</code>
	 */
	public DTLSConnector(DtlsConnectorConfig configuration, ConnectionStore connectionStore) {
		if (configuration == null) {
			throw new NullPointerException("Configuration must not be null");
		} else {
			this.config = configuration;
		}
		this.outboundMessages = new LinkedBlockingQueue<RawData>(config.getOutboundMessageBufferSize());
		if (connectionStore != null) {
			this.connectionStore = connectionStore;
		} else {
			this.connectionStore = new InMemoryConnectionStore();
		}
		
	}
	
	/**
	 * Creates a DTLS connector for PSK based authentication only.
	 * 
	 * @param address the IP address and port to bind to
	 * @deprecated Use {@link #DTLSConnector(DtlsConnectorConfig, ConnectionStore)} instead
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
	 * @deprecated Use {@link #DTLSConnector(DtlsConnectorConfig, ConnectionStore)} instead
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
	 * @param connectionStore the store to use for keeping track of connection information,
	 *       if <code>null</code> connection information is kept in-memory
	 * @param config the configuration options to use
	 * @deprecated Use {@link #DTLSConnector(DtlsConnectorConfig, ConnectionStore)} instead
	 */
	public DTLSConnector(InetSocketAddress address, Certificate[] rootCertificates,
			ConnectionStore connectionStore, DTLSConnectorConfig config) {
		Builder builder = new Builder(address);
		if (config != null) {
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
		this.outboundMessages = new LinkedBlockingQueue<RawData>(this.config.getOutboundMessageBufferSize());
		if (connectionStore != null) {
			this.connectionStore = connectionStore;
		} else {
			this.connectionStore = new InMemoryConnectionStore();
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
		Connection connection = connectionStore.get(peerAddress);
		if (connection != null && connection.getEstablishedSession() != null) {
			terminateConnection(
					connection,
					new AlertMessage(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY, peerAddress),
					connection.getEstablishedSession());
		}
	}

	@Override
	public final synchronized void start() throws IOException {
		start(config.getAddress());
	}

	/**
	 * Re-starts the connector binding to the same IP address and port as
	 * on the previous start.
	 * 
	 * @throws IOException if the connector cannot be bound to the previous
	 *            IP address and port
	 */
	final synchronized void restart() throws IOException {
		if (lastBindAddress != null) {
			start(lastBindAddress);
		} else {
			throw new IllegalStateException("Connector has never been started before");
		}
	}

	private void start(InetSocketAddress bindAddress) throws IOException {
		if (running) {
			return;
		}
		timer = new Timer(true); // run as daemon
		socket = new DatagramSocket(null);
		// make it easier to stop/start a server consecutively without delays
		socket.setReuseAddress(true);
		socket.bind(bindAddress);
		NetworkInterface ni = NetworkInterface.getByInetAddress(bindAddress.getAddress());
		if (ni != null && ni.getMTU() > 0) {
			this.maximumTransmissionUnit = ni.getMTU();
		} else {
			LOGGER.config("Cannot determine MTU of network interface, using minimum MTU [1280] of IPv6 instead");
			this.maximumTransmissionUnit = 1280;
		}

		if (config.getMaxFragmentLengthCode() != null) {
			MaxFragmentLengthExtension.Length lengthCode = MaxFragmentLengthExtension.Length.fromCode(
					config.getMaxFragmentLengthCode());
			// reduce inbound buffer size accordingly
			inboundDatagramBufferSize = lengthCode.length()
					+ MAX_CIPHERTEXT_EXPANSION
					+ 25; // 12 bytes DTLS message headers, 13 bytes DTLS record headers
		}

		lastBindAddress = new InetSocketAddress(socket.getLocalAddress(), socket.getLocalPort());
		running = true;

		sender = new Worker("DTLS-Sender-" + lastBindAddress) {
				public void doWork() throws Exception {
					sendNextMessageOverNetwork();
				}
			};

		receiver = new Worker("DTLS-Receiver-" + lastBindAddress) {
				public void doWork() throws Exception {
					receiveNextDatagramFromNetwork();
				}
			};

		receiver.start();
		sender.start();
		LOGGER.log(
				Level.INFO,
				"DLTS connector listening on [{0}] with MTU [{1}] using (inbound) datagram buffer size [{2} bytes]",
				new Object[]{lastBindAddress, maximumTransmissionUnit, inboundDatagramBufferSize});
	}

	/**
	 * Force connector to an abbreviated handshake. See <a href="https://tools.ietf.org/html/rfc5246#section-7.3">RFC 5246</a>.
	 * 
	 * The abbreviated handshake will be done next time data will be sent with {@link #send(RawData)}.
	 * @param peer the peer for which we will force to do an abbreviated handshake
	 */
	public synchronized void forceResumeSessionFor(InetSocketAddress peer){
		Connection peerConnection = connectionStore.get(peer);
		if (peerConnection != null && peerConnection.getEstablishedSession() != null)
			peerConnection.setResumptionRequired(true);
	}

	/**
	 * Stops the sender and receiver threads and closes the socket
	 * used for sending and receiving datagrams.
	 */
	final synchronized void releaseSocket() {
		running = false;
		sender.interrupt();
		outboundMessages.clear();
		if (socket != null) {
			socket.close();
			socket = null;
		}
		maximumTransmissionUnit = 0;
	}

	@Override
	public final synchronized void stop() {
		if (!running) {
			return;
		}
		LOGGER.log(Level.INFO, "Stopping DLTS connector on [{0}]", lastBindAddress);
		timer.cancel();
		releaseSocket();
	}

	/**
	 * Destroys the connector.
	 * <p>
	 * This method invokes {@link #stop()} and clears the <code>ConnectionStore</code>
	 * used to manage connections to peers. Thus, contrary to the behavior specified
	 * for {@link Connector#destroy()}, this connector can be re-started using the
	 * {@link #start()} method but subsequent invocations of the {@link #send(RawData)}
	 * method will trigger the establishment of a new connection to the corresponding peer.
	 * </p>
	 */
	@Override
	public final synchronized void destroy() {
		stop();
		connectionStore.clear();
	}

	private void receiveNextDatagramFromNetwork() throws IOException {
		byte[] buffer = new byte[inboundDatagramBufferSize];
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
		List<Record> records = Record.fromByteArray(data, peerAddress);
		LOGGER.log(Level.FINER, "Received {0} DTLS records using a {1} byte datagram buffer",
				new Object[]{records.size(), inboundDatagramBufferSize});

		for (Record record : records) {
			try {
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
			} catch (InvalidMacException e) {
				// this means that the message from the record could not be authenticated
				// maybe because the record has been sent in a forged UDP datagram by an attacker
				// the DTLS 1.2 spec section 4.1.2.7 (see http://tools.ietf.org/html/rfc6347#section-4.1.2.7)
				// advises to silently discard such records
				LOGGER.log(Level.FINE, "Discarding [{0}] record from peer [{1}]: MAC validation failed",
						new Object[]{record.getType(), peerAddress});
			} catch (GeneralSecurityException e) {
				// this means that the message could not be decrypted, e.g. because the JVM does
				// not support the negotiated cipher algorithm or the ciphertext has the wrong block size etc.
				// the DTLS 1.2 spec section 4.1.2.7 (see http://tools.ietf.org/html/rfc6347#section-4.1.2.7)
				// advises to silently discard such records
				LOGGER.log(Level.FINE, "Discarding [{0}] record from peer [{1}]: {2}",
						new Object[]{record.getType(), peerAddress, e.getMessage()});
			} catch (HandshakeException e) {
				if (AlertLevel.FATAL.equals(e.getAlert().getLevel())) {
					LOGGER.log(Level.INFO, "Aborting handshake with peer [{1}]: {2}",
							new Object[]{record.getType(), peerAddress, e.getMessage()});
					terminateOngoingHandshake(peerAddress, e.getAlert());
					break;
				} else {
					LOGGER.log(Level.FINE, "Discarding [{0}] record from peer [{1}]: {2}",
							new Object[]{record.getType(), peerAddress, e.getMessage()});
				}
			}
		}
	}

	/**
	 * Immediately terminates an ongoing handshake with a peer.
	 * 
	 * Terminating the handshake includes
	 * <ul>
	 * <li>canceling any pending retransmissions to the peer</li>
	 * <li>destroying any state for an ongoing handshake with the peer</li>
	 * </ul>
	 * 
	 * @param peerAddress the peer to terminate the handshake with
	 * @param alert the message to send to the peer before terminating the handshake
	 */
	private void terminateOngoingHandshake(InetSocketAddress peerAddress, AlertMessage alert) {

		Connection connection = connectionStore.get(peerAddress);
		if (connection != null && connection.getOngoingHandshake() != null) {
			DTLSSession session = connection.getOngoingHandshake().getSession();
			if (connection.getEstablishedSession() == null) {
				terminateConnection(connection, alert, session);
			} else {
				// keep established session intact and only terminate ongoing handshake
				if (alert != null) {
					send(alert, session);
				}
				connection.terminateOngoingHandshake();
			}
		}
	}

	/**
	 * Immediately terminates a connection with a peer.
	 * 
	 * Terminating the connection includes
	 * <ul>
	 * <li>canceling any pending retransmissions to the peer</li>
	 * <li>destroying any established session with the peer</li>
	 * <li>destroying any handshakers for the peer</li>
	 * <li>optionally sending a final ALERT to the peer (if a session exists with the peer)</li>
	 * </ul>
	 * 
	 * @param connection the connection to terminate
	 * @param alert the message to send to the peer before terminating the connection (may be <code>null</code>)
	 * @param session the parameters to encrypt the alert message with (may be <code>null</code> if alert is
	 *           <code>null</code>)
	 */
	private void terminateConnection(Connection connection, AlertMessage alert, DTLSSession session) {
		if (alert != null && session == null) {
			throw new IllegalArgumentException("Session must not be NULL if alert message is to be sent");
		}

		connection.cancelPendingFlight();

		if (alert == null) {
			LOGGER.log(Level.FINE, "Terminating connection with peer [{0}]", connection.getPeerAddress());
		} else {
			LOGGER.log(Level.FINE, "Terminating connection with peer [{0}], reason [{1}]",
					new Object[]{connection.getPeerAddress(), alert.getDescription()});
			send(alert, session);
		}
		// clear session & (pending) handshaker
		connectionClosed(connection.getPeerAddress());
	}

	private void processApplicationDataRecord(InetSocketAddress peerAddress, Record record)
			throws GeneralSecurityException, HandshakeException {

		Connection connection = connectionStore.get(peerAddress);
		DTLSSession session = null;
		if (connection != null)
			session = connection.getEstablishedSession();

		if (session != null) {
			synchronized (session) {
				// The DTLS 1.2 spec (section 4.1.2.6) advises to do replay detection
				// before MAC validation based on the record's sequence numbers
				// see http://tools.ietf.org/html/rfc6347#section-4.1.2.6
				if (session.isRecordProcessable(record.getEpoch(), record.getSequenceNumber())) {
					// APPLICATION_DATA can only be processed within the context of
					// an established, i.e. fully negotiated, session
					record.setSession(session);
					ApplicationMessage message = (ApplicationMessage) record.getFragment();
					// the fragment could be de-crypted
					// thus, the handshake seems to have been completed successfully
					connection.handshakeCompleted(peerAddress);
					session.markRecordAsRead(record.getEpoch(), record.getSequenceNumber());
					// finally, forward de-crypted message to application layer
					if (messageHandler != null) {
						messageHandler.receiveData(new RawData(message.getData(), peerAddress, session.getPeerIdentity()));
					}
				} else {
					LOGGER.log(Level.FINER, "Discarding duplicate APPLICATION_DATA record received from peer [{0}]",
							peerAddress);
				}
			}
		} else {
			LOGGER.log(Level.FINER,
					"Discarding APPLICATION_DATA record received from peer [{0}] without an active session",
					new Object[]{peerAddress});
		}
	}

	/**
	 * Processes an <em>ALERT</em> message received from the peer.
	 * 
	 * Terminates the connection with the peer if either
	 * <ul>
	 * <li>the ALERT's level is FATAL or</li>
	 * <li>the ALERT is a <em>closure alert</em></li>
	 * </ul>
	 * 
	 * Also notifies a registered {@link #errorHandler} about the alert message.
	 * 
	 * @param peerAddress the IP address an port of the peer
	 * @param record the record containing the ALERT message
	 * @throws GeneralSecurityException if the ALERT message could not be de-crypted
	 * @throws HandshakeException if the record's content could not be parsed into an ALERT message
	 * @see ErrorHandler
	 * @see #terminateConnection(Connection, AlertMessage, DTLSSession)
	 */
	private void processAlertRecord(InetSocketAddress peerAddress, Record record) throws GeneralSecurityException, HandshakeException {

		// An ALERT can be processed at all times. If the ALERT level is fatal
		// the connection with the peer must be terminated and all session or handshake
		// state (keys, session identifier etc) must be destroyed.
		Connection connection = connectionStore.get(peerAddress);
		if (connection == null) {
			LOGGER.log(Level.FINER, "Received ALERT record from [{0}] without existing connection, discarding ...", peerAddress);
			return;
		}

		// get session for this connection
		DTLSSession session = null;
		if (connection.getEstablishedSession() == null) {
			if (record.getEpoch() > 0) {
				LOGGER.log(Level.FINER, "Received ALERT record with epoch > 0 from [{0}] without established session, discarding ...", peerAddress);
				return;
			} else {
				// we have no established session but we could have a fresh new on going handshake
				if (connection.getOngoingHandshake() != null && connection.getOngoingHandshake().getSession() != null && connection.getOngoingHandshake().getSession().getReadEpoch() == 0){
					session = connection.getOngoingHandshake().getSession();
				} else {
					LOGGER.log(Level.FINER, "Received ALERT record with epoch == 0 from [{0}] without on going handshake, discarding ...", peerAddress);
					return;
				}
			}
		} else {
			if (record.getEpoch() == 0){
				LOGGER.log(Level.FINER, "Received ALERT record with epoch == 0 from [{0}] with established session, discarding ...", peerAddress);
				return;
			} else {
				session = connection.getEstablishedSession();
			}
		}

		if (session == null) {
			LOGGER.log(Level.FINER, "Received ALERT record from [{0}] without existing session, discarding ...", peerAddress);
		} else {
			record.setSession(session);
			AlertMessage alert = (AlertMessage) record.getFragment();
			LOGGER.log(Level.FINEST, "Processing ALERT message from [{0}]:\n{1}", new Object[]{peerAddress, record});
			if (AlertDescription.CLOSE_NOTIFY.equals(alert.getDescription())) {
				// according to section 7.2.1 of the TLS 1.2 spec
				// (http://tools.ietf.org/html/rfc5246#section-7.2.1)
				// we need to respond with a CLOSE_NOTIFY alert and
				// then close and remove the connection immediately
				terminateConnection(
						connection,
						new AlertMessage(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY, peerAddress),
						session);
			} else if (AlertLevel.FATAL.equals(alert.getLevel())) {
				// according to section 7.2 of the TLS 1.2 spec
				// (http://tools.ietf.org/html/rfc5246#section-7.2)
				// the connection needs to be terminated immediately
				terminateConnection(connection, null, null);
			} else {
				// alert is not fatal, ignore for now
			}

			if (errorHandler != null) {
				errorHandler.onError(peerAddress, alert.getLevel(), alert.getDescription());
			}
		}
	}

	private void processChangeCipherSpecRecord(InetSocketAddress peerAddress, Record record) throws HandshakeException {
		Connection connection = connectionStore.get(peerAddress);
		if (connection == null || connection.getOngoingHandshake() == null) {
			// change cipher spec can only be processed within the
			// context of an existing handshake -> ignore record
			LOGGER.log(Level.FINE,
					"Discarding CHANGE_CIPHER_SPEC record from peer [{0}], no handshake in progress...",
					peerAddress);
		} else {
			// processing a CCS message does not result in any additional flight to be sent
			connection.getOngoingHandshake().processMessage(record);
		}		
	}
	
	private void processHandshakeRecord(InetSocketAddress peerAddress, Record record)
			throws HandshakeException, GeneralSecurityException {

		LOGGER.log(Level.FINER, "Received HANDSHAKE record from peer [{0}]", peerAddress);
		DTLSFlight flight = null;
		Connection connection = connectionStore.get(peerAddress);
		if (connection != null && connection.getOngoingHandshake() != null) {
			// we are already in an ongoing handshake
			// simply delegate the processing of the record to the handshaker
			flight = connection.getOngoingHandshake().processMessage(record);
		} else {

			if (record.getEpoch()>0){
				if (connection != null && connection.getEstablishedSession() != null){
					// we received a record with Epoch > 0 and we have an established session
					// so, we use it to decrypt the handshake message.
					record.setSession(connection.getEstablishedSession());
				}
				else
				{
					LOGGER.log(Level.FINER, "Discarding unexpected handshake message with epoch > 0 from peer [{0}] with no session established.",
							new Object[]{peerAddress});
					return;
				}
			}

			HandshakeMessage handshakeMessage = (HandshakeMessage) record.getFragment();

			switch (handshakeMessage.getMessageType()) {
			case HELLO_REQUEST:
				// Peer (server) wants us (client) to initiate (re-)negotiation of session
				flight = processHelloRequest(connection, record);
				break;

			case CLIENT_HELLO:
				// Peer (client) wants to either resume an existing session
				// or wants to negotiate a new session with us (server)
				flight = processClientHello(connection, record);
				break;

			default:
				LOGGER.log(Level.FINER, "Discarding unexpected handshake message of type [{0}] from peer [{1}]",
						new Object[]{handshakeMessage.getMessageType(), peerAddress});
				return;
			}
		}

		if (flight != null) {
			// we search again in the store because after message processing,
			// we could have a connection for this peer now.
			connection = connectionStore.get(peerAddress);

			if (connection != null) {
				connection.cancelPendingFlight();
				if (flight.isRetransmissionNeeded()) {
					connection.setPendingFlight(flight);
					scheduleRetransmission(flight);
				}
			}

			sendFlight(flight);
		}
		
	}
	
	private DTLSFlight processHelloRequest(final Connection connection, final Record record)
			throws HandshakeException, GeneralSecurityException {

		if (connection == null) {
			LOGGER.log(
					Level.FINE,
					"Received HELLO_REQUEST from peer [{0}] without an existing connection, discarding ...",
					record.getPeerAddress());
			return null;
		} else if (connection.getOngoingHandshake() == null) {
			DTLSSession session = connection.getEstablishedSession();
			if (session == null) {
				session = new DTLSSession(record.getPeerAddress(), true);
			}
			Handshaker handshaker = new ClientHandshaker(null, session, connection, config, maximumTransmissionUnit);
			return handshaker.getStartHandshakeMessage();
		} else {
			// nothing to do, we are already re-negotiating the session parameters
			return null;
		}
	}
	
	private DTLSFlight processClientHello(Connection connection, Record record)
			throws HandshakeException, GeneralSecurityException {
		
		DTLSFlight nextFlight = null;
		Connection peerConnection = connection;
		
		if (record.getEpoch() > 0) {
			// client tries to re-negotiate new crypto params for existing session
			if (peerConnection == null || peerConnection.getEstablishedSession() == null) {
				// no connection to peer (yet) or no established session to re-negotiate, ignore request
				LOGGER.log(Level.FINE, "Ignoring request from [{0}] to re-negotiate non-existing session", record.getPeerAddress());
			} else {
				// let handshaker figure out whether CLIENT_HELLO is from correct
				// epoch and client uses correct crypto params
				Handshaker handshaker = new ServerHandshaker(connection.getEstablishedSession(), peerConnection, config, maximumTransmissionUnit);
				nextFlight = handshaker.processMessage(record);
			}
		} else {
			// epoch == 0, i.e. client tries to negotiate fresh session
			// record payload should therefore not be encrypted
			ClientHello clientHello = (ClientHello) record.getFragment();
			
			// verify client's ability to respond on given IP address
			// by exchanging a cookie as described in section 4.2.1 of the DTLS 1.2 spec
			// see http://tools.ietf.org/html/rfc6347#section-4.2.1
			byte[] expectedCookie = generateCookie(record.getPeerAddress(), clientHello);
			if (!Arrays.equals(expectedCookie, clientHello.getCookie())) {
				LOGGER.log(Level.FINE, "Processing CLIENT_HELLO from peer [{0}]:\n{1}", new Object[]{record.getPeerAddress(), record});
				// send CLIENT_HELLO_VERIFY with cookie in order to prevent
				// DOS attack as described in DTLS 1.2 spec
				LOGGER.log(Level.FINER, "Verifying client IP address [{0}] using HELLO_VERIFY_REQUEST", record.getPeerAddress());
				HelloVerifyRequest msg = new HelloVerifyRequest(new ProtocolVersion(), expectedCookie, record.getPeerAddress());
				// because we do not have a handshaker in place yet that
				// manages message_seq numbers, we need to set it explicitly
				// use message_seq from CLIENT_HELLO in order to allow for
				// multiple consecutive cookie exchanges with a client
				msg.setMessageSeq(clientHello.getMessageSeq());
				// use epoch 0 and sequence no from CLIENT_HELLO record as
				// mandated by section 4.2.1 of the DTLS 1.2 spec
				// see http://tools.ietf.org/html/rfc6347#section-4.2.1
				Record helloVerify = new Record(ContentType.HANDSHAKE, 0, record.getSequenceNumber(), msg, record.getPeerAddress());
				nextFlight = new DTLSFlight(record.getPeerAddress());
				nextFlight.addMessage(helloVerify);
			} else {
				LOGGER.log(Level.FINER,
						"Successfully verified client IP address [{0}] using cookie exchange",
						record.getPeerAddress());
				
				// check if message contains a session identifier
				SessionId sessionId = clientHello.getSessionId().length() > 0 ? clientHello.getSessionId() : null;

				if (sessionId == null) {
					// At this point the client has demonstrated reachability by completing a cookie exchange
					// so we can terminate the previous session.
					// (see section 4.2.8 of RFC 6347 (DTLS 1.2))
					if (peerConnection != null) {
						terminateConnection(connection, null, null);
					}
					peerConnection = new Connection(record.getPeerAddress());
					connectionStore.put(peerConnection);

					// use the record sequence number from CLIENT_HELLO as initial sequence number
					// for records sent to the client (see section 4.2.1 of RFC 6347 (DTLS 1.2))
					DTLSSession newSession = new DTLSSession(record.getPeerAddress(), false, record.getSequenceNumber());
					// initialize handshaker based on CLIENT_HELLO (this accounts
					// for the case that multiple cookie exchanges have taken place)
					Handshaker handshaker = new ServerHandshaker(clientHello.getMessageSeq(),
							newSession, peerConnection, config, maximumTransmissionUnit);
					nextFlight = handshaker.processMessage(record);
				} else {
					// client wants to resume a cached session
					LOGGER.log(Level.FINER, "Client [{0}] wants to resume session with ID [{1}]",
							new Object[]{record.getPeerAddress(), ByteArrayUtils.toHexString(sessionId.getSessionId())});
					final Connection previousConnection = connectionStore.find(sessionId);
					if (previousConnection != null && previousConnection.getEstablishedSession() != null) {
						// session has been found in cache, resume it
						DTLSSession resumableSession = new DTLSSession(record.getPeerAddress(),previousConnection.getEstablishedSession(),record.getSequenceNumber());
						peerConnection = new Connection(record.getPeerAddress());

						Handshaker handshaker = new ResumingServerHandshaker(clientHello.getMessageSeq(),
								resumableSession, peerConnection, config, maximumTransmissionUnit);

						if (!previousConnection.getPeerAddress().equals(peerConnection.getPeerAddress())) {
							handshaker.addSessionListener(new SessionAdapter() {
								@Override
								public void sessionEstablished(Handshaker handshaker, DTLSSession establishedSession)
										throws HandshakeException {
									// when the session will be established for this new connection, remove the previous one.
									LOGGER.log(Level.FINER,
											"Remove old connection to [{0}], session with ID [{1}] was successfully resumed on peer [{2}] ",
											new Object[]{previousConnection.getPeerAddress(),ByteArrayUtils.toHexString(establishedSession.getSessionIdentifier().getSessionId()),establishedSession.getPeer()});
									terminateConnection(previousConnection, null, null);
								}
							});
						} else {
							// remove immediately the previous connection;
							terminateConnection(previousConnection, null, null);
						}
						// add the new one to the store
						connectionStore.put(peerConnection);
					
						// process message
						nextFlight = handshaker.processMessage(record);
					} else {
						LOGGER.log(Level.FINER, "Client [{0}] tries to resume non-existing session with ID [{1}], starting new handshake...",
								new Object[]{record.getPeerAddress(), ByteArrayUtils.toHexString(sessionId.getSessionId())});
						// At this point the client has demonstrated reachability by completing a cookie exchange
						// so we can terminate the previous session.
						// (see section 4.2.8 of RFC 6347 (DTLS 1.2))
						if (peerConnection != null) {
							terminateConnection(peerConnection, null, null);
						}
						peerConnection = new Connection(record.getPeerAddress());
						connectionStore.put(peerConnection);

						// use the record sequence number from CLIENT_HELLO as initial sequence number
						// for records sent to the client (see section 4.2.1 of RFC 6347 (DTLS 1.2))
						DTLSSession newSession = new DTLSSession(record.getPeerAddress(), false, record.getSequenceNumber());
						// initialize handshaker based on CLIENT_HELLO (this accounts
						// for the case that multiple cookie exchanges have taken place)
						Handshaker handshaker = new ServerHandshaker(clientHello.getMessageSeq(),
								newSession, peerConnection, config, maximumTransmissionUnit);
						nextFlight = handshaker.processMessage(record);
					}
				}
			}
		}
		
		return nextFlight;
	}

	private SecretKey getMacKeyForCookies() {
		synchronized (cookieMacKeyLock) {
			// if the last generation was more than 5 minute ago, let's generate
			// a new key
			if (System.currentTimeMillis() - lastGenerationDate > TimeUnit.MINUTES.toMillis(5)) {
				cookieMacKey = new SecretKeySpec(randomBytes(), "MAC");
				lastGenerationDate = System.currentTimeMillis();
			}
			return cookieMacKey;
		}

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
	private byte[] generateCookie(InetSocketAddress peerAddress, ClientHello clientHello)
		throws HandshakeException {

		try {
			// Cookie = HMAC(Secret, Client-IP, Client-Parameters)
			Mac hmac = Mac.getInstance("HmacSHA256");
			hmac.init(getMacKeyForCookies());
			// Client-IP
			hmac.update(peerAddress.toString().getBytes());

			// Client-Parameters
			hmac.update((byte) clientHello.getClientVersion().getMajor());
			hmac.update((byte) clientHello.getClientVersion().getMinor());
			hmac.update(clientHello.getRandom().getRandomBytes());
			hmac.update(clientHello.getSessionId().getSessionId());
			hmac.update(CipherSuite.listToByteArray(clientHello.getCipherSuites()));
			hmac.update(CompressionMethod.listToByteArray(clientHello.getCompressionMethods()));
			return hmac.doFinal();
		} catch (GeneralSecurityException e) {
			LOGGER.log(Level.SEVERE,"Could not instantiate MAC algorithm for cookie creation", e);
			throw new HandshakeException("Internal error", new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, peerAddress));
		}
	}

	void send(AlertMessage alert, DTLSSession session) {
		if (alert == null) {
			throw new IllegalArgumentException("Alert must not be NULL");
		} else if (session == null) {
			throw new IllegalArgumentException("Session must not be NULL");
		} else {
			try {
				DTLSFlight flight = new DTLSFlight(session);
				flight.setRetransmissionNeeded(false);
				flight.addMessage(new Record(ContentType.ALERT, session.getWriteEpoch(), session.getSequenceNumber(), alert, session));
				sendFlight(flight);
			} catch (GeneralSecurityException e) {
				LOGGER.log(Level.FINE, "Cannot create ALERT message for peer [{0}] due to [{1}]",
						new Object[]{session.getPeer(), e.getMessage()});
			}
		}
	}

	@Override
	public final void send(RawData msg) {
		if (msg == null) {
			LOGGER.finest("Ignoring NULL msg ...");
		} else if (msg.getBytes().length > MAX_PLAINTEXT_FRAGMENT_LENGTH) {
			throw new IllegalArgumentException("Message data must not exceed "
					+ MAX_PLAINTEXT_FRAGMENT_LENGTH + " bytes");
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
			Thread.currentThread().interrupt();
			return;
		}
		
		InetSocketAddress peerAddress = message.getInetSocketAddress();
		LOGGER.log(Level.FINER, "Sending application layer message to peer [{0}]", peerAddress);
		Connection connection = connectionStore.get(peerAddress);
		
		/*
		 * When the DTLS layer receives a message from an upper layer, there is
		 * either already a DTLS session established with the peer or a new
		 * handshake must be initiated. If a session is available and active, the
		 * message will be encrypted and sent to the peer, otherwise a short
		 * handshake will be initiated.
		 */
		
		// TODO make sure that only ONE handshake is in progress with a peer
		// at all times
		
		Handshaker handshaker = null;
		DTLSFlight flight = null;

		try {
			if (connection == null) {
				connection = new Connection(peerAddress);
				connectionStore.put(connection);
			}
			
			DTLSSession session = connection.getEstablishedSession();
			if (session == null) {
				// no session with peer available, create new empty session &
				// start fresh handshake
				handshaker = new ClientHandshaker(message, new DTLSSession(peerAddress, true), connection, config, maximumTransmissionUnit);
			}
			// TODO what if there already is an ongoing handshake with the peer
			else if (connection.isResumptionRequired()){
				// create the session to resume from the previous one.
				DTLSSession resumableSession = new DTLSSession(peerAddress, session, 0);

				// terminate the previous connection and add the new one to the store
				Connection newConnection = new Connection(peerAddress);
				terminateConnection(connection, null, null);
				connectionStore.put(newConnection);
				handshaker = new ResumingClientHandshaker(message, resumableSession, newConnection, config, maximumTransmissionUnit);
			} else {
				// session to peer is active, send encrypted message
				flight = new DTLSFlight(session);
				flight.addMessage(new Record(
						ContentType.APPLICATION_DATA,
						session.getWriteEpoch(),
						session.getSequenceNumber(),
						new ApplicationMessage(message.getBytes(), peerAddress),
						session));
			}
			// start DTLS handshake protocol
			if (handshaker != null) {
				// get starting handshake message
				flight = handshaker.getStartHandshakeMessage();
				connection.setPendingFlight(flight);
				scheduleRetransmission(flight);
			}
			sendFlight(flight);
		} catch (GeneralSecurityException e) {
			LOGGER.log(Level.FINE, "Cannot send record to peer [{0}] due to [{1}]",
					new Object[]{peerAddress, e.getMessage()});
		}
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
		Connection connection = connectionStore.get(address);
		if (connection != null) {
			return connection.getEstablishedSession();
		} else {
			return null;
		}
	}

	private void sendFlight(DTLSFlight flight) {
		byte[] payload = new byte[] {};
		int maxDatagramSize = maximumTransmissionUnit;
		if (flight.getSession() != null) {
			// the max. fragment length reported by the session will be
			// slightly smaller than the (assumed) PMTU to the peer because it doesn't
			// account for payload expansion introduced by cipher and headers
			maxDatagramSize = flight.getSession().getMaxDatagramSize();
		}

		// put as many records into one datagram as allowed by the max. payload size
		List<DatagramPacket> datagrams = new ArrayList<DatagramPacket>();

		try {
			for (Record record : flight.getMessages()) {
				if (flight.getTries() > 0) {
					// adjust the record sequence number
					int epoch = record.getEpoch();
					record.setSequenceNumber(flight.getSession().getSequenceNumber(epoch));
				}

				byte[] recordBytes = record.toByteArray();
				if (recordBytes.length > maxDatagramSize) {
					LOGGER.log(
							Level.INFO,
							"{0} record of {1} bytes for peer [{2}] exceeds max. datagram size [{3}], discarding...",
							new Object[]{record.getType(), recordBytes.length, record.getPeerAddress(), maxDatagramSize});
					// TODO: inform application layer, e.g. using error handler
					continue;
				}
				LOGGER.log(
						Level.FINEST,
						"Sending record of {2} bytes to peer [{0}]:\n{1}",
						new Object[]{flight.getPeerAddress(), record, recordBytes.length});

				if (payload.length + recordBytes.length > maxDatagramSize) {
					// current record does not fit into datagram anymore
					// thus, send out current datagram and put record into new one
					DatagramPacket datagram = new DatagramPacket(payload, payload.length,
							flight.getPeerAddress().getAddress(), flight.getPeerAddress().getPort());
					datagrams.add(datagram);
					payload = new byte[] {};
				}

				payload = ByteArrayUtils.concatenate(payload, recordBytes);
			}

			DatagramPacket datagram = new DatagramPacket(payload, payload.length,
					flight.getPeerAddress().getAddress(), flight.getPeerAddress().getPort());
			datagrams.add(datagram);

			// send it over the UDP socket
			LOGGER.log(Level.FINER, "Sending flight of {0} message(s) to peer [{1}] using {2} datagram(s) of max. {3} bytes",
					new Object[]{flight.getMessages().size(), flight.getPeerAddress(), datagrams.size(), maxDatagramSize});
			for (DatagramPacket datagramPacket : datagrams) {
				if (!socket.isClosed()) {
					socket.send(datagramPacket);
				} else {
					LOGGER.log(Level.FINE, "Socket [{0}] is closed, discarding packet ...", config.getAddress());
				}
			}

		} catch (IOException e) {
			LOGGER.log(Level.WARNING, "Could not send datagram", e);
		} catch (GeneralSecurityException e) {
			LOGGER.log(Level.INFO, "Cannot send flight to peer [{0}] due to [{1}]",
					new Object[]{flight.getPeerAddress(), e.getMessage()});
		}
	}
	
	private void handleTimeout(DTLSFlight flight) {

		// set DTLS retransmission maximum
		final int max = config.getMaxRetransmissions();

		// check if limit of retransmissions reached
		if (flight.getTries() < max) {
			LOGGER.log(Level.FINE, "Re-transmitting flight for [{0}], [{1}] retransmissions left",
					new Object[]{flight.getPeerAddress(), max - flight.getTries() - 1});

			flight.incrementTries();
			sendFlight(flight);

			// schedule next retransmission
			scheduleRetransmission(flight);
		} else {
			LOGGER.log(Level.FINE, "Flight for [{0}] has reached maximum no. [{1}] of retransmissions",
					new Object[]{flight.getPeerAddress(), max});
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
	 * Gets the MTU value of the network interface this connector is bound to.
	 * <p>
	 * Applications may use this property to determine the maximum length of application
	 * layer data that can be sent using this connector without requiring IP fragmentation.
	 * <p> 
	 * The value returned will be 0 if this connector is not running or the network interface
	 * this connector is bound to does not provide an MTU value.
	 * 
	 * @return the MTU provided by the network interface
	 */
	public int getMaximumTransmissionUnit() {
		return maximumTransmissionUnit;
	}

	/**
	 * Gets the maximum amount of unencrypted payload data that can be sent to a given
	 * peer in a single DTLS record.
	 * <p>
	 * The value of this property serves as an upper boundary for the <em>DTLSPlaintext.length</em>
	 * field defined in <a href="http://tools.ietf.org/html/rfc6347#section-4.3.1">DTLS 1.2 spec,
	 * Section 4.3.1</a>. This means that an application can assume that any message containing at
	 * most as many bytes as indicated by this method, will be delivered to the peer in a single
	 * unfragmented datagram.
	 * </p>
	 * <p>
	 * The value returned by this method considers the <em>current write state</em> of the connection
	 * to the peer and any potential ciphertext expansion introduced by this cipher suite used to
	 * secure the connection. However, if no connection exists to the peer, the value returned is
	 * determined as follows:
	 * </p>
	 * <pre>
	 *   maxFragmentLength = network interface's <em>Maximum Transmission Unit</em>
	 *                     - IP header length (20 bytes)
	 *                     - UDP header length (8 bytes)
	 *                     - DTLS record header length (13 bytes)
	 *                     - DTLS message header length (12 bytes)
	 * </pre>
	 * 
	 * @param peer the address of the remote endpoint
	 * 
	 * @return the maximum length in bytes
	 */
	public int getMaximumFragmentLength(InetSocketAddress peer) {
		Connection con = connectionStore.get(peer);
		if (con != null && con.getEstablishedSession() != null) {
			return con.getEstablishedSession().getMaxFragmentLength();
		} else {
			return maximumTransmissionUnit - DTLSSession.HEADER_LENGTH;
		}
	}

	/**
	 * Gets the address this connector is bound to.
	 * 
	 * @return the IP address and port this connector is bound to or configured to
	 *            bind to
	 */
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

	/**
	 * Sets a handler to call back if an alert message is received from a peer.
	 * 
	 * @param errorHandler the handler to invoke
	 */
	public final void setErrorHandler(ErrorHandler errorHandler) {
		this.errorHandler = errorHandler;
	}

	private void connectionClosed(InetSocketAddress peerAddress) {
		if (peerAddress != null) {
			connectionStore.remove(peerAddress);
		}
	}

	/** generate a random byte[] of length 32 **/
	private byte[] randomBytes() {
		SecureRandom rng = new SecureRandom();
		byte[] result = new byte[32];
		rng.nextBytes(result);
		return result;
	}
}
