/*******************************************************************************
 * Copyright (c) 2015, 2018 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 483371
 *    Benjamin Cabe - fix typos in logger
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use SessionListener to trigger sending of pending
 *                                                    APPLICATION messages
 *    Bosch Software Innovations GmbH - set correlation context on sent/received messages
 *                                      (fix GitHub issue #1)
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CorrelationContextMatcher
 *                                                    for outgoing messages
 *                                                    (fix GitHub issue #104)
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce synchronized getSocket()
 *                                                    as pair to synchronized releaseSocket().
 *    Achim Kraus (Bosch Software Innovations GmbH) - restart internal executor
 *    Achim Kraus (Bosch Software Innovations GmbH) - processing retransmission of flight
 *                                                    after last flight was sent.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add onSent() and onError(). 
 *                                                    issue #305
 *    Achim Kraus (Bosch Software Innovations GmbH) - Change RetransmitTask to
 *                                                    schedule a "stripped job"
 *                                                    instead of executing 
 *                                                    handleTimeout directly.
 *                                                    cancel flight only, if they
 *                                                    should not be retransmitted
 *                                                    anymore.
 *    Achim Kraus (Bosch Software Innovations GmbH) - call handshakeFailed on 
 *                                                    terminateOngoingHandshake,
 *                                                    processAlertRecord, 
 *                                                    handleTimeout,
 *                                                    and add error callback in
 *                                                    newDeferredMessageSender.
 *    Achim Kraus (Bosch Software Innovations GmbH) - reuse receive buffer and packet. 
 *    Achim Kraus (Bosch Software Innovations GmbH) - use socket's reuseAddress only
 *                                                    if bindAddress determines a port
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce protocol,
 *                                                    remove scheme
 *    Achim Kraus (Bosch Software Innovations GmbH) - check for cancelled retransmission
 *                                                    before sending.
 *    Achim Kraus (Bosch Software Innovations GmbH) - move application handler call
 *                                                    out of synchronized block
 *    Achim Kraus (Bosch Software Innovations GmbH) - move creation of endpoint context
 *                                                    to DTLSSession
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - add automatic resumption
 *    Achim Kraus (Bosch Software Innovations GmbH) - change receiver thread to
 *                                                    daemon
 *    Achim Kraus (Bosch Software Innovations GmbH) - response with alert, if 
 *                                                    connection store is exhausted.
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix double incrementing
 *                                                    pending outgoing message downcounter.
 *    Achim Kraus (Bosch Software Innovations GmbH) - update dtls session timestamp only,
 *                                                    if access is validated with the MAC 
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix session resumption with session cache
 *                                                    issue #712
 *                                                    execute jobs after shutdown to ensure, 
 *                                                    onError is called for all pending messages. 
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix issues #716 and #717
 *                                                    change scopes to protected to support
 *                                                    subclass specific implementations.
 *    Achim Kraus (Bosch Software Innovations GmbH) - use session ticket when sending messages
 *                                                    over a connection marked for resumption.
 *    Achim Kraus (Bosch Software Innovations GmbH) - issue 744: use handshaker as 
 *                                                    parameter for session listener.
 *                                                    Move session listener callback out of sync
 *                                                    block of processApplicationDataRecord.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add handshakeFlightRetransmitted
 *    Achim Kraus (Bosch Software Innovations GmbH) - add onConnecting and onDtlsRetransmission
 *    Achim Kraus (Bosch Software Innovations GmbH) - redesign connection session listener to
 *                                                    ensure, that the session listener methods
 *                                                    are called via the handshaker.
 *                                                    Move handshakeCompleted out on synchronized block.
 *                                                    When handshaker replaced, called handshakeFailed
 *                                                    on old to trigger sent error for pending messages.
 *                                                    Reuse ongoing handshaker instead of creating a new
 *                                                    one.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add multiple receiver threads.
 *                                                    move default thread numbers to configuration.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add cause to handshake failure.
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove HELLO_VERIFY_REQUEST
 *                                                    from resumption handshakes
 *    Achim Kraus (Bosch Software Innovations GmbH) - extend deferred processed messages to
 *                                                    limited number of incoming and outgoing messages
 *                                                    extend executor names with specific prefix.
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix reuse of already stopped serial
 *                                                    executors.
 ******************************************************************************/
package org.eclipse.californium.scandium;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.nio.channels.ClosedByInterruptException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.EndpointMismatchException;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.LeastRecentlyUsedCache;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.elements.util.SerialExecutor;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.ApplicationMessage;
import org.eclipse.californium.scandium.dtls.ClientHandshaker;
import org.eclipse.californium.scandium.dtls.ClientHello;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.ContentType;
import org.eclipse.californium.scandium.dtls.DTLSFlight;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.DtlsHandshakeException;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.HandshakeMessage;
import org.eclipse.californium.scandium.dtls.HandshakeType;
import org.eclipse.californium.scandium.dtls.Handshaker;
import org.eclipse.californium.scandium.dtls.HelloRequest;
import org.eclipse.californium.scandium.dtls.HelloVerifyRequest;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.eclipse.californium.scandium.dtls.MaxFragmentLengthExtension;
import org.eclipse.californium.scandium.dtls.ProtocolVersion;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.RecordLayer;
import org.eclipse.californium.scandium.dtls.ResumingClientHandshaker;
import org.eclipse.californium.scandium.dtls.ResumingServerHandshaker;
import org.eclipse.californium.scandium.dtls.ResumptionSupportingConnectionStore;
import org.eclipse.californium.scandium.dtls.ServerHandshaker;
import org.eclipse.californium.scandium.dtls.SessionAdapter;
import org.eclipse.californium.scandium.dtls.SessionCache;
import org.eclipse.californium.scandium.dtls.SessionId;
import org.eclipse.californium.scandium.dtls.SessionListener;
import org.eclipse.californium.scandium.dtls.SessionTicket;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.util.ByteArrayUtils;

/**
 * A {@link Connector} using <em>Datagram TLS</em> (DTLS) as specified in
 * <a href="http://tools.ietf.org/html/rfc6347">RFC 6347</a> for securing data
 * exchanged between networked clients and a server application.
 */
public class DTLSConnector implements Connector {

	/**
	 * The {@code EndpointContext} key used to store the host name indicated by a
	 * client in an SNI hello extension.
	 */
	public static final String KEY_TLS_SERVER_HOST_NAME = "TLS_SERVER_HOST_NAME";

	public static final int MAX_MTU = 65535;
	/**
	 * MTU values according 
	 * <a href="https://en.wikipedia.org/wiki/Maximum_transmission_unit">MTU - Wikipedia</a>.
	 */
	public static final int DEFAULT_IPV6_MTU = 1280;
	public static final int DEFAULT_IPV4_MTU = 576;

	private static final Logger LOGGER = LoggerFactory.getLogger(DTLSConnector.class.getCanonicalName());
	private static final int MAX_PLAINTEXT_FRAGMENT_LENGTH = 16384; // max. DTLSPlaintext.length (2^14 bytes)
	private static final int MAX_CIPHERTEXT_EXPANSION =
			CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256.getMaxCiphertextExpansion(); // CBC cipher has largest expansion
	private static final int MAX_DATAGRAM_BUFFER_SIZE = MAX_PLAINTEXT_FRAGMENT_LENGTH
			+ 12 // DTLS message headers
			+ 13 // DTLS record headers
			+ MAX_CIPHERTEXT_EXPANSION;

	/** all the configuration options for the DTLS connector */ 
	private final DtlsConnectorConfig config;

	private final LeastRecentlyUsedCache<InetSocketAddress, SerialExecutor> connectionExecutors;
	private final ResumptionSupportingConnectionStore connectionStore;

	/**
	 * (Down-)counter for pending outbound messages. Initialized with
	 * {@link DtlsConnectorConfig#getOutboundMessageBufferSize()}.
	 */
	private final AtomicInteger pendingOutboundMessagesCountdown = new AtomicInteger();

	private final List<Thread> receiverThreads = new LinkedList<Thread>();
	
	private InetSocketAddress lastBindAddress;
	private int maximumTransmissionUnit = DEFAULT_IPV4_MTU;
	private int inboundDatagramBufferSize = MAX_DATAGRAM_BUFFER_SIZE;

	private CookieGenerator cookieGenerator = new CookieGenerator();
	private Object alertHandlerLock= new Object();

	private volatile DatagramSocket socket;

	/** The timer daemon to schedule retransmissions. */
	private ScheduledExecutorService timer;

	/** Indicates whether the connector has started and not stopped yet */
	private AtomicBoolean running = new AtomicBoolean(false);

	/**
	 * Endpoint context matcher for outgoing messages.
	 * 
	 * @see #setEndpointContextMatcher(EndpointContextMatcher)
	 * @see #getEndpointContextMatcher()
	 * @see #sendMessage(RawData)
	 * @see #sendMessage(RawData, DTLSSession)
	 */
	private EndpointContextMatcher endpointContextMatcher;

	private RawDataChannel messageHandler;
	private AlertHandler alertHandler;
	private SessionListener sessionListener;
	private ExecutorService executorService;
	private boolean hasInternalExecutor;

	/**
	 * Creates a DTLS connector from a given configuration object
	 * using the standard in-memory <code>ConnectionStore</code>. 
	 * 
	 * @param configuration the configuration options
	 * @throws NullPointerException if the configuration is <code>null</code>
	 */
	public DTLSConnector(DtlsConnectorConfig configuration) {
		this(configuration, (SessionCache) null);
	}

	/**
	 * Creates a DTLS connector for a given set of configuration options.
	 * 
	 * @param configuration The configuration options.
	 * @param sessionCache An (optional) cache for <code>DTLSSession</code> objects that can be used for
	 *       persisting and/or sharing of session state among multiple instances of <code>DTLSConnector</code>.
	 *       Whenever a handshake with a client is finished the negotiated session is put to this cache.
	 *       Similarly, whenever a client wants to perform an abbreviated handshake based on an existing session
	 *       the connection store will try to retrieve the session from this cache if it is
	 *       not available from the connection store's in-memory (first-level) cache.
	 * @throws NullPointerException if the configuration is <code>null</code>.
	 */
	public DTLSConnector(final DtlsConnectorConfig configuration, final SessionCache sessionCache) {
		this(configuration,
				new InMemoryConnectionStore(
						configuration.getMaxConnections(),
						configuration.getStaleConnectionThreshold(),
						sessionCache));
	}

	/**
	 * Creates a DTLS connector for a given set of configuration options.
	 * 
	 * @param configuration The configuration options.
	 * @param connectionStore The registry to use for managing connections to peers.
	 * @throws NullPointerException if any of the parameters is <code>null</code>.
	 */
	protected DTLSConnector(final DtlsConnectorConfig configuration, final ResumptionSupportingConnectionStore connectionStore) {
		if (configuration == null) {
			throw new NullPointerException("Configuration must not be null");
		} else if (connectionStore == null) {
			throw new NullPointerException("Connection store must not be null");
		} else {
			this.config = configuration;
			this.pendingOutboundMessagesCountdown.set(config.getOutboundMessageBufferSize());
			this.connectionStore = connectionStore;
			this.sessionListener = new SessionAdapter() {

				@Override
				public void sessionEstablished(Handshaker handshaker, DTLSSession establishedSession)
						throws HandshakeException {
					DTLSConnector.this.sessionEstablished(handshaker, establishedSession);
				}
			};
			int maxConnections = configuration.getMaxConnections();
			// create cache slightly larger than max connections for new CLIENT_HELLOs
			this.connectionExecutors = new LeastRecentlyUsedCache<>(maxConnections + (maxConnections / 16), 20);
		}
	}

	private final void sessionEstablished(Handshaker handshaker, final DTLSSession establishedSession)
			throws HandshakeException {
		Connection connection = connectionStore.get(handshaker.getPeerAddress());
		connectionStore.putEstablishedSession(establishedSession, connection);
		List<Object> list = handshaker.takeDeferredApplicationData();
		if (!list.isEmpty()) {
			final SerialExecutor serialExecutor = getSerialExecutor(handshaker.getPeerAddress());
			if (serialExecutor != null) {
				LOGGER.debug("Session with [{}] established, now process deferred {} messages",
						establishedSession.getPeer(), list.size());
				for (Object message : list) {
					if (message instanceof RawData) {
						final RawData rawData = (RawData) message;
						serialExecutor.execute(new Runnable() {

							@Override
							public void run() {
								sendMessage(rawData, establishedSession);
							}
						});
					} else if (message instanceof Record) {
						final Record record = (Record) message;
						serialExecutor.execute(new Runnable() {

							@Override
							public void run() {
								processApplicationDataRecord(record);
							}
						});
					}
				}
			}
		}
	}

	/**
	 * Called after initialization of new create handshaker.
	 * 
	 * Intended to be used for subclass specific handshaker initialization.
	 * 
	 * @param handshaker new create handshaker
	 */
	protected void onInitializeHandshaker(final Handshaker handshaker) {
	}

	/**
	 * Initialize new create handshaker.
	 * 
	 * Add {@link #sessionListener}.
	 * 
	 * @param handshaker new create handshaker
	 */
	private final void initializeHandshaker(final Handshaker handshaker) {
		if (sessionListener != null) {
			handshaker.addSessionListener(sessionListener);
		}
		onInitializeHandshaker(handshaker);
	}

	/**
	 * Sets the executor to be used for processing records.
	 * <p>
	 * If this property is not set before invoking the {@linkplain #start()
	 * start method}, a new {@link ExecutorService} is created with a thread
	 * pool of {@linkplain #DEFAULT_EXECUTOR_THREAD_POOL_SIZE default size}.
	 * 
	 * This helps with performing multiple handshakes in parallel, in particular if the key exchange
	 * requires a look up of identities, e.g. in a database or using a web service.
	 * <p>
	 * If this method is used to set an executor, the executor will <em>not</em> be shut down
	 * by the {@linkplain #stop() stop method}.
	 * 
	 * @param executor The executor.
	 * @throws IllegalStateException if a new executor is set and this connector is already running.
	 */
	public final synchronized void setExecutor(ExecutorService executor) {
		if (this.executorService != executor) {
			if (running.get()) {
				throw new IllegalStateException("cannot set new executor while connector is running");
			} else {
				this.executorService = executor;
			}
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

	/**
	 * {@inheritDoc}
	 */
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

	private synchronized Executor getExecutorService() {
		return executorService;
	}

	private void start(final InetSocketAddress bindAddress) throws IOException {

		if (running.get()) {
			return;
		}

		pendingOutboundMessagesCountdown.set(config.getOutboundMessageBufferSize());

		if (executorService instanceof ScheduledExecutorService) {
			timer = (ScheduledExecutorService) executorService;
		} else {
			timer = ExecutorsUtil.newSingleThreadScheduledExecutor(
					new DaemonThreadFactory("DTLS-Retransmit-Task-", NamedThreadFactory.SCANDIUM_THREAD_GROUP)); //$NON-NLS-1$
		}

		if (executorService == null) {
			int threadCount = config.getConnectionThreadCount();
			if (threadCount > 1) {
				executorService = ExecutorsUtil.newFixedThreadPool(threadCount - 1,
						new DaemonThreadFactory("DTLS-Connection-Handler-", NamedThreadFactory.SCANDIUM_THREAD_GROUP)); //$NON-NLS-1$
			} else {
				executorService = timer;
			}
			this.hasInternalExecutor = true;
		}
		socket = new DatagramSocket(null);
		if (bindAddress.getPort() != 0 && config.isAddressReuseEnabled()) {
			// make it easier to stop/start a server consecutively without delays
			LOGGER.info("Enable address reuse for socket!");
			socket.setReuseAddress(true);
			if (!socket.getReuseAddress()) {
				LOGGER.warn("Enable address reuse for socket failed!");
			}
		}

		socket.bind(bindAddress);
		if (lastBindAddress != null && (!socket.getLocalAddress().equals(lastBindAddress.getAddress()) || socket.getLocalPort() != lastBindAddress.getPort())){
			if (connectionStore instanceof ResumptionSupportingConnectionStore) {
				((ResumptionSupportingConnectionStore) connectionStore).markAllAsResumptionRequired();
			} else {
				connectionStore.clear();
			}
		}
		if (config.getMaxTransmissionUnit() == null) {
			InetAddress localInterfaceAddress = bindAddress.getAddress();
			if (localInterfaceAddress.isAnyLocalAddress()) {
				int mtu = MAX_MTU;
				Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
				while (interfaces.hasMoreElements()) {
					NetworkInterface iface = interfaces.nextElement();
					int ifaceMtu = iface.getMTU();
					if (ifaceMtu > 0 && ifaceMtu < mtu) {
						mtu = ifaceMtu;
					}
				}
				LOGGER.info("multiple network interfaces, using smallest MTU [{}]", mtu);
				this.maximumTransmissionUnit = mtu;
			} else {
				NetworkInterface ni = NetworkInterface.getByInetAddress(localInterfaceAddress);
				if (ni != null && ni.getMTU() > 0) {
					this.maximumTransmissionUnit = ni.getMTU();
				} else if (localInterfaceAddress instanceof Inet4Address) {
					LOGGER.info("Cannot determine MTU of network interface, using minimum MTU [{}] of IPv4 instead", DEFAULT_IPV4_MTU);
					this.maximumTransmissionUnit = DEFAULT_IPV4_MTU;
				} else {
					LOGGER.info("Cannot determine MTU of network interface, using minimum MTU [{}] of IPv6 instead", DEFAULT_IPV6_MTU);
					this.maximumTransmissionUnit = DEFAULT_IPV6_MTU;
				}
			}
		}
		else {
			this.maximumTransmissionUnit = config.getMaxTransmissionUnit();
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
		running.set(true);

		int receiverThreadCount = config.getReceiverThreadCount();
		for (int i = 0; i < receiverThreadCount; i++) {
			Worker receiver = new Worker("DTLS-Receiver-" + i + "-" + lastBindAddress) {

				private final byte[] receiverBuffer = new byte[inboundDatagramBufferSize];
				private final DatagramPacket packet = new DatagramPacket(receiverBuffer, inboundDatagramBufferSize);

				@Override
				public void doWork() throws Exception {
					packet.setData(receiverBuffer);
					receiveNextDatagramFromNetwork(packet);
				}
			};
			receiver.setDaemon(true);
			receiver.start();
			receiverThreads.add(receiver);
		}

		LOGGER.info(
				"DTLS connector listening on [{}] with MTU [{}] using (inbound) datagram buffer size [{} bytes]",
				lastBindAddress, maximumTransmissionUnit, inboundDatagramBufferSize);
	}

	/**
	 * Force connector to an abbreviated handshake. See <a href="https://tools.ietf.org/html/rfc5246#section-7.3">RFC 5246</a>.
	 * 
	 * The abbreviated handshake will be done next time data will be sent with {@link #send(RawData)}.
	 * @param peer the peer for which we will force to do an abbreviated handshake
	 */
	public final synchronized void forceResumeSessionFor(InetSocketAddress peer) {
		Connection peerConnection = connectionStore.get(peer);
		if (peerConnection != null && peerConnection.getEstablishedSession() != null)
			peerConnection.setResumptionRequired(true);
	}

	/**
	 * Marks all established sessions currently maintained by this connector to be resumed by means
	 * of an <a href="https://tools.ietf.org/html/rfc5246#section-7.3">abbreviated handshake</a> the
	 * next time a message is being sent to the corresponding peer using {@link #send(RawData)}.
	 * <p>
	 * This method's execution time is proportional to the number of connections this connector maintains.
	 */
	public final synchronized void forceResumeAllSessions() {
		connectionStore.markAllAsResumptionRequired();
	}

	/**
	 * Clears all connection state this connector maintains for peers.
	 * <p>
	 * After invoking this method a new connection needs to be established with a peer using a 
	 * full handshake in order to exchange messages with it again.
	 */
	public final synchronized void clearConnectionState() {
		connectionStore.clear();
	}

	private final synchronized DatagramSocket getSocket() {
		return socket;
	}

	@Override
	public final void stop() {
		ExecutorService shutdownTimer = null;
		ExecutorService shutdown = null;
		List<Runnable> pending = new ArrayList<>();
		synchronized (this) {
			if (running.compareAndSet(true, false)) {
				LOGGER.info("Stopping DTLS connector on [{}]", lastBindAddress);
				for (Thread t : receiverThreads) {
					t.interrupt();
				}
				receiverThreads.clear();
				if (socket != null) {
					socket.close();
					socket = null;
				}
				maximumTransmissionUnit = 0;
				synchronized (connectionExecutors) {
					for (SerialExecutor executors : connectionExecutors.values()) {
						executors.shutdownNow(pending);
					}
					connectionExecutors.clear();
				}
				if (hasInternalExecutor) {
					if (executorService != timer) {
						pending.addAll(timer.shutdownNow());
						shutdownTimer = timer;
						timer = null;
					}
					pending.addAll(executorService.shutdownNow());
					shutdown = executorService;
					executorService = null;
					hasInternalExecutor = false;
				}
			}
		}
		if (shutdownTimer != null) {
			try {
				if (!shutdownTimer.awaitTermination(500, TimeUnit.MILLISECONDS)) {
					LOGGER.warn("Shutdown DTLS connector on [{}] timer not terminated in time!", lastBindAddress);
				}
			} catch (InterruptedException e) {
			}
		}
		if (shutdown != null) {
			try {
				if (!shutdown.awaitTermination(500, TimeUnit.MILLISECONDS)) {
					LOGGER.warn("Shutdown DTLS connector on [{}] executor not terminated in time!", lastBindAddress);
				}
			} catch (InterruptedException e) {
			}
		}
		for (Runnable job : pending) {
			job.run();
		}
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

	/**
	 * Get serial executor for peer.
	 * 
	 * Use the {@link #connectionExecutors} cache to ensure, that the same
	 * serial executor is used for all message to and from the same peer. If the
	 * connector is stopped, new returned serial executor are not added to the
	 * cache.
	 * 
	 * @param peerAddress socket address of peer
	 * @return serial executor. If the connector is already stopped, then the
	 *         returned executor will be shutdown and throws a
	 *         {@link RejectedExecutionException} on executing a job.
	 *         {@code null}, if {@link #connectionExecutors} is exhausted.
	 */
	private final SerialExecutor getSerialExecutor(InetSocketAddress peerAddress) {
		Executor executor = getExecutorService();
		synchronized (connectionExecutors) {
			SerialExecutor serialExecutor = connectionExecutors.get(peerAddress);
			if (serialExecutor == null) {
				serialExecutor = new SerialExecutor(executor);
				if (running.get()) {
					// only store serial executor, when connector is running.
					if (!connectionExecutors.put(peerAddress, serialExecutor)) {
						serialExecutor = null;
					}
				}
			}
			return serialExecutor;
		}
	}

	private void receiveNextDatagramFromNetwork(DatagramPacket packet) throws IOException {

		DatagramSocket currentSocket = getSocket();
		if (currentSocket == null) {
			// very unlikely race condition.
			return;
		}

		currentSocket.receive(packet);

		if (packet.getLength() == 0) {
			// nothing to do
			return;
		}
		InetSocketAddress peerAddress = new InetSocketAddress(packet.getAddress(), packet.getPort());

		byte[] data = Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getLength());
		List<Record> records = Record.fromByteArray(data, peerAddress);
		LOGGER.debug("Received {} DTLS records using a {} byte datagram buffer",
				records.size(), inboundDatagramBufferSize);

		if (!running.get()) {
			LOGGER.debug("Execution shutdown while processing incoming records from peer: {}", peerAddress);
			return;
		}

		SerialExecutor serialExecutor = getSerialExecutor(peerAddress);
		if (serialExecutor == null) {
			LOGGER.debug("Execution cache is full while processing incoming records from peer: {}", peerAddress);
			return;
		}

		for (final Record record : records) {
			try {

				switch (record.getType()) {
				case HANDSHAKE:
				case APPLICATION_DATA:
				case ALERT:
				case CHANGE_CIPHER_SPEC:

					serialExecutor.execute(new Runnable() {

						@Override
						public void run() {
							if (running.get()) {
								processRecord(record);
							}
						}
					});
					break;
				default:
					LOGGER.debug(
						"Discarding unsupported record [type: {}, peer: {}]",
						record.getType(), record.getPeerAddress());
				}
			} catch (RejectedExecutionException e) {
				// dont't terminate connection on shutdown!
				LOGGER.debug("Execution rejected while processing record [type: {}, peer: {}]",
						record.getType(), peerAddress, e);
				break;
			} catch (RuntimeException e) {
				LOGGER.info("Unexpected error occurred while processing record [type: {}, peer: {}]",
						record.getType(), peerAddress, e);
				terminateConnection(peerAddress, e, AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR);
				break;
			}
		}
	}

	private void processRecord(Record record) {

		try {
			LOGGER.trace("Received DTLS record of type [{}], length: {}, [epoche:{},reqn:{}]", record.getType(),
					record.getLength(), record.getEpoch(), record.getSequenceNumber());

			switch (record.getType()) {
			case APPLICATION_DATA:
				processApplicationDataRecord(record);
				break;
			case ALERT:
				processAlertRecord(record);
				break;
			case CHANGE_CIPHER_SPEC:
				processChangeCipherSpecRecord(record);
				break;
			case HANDSHAKE:
				processHandshakeRecord(record);
				break;
			default:
				LOGGER.debug(
					"Discarding record of unsupported type [{}] from peer [{}]",
					record.getType(), record.getPeerAddress());
			}
		} catch (RuntimeException e) {
			LOGGER.info("Unexpected error occurred while processing record from peer [{}]",
					record.getPeerAddress(), e);
			terminateConnection(record.getPeerAddress(), e, AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR);
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
	 * @param cause the exception that is the cause for terminating the handshake
	 * @param description the reason to indicate in the message sent to the peer before terminating the handshake
	 */
	private void terminateOngoingHandshake(final InetSocketAddress peerAddress, final Throwable cause, final AlertDescription description) {

		Connection connection = connectionStore.get(peerAddress);
		if (connection != null && connection.hasOngoingHandshake()) {
			if (LOGGER.isTraceEnabled()) {
				LOGGER.trace("Aborting handshake with peer [{}]:", peerAddress, cause);
			} else if (LOGGER.isInfoEnabled()) {
				LOGGER.info("Aborting handshake with peer [{}]: {}",
					peerAddress, cause.getMessage());
			}
			Handshaker handshaker = connection.getOngoingHandshake();
			DTLSSession session = handshaker.getSession();
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, description, peerAddress);
			if (!connection.hasEstablishedSession()) {
				terminateConnection(connection, alert, session);
			} else {
				// keep established session intact and only terminate ongoing handshake
				send(alert, session);
			}
			handshaker.handshakeFailed(cause);
		}
	}

	private void terminateConnection(Connection connection) {
		if (connection != null) {
			connection.cancelPendingFlight();
			// clear session & (pending) handshaker
			connectionStore.remove(connection);
		}
	}

	private void terminateConnection(InetSocketAddress peerAddress, Throwable cause, AlertLevel level, AlertDescription description) {
		Connection connection = connectionStore.get(peerAddress);
		if (connection != null) {
			if (connection.hasEstablishedSession()) {
				terminateConnection(
						connection,
						new AlertMessage(level, description, peerAddress),
						connection.getEstablishedSession());
			} else if (connection.hasOngoingHandshake()) {
				terminateConnection(
						connection,
						new AlertMessage(level, description, peerAddress),
						connection.getOngoingHandshake().getSession());
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
			LOGGER.debug("Terminating connection with peer [{}]", connection.getPeerAddress());
		} else {
			LOGGER.debug("Terminating connection with peer [{}], reason [{}]", connection.getPeerAddress(),
					alert.getDescription());
			send(alert, session);
		}
		// clear session & (pending) handshaker
		connectionStore.remove(connection);
	}

	private void processApplicationDataRecord(final Record record) {
		final DTLSSession session;
		final Connection connection = connectionStore.get(record.getPeerAddress());
		if (connection != null && (session = connection.getEstablishedSession()) != null) {
			RawData receivedApplicationMessage = null;
			Handshaker ongoingHandshake = connection.getOngoingHandshake();
			synchronized (session) {
				// The DTLS 1.2 spec (section 4.1.2.6) advises to do replay detection
				// before MAC validation based on the record's sequence numbers
				// see http://tools.ietf.org/html/rfc6347#section-4.1.2.6
				if (session.isRecordProcessable(record.getEpoch(), record.getSequenceNumber())) {
					try {
						// APPLICATION_DATA can only be processed within the context of
						// an established, i.e. fully negotiated, session
						record.setSession(session);
						ApplicationMessage message = (ApplicationMessage) record.getFragment();
						session.markRecordAsRead(record.getEpoch(), record.getSequenceNumber());
						// create application message.
						receivedApplicationMessage = RawData.inbound(message.getData(), session.getConnectionReadContext(), false);
					} catch (HandshakeException | GeneralSecurityException e) {
						// this means that we could not parse or decrypt the message
						discardRecord(record, e);
					}
				} else {
					LOGGER.debug("Discarding duplicate APPLICATION_DATA record received from peer [{}]",
							record.getPeerAddress());
				}
			}
			if (receivedApplicationMessage != null) {
				if (ongoingHandshake != null) {
					// the fragment could be de-crypted
					// thus, the handshake seems to have been completed successfully
					ongoingHandshake.handshakeCompleted();
				} else {
					connection.refreshAutoResumptionTime();
				}
				connectionStore.update(connection);

				final RawDataChannel channel = messageHandler;
				// finally, forward de-crypted message to application layer
				// outside the synchronized block
				if (channel != null) {
					channel.receiveData(receivedApplicationMessage);
				}
			}
		} else {
			Handshaker ongoingHandshake = connection.getOngoingHandshake();
			if (ongoingHandshake != null && ongoingHandshake.isChangeCipherSpecMessageExpected()) {
				ongoingHandshake.addApplicationDataForDeferredProcessing(record);
			} else {
				LOGGER.debug("Discarding APPLICATION_DATA record received from peer [{}] without an active session",
						record.getPeerAddress());
			}
		}
	}

	/**
	 * Processes an <em>ALERT</em> message received from the peer.
	 * <p>
	 * Terminates the connection with the peer if either
	 * <ul>
	 * <li>the ALERT's level is FATAL or</li>
	 * <li>the ALERT is a <em>closure alert</em></li>
	 * </ul>
	 * 
	 * Also notifies a registered {@link #alertHandler} about the alert message.
	 * </p>
	 * @param record the record containing the ALERT message
	 * @see ErrorHandler
	 * @see #terminateConnection(Connection, AlertMessage, DTLSSession)
	 */
	private void processAlertRecord(Record record) {

		Connection connection = connectionStore.get(record.getPeerAddress());
		if (connection == null) {
			LOGGER.debug("Discarding ALERT record from [{}] received without existing connection", record.getPeerAddress());
		} else {
			processAlertRecord(record, connection);
		}
	}

	private void processAlertRecord(final Record record, final Connection connection) {

		if (connection.hasEstablishedSession() && connection.getEstablishedSession().getReadEpoch() == record.getEpoch()) {
				processAlertRecord(record, connection, connection.getEstablishedSession());
		} else if (connection.hasOngoingHandshake() && connection.getOngoingHandshake().getSession().getReadEpoch() == record.getEpoch()) {
				processAlertRecord(record, connection, connection.getOngoingHandshake().getSession());
		} else {
			LOGGER.debug(
				"Epoch of ALERT record [epoch={}] from [{}] does not match expected epoch(s), discarding ...",
				new Object[]{record.getEpoch(), record.getPeerAddress()});
		}
	}

	private void processAlertRecord(final Record record, final Connection connection, final DTLSSession session) {
		record.setSession(session);
		try {
			AlertMessage alert = (AlertMessage) record.getFragment();
			Handshaker handshaker = connection.getOngoingHandshake();
			HandshakeException error = null;
			LOGGER.trace("Processing {} ALERT from [{}]: {}",
					new Object[]{alert.getLevel(), alert.getPeer(), alert.getDescription()});
			if (AlertDescription.CLOSE_NOTIFY.equals(alert.getDescription())) {
				// according to section 7.2.1 of the TLS 1.2 spec
				// (http://tools.ietf.org/html/rfc5246#section-7.2.1)
				// we need to respond with a CLOSE_NOTIFY alert and
				// then close and remove the connection immediately
				error = new HandshakeException("Received 'close notify'", alert);
				terminateConnection(
						connection,
						new AlertMessage(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY, alert.getPeer()),
						session);
			} else if (AlertLevel.FATAL.equals(alert.getLevel())) {
				// according to section 7.2 of the TLS 1.2 spec
				// (http://tools.ietf.org/html/rfc5246#section-7.2)
				// the connection needs to be terminated immediately
				error = new HandshakeException("Received 'fatal alert'", alert);
				terminateConnection(connection);
			} else {
				// non-fatal alerts do not require any special handling
			}

			synchronized (alertHandlerLock) {
				if (alertHandler != null) {
					alertHandler.onAlert(alert.getPeer(), alert);
				}
			}
			if (null != error && null != handshaker) {
				handshaker.handshakeFailed(error);
			}
		} catch (HandshakeException | GeneralSecurityException e) {
			discardRecord(record, e);
		}
	}

	private void processChangeCipherSpecRecord(Record record) {
		Connection connection = connectionStore.get(record.getPeerAddress());
		if (connection != null && connection.hasOngoingHandshake()) {
			// processing a CCS message does not result in any additional flight to be sent
			try {
				connection.getOngoingHandshake().processMessage(record);
			} catch (HandshakeException e) {
				handleExceptionDuringHandshake(e, e.getAlert().getLevel(), e.getAlert().getDescription(), record);
			}
		} else {
			// change cipher spec can only be processed within the
			// context of an existing handshake -> ignore record
			LOGGER.debug("Received CHANGE_CIPHER_SPEC record from peer [{}] with no handshake going on", record.getPeerAddress());
		}
	}

	private void processHandshakeRecord(final Record record) {

		LOGGER.debug("Received {} record from peer [{}]",
				record.getType(), record.getPeerAddress());
		final Connection con = connectionStore.get(record.getPeerAddress());
		try {
			if (con == null) {
				processHandshakeRecordWithoutConnection(record);
			} else {
				processHandshakeRecordWithConnection(record, con);
			}
		} catch (HandshakeException e) {
			handleExceptionDuringHandshake(e, e.getAlert().getLevel(), e.getAlert().getDescription(), record);
		}
	}

	/**
	 * 
	 * @param record
	 * @throws HandshakeException if the handshake record cannot be parsed or processed successfully
	 */
	private void processHandshakeRecordWithoutConnection(final Record record) throws HandshakeException {
		if (record.getEpoch() > 0) {
			LOGGER.debug(
				"Discarding unexpected handshake message [epoch={}] received from peer [{}] without existing connection",
				record.getEpoch(), record.getPeerAddress());
		} else {
			try {
				// in epoch 0 no crypto params have been established yet, thus we can simply call getFragment()
				HandshakeMessage handshakeMessage = (HandshakeMessage) record.getFragment();
				// if we do not have a connection yet we ignore everything but a CLIENT_HELLO
				if (HandshakeType.CLIENT_HELLO.equals(handshakeMessage.getMessageType())) {
					processClientHello((ClientHello) handshakeMessage, record);
				} else {
					LOGGER.debug(
							"Discarding unexpected {} message from peer [{}]",
							handshakeMessage.getMessageType(), handshakeMessage.getPeer());
				}
			} catch (GeneralSecurityException e) {
				discardRecord(record, e);
			}
		}
	}

	/**
	 * 
	 * @param record
	 * @param connection
	 * @throws HandshakeException if the handshake message cannot be processed
	 */
	private void processHandshakeRecordWithConnection(final Record record, final Connection connection) throws HandshakeException {
		if (connection.hasOngoingHandshake()) {
			DTLSSession handshakeSession = connection.getOngoingHandshake().getSession();
			if (handshakeSession.getReadEpoch() == record.getEpoch()) {
				// evaluate message in context of ongoing handshake
				record.setSession(handshakeSession);
			} else if (!record.isNewClientHello()) {
				// epoch is not the same as the current session so we
				// can not decrypt the message now. Let handshaker handle it
				// (it can queue it to deal with it later)
				connection.getOngoingHandshake().processMessage(record);
				return;
			}
		} else if (connection.hasEstablishedSession() && connection.getEstablishedSession().getReadEpoch() == record.getEpoch()) {
			// client wants to re-negotiate established connection's crypto params
			// evaluate message in context of established session
			record.setSession(connection.getEstablishedSession());
		} else if (record.isNewClientHello()) {
			// client has lost track of existing connection and wants to negotiate a new connection
			// in epoch 0 no crypto params have been established yet, thus we do not need to set a session
		} else {
			LOGGER.debug(
				"Discarding HANDSHAKE message [epoch={}] from peer [{}] which does not match expected epoch(s)",
				new Object[]{record.getEpoch(), record.getPeerAddress()});
			return;
		}

		try {
			HandshakeMessage handshakeMessage = (HandshakeMessage) record.getFragment();
			processDecryptedHandshakeMessage(handshakeMessage, record, connection);
		} catch (GeneralSecurityException e) {
			discardRecord(record, e);
		}
	}

	private void processDecryptedHandshakeMessage(final HandshakeMessage handshakeMessage, final Record record,
			final Connection connection) throws HandshakeException {
		switch (handshakeMessage.getMessageType()) {
		case CLIENT_HELLO:
			processClientHello((ClientHello) handshakeMessage, record, connection);
			break;
		case HELLO_REQUEST:
			processHelloRequest((HelloRequest) handshakeMessage, connection);
			break;
		default:
			processOngoingHandshakeMessage(handshakeMessage, record, connection);
		}
	}

	/**
	 * 
	 * @param message
	 * @param record
	 * @param connection
	 * @throws HandshakeException if the handshake message cannot be processed
	 */
	private static void processOngoingHandshakeMessage(final HandshakeMessage message, final Record record, final Connection connection) throws HandshakeException {
		if (connection.hasOngoingHandshake()) {
			connection.getOngoingHandshake().processMessage(record);
		} else {
			LOGGER.debug(
				"Discarding {} message received from peer [{}] with no handshake going on",
				new Object[]{message.getMessageType(), message.getPeer()});
		}
	}

	/**
	 * 
	 * @param helloRequest
	 * @param connection
	 * @throws HandshakeException if the message to initiate the handshake with
	 *             the peer cannot be created
	 */
	private void processHelloRequest(final HelloRequest helloRequest, final Connection connection)
			throws HandshakeException {
		if (connection.hasOngoingHandshake()) {
			// TLS 1.2, Section 7.4 advises to ignore HELLO_REQUEST messages
			// arriving while in an ongoing handshake
			// (http://tools.ietf.org/html/rfc5246#section-7.4)
			LOGGER.debug("Ignoring {} received from [{}] while already in an ongoing handshake with peer",
					helloRequest.getMessageType(), helloRequest.getPeer());
		} else {
			// We do not support re-negotiation as recommended in :
			// https://tools.ietf.org/html/rfc7925#section-17
			DTLSSession session = connection.getEstablishedSession();
			send(new AlertMessage(AlertLevel.WARNING, AlertDescription.NO_RENEGOTIATION, helloRequest.getPeer()),
					session);
		}
	}

	/**
	 * 
	 * @param clientHello
	 * @param record
	 * @throws HandshakeException if the parameters provided in the client hello message cannot be used
	 *               to start a new handshake or resume an existing session
	 */
	private void processClientHello(final ClientHello clientHello, final Record record) throws HandshakeException {
		if (LOGGER.isDebugEnabled()) {
			StringBuilder msg = new StringBuilder("Processing CLIENT_HELLO from peer [").append(record.getPeerAddress()).append("]");
			if (LOGGER.isTraceEnabled()) {
				msg.append(":").append(StringUtil.lineSeparator()).append(record);
			}
			LOGGER.debug(msg.toString());
		}

		// before starting a new handshake or resuming an established session we need to make sure that the
		// peer is in possession of the IP address indicated in the client hello message
		if (isClientInControlOfSourceIpAddress(clientHello, record, null)) {
			if (clientHello.hasSessionId()) {
				// client wants to resume a cached session
				resumeExistingSession(clientHello, record, null);
			} else {
				// At this point the client has demonstrated reachability by completing a cookie exchange
				// so we start a new handshake (see section 4.2.8 of RFC 6347 (DTLS 1.2))
				startNewHandshake(clientHello, record);
			}
		}
	}

	/**
	 * 
	 * @param clientHello
	 * @param record
	 * @param connection
	 * @throws HandshakeException if the parameters provided in the client hello message cannot be used
	 *               to start a new handshake or resume an existing session
	 */
	private void processClientHello(final ClientHello clientHello, final Record record, final Connection connection) throws HandshakeException {
		if (LOGGER.isDebugEnabled()) {
			StringBuilder msg = new StringBuilder("Processing CLIENT_HELLO from peer [").append(record.getPeerAddress()).append("]");
			if (LOGGER.isTraceEnabled()) {
				msg.append(":").append(StringUtil.lineSeparator()).append(record);
			}
			LOGGER.debug(msg.toString());
		}

		// We do not support re-negotiation as recommended in :
		// https://tools.ietf.org/html/rfc7925#section-17
		if (record.getEpoch() > 0) {
			DTLSSession session = connection.getEstablishedSession();
			send(new AlertMessage(AlertLevel.WARNING, AlertDescription.NO_RENEGOTIATION, clientHello.getPeer()),
					session);
			return;
		}

		// before starting a new handshake or resuming an established session we need to make sure that the
		// peer is in possession of the IP address indicated in the client hello message
		if (isClientInControlOfSourceIpAddress(clientHello, record, connection)) {
			if (isHandshakeAlreadyStartedForMessage(clientHello, connection)) {
				// client has sent this message before (maybe our response flight has been lost)
				// but we do not want to start over again, so let the existing handshaker handle
				// the duplicate
				processOngoingHandshakeMessage(clientHello, record, connection);
			} else if (clientHello.hasSessionId()) {
				// client wants to resume a cached session
				resumeExistingSession(clientHello, record, connection);
			} else {
				// At this point the client has demonstrated reachability by completing a cookie exchange
				// so we terminate the previous connection and start a new handshake
				// (see section 4.2.8 of RFC 6347 (DTLS 1.2))
				terminateConnection(connection);
				startNewHandshake(clientHello, record);
			}
		}
	}

	private static boolean isHandshakeAlreadyStartedForMessage(final ClientHello clientHello, final Connection connection) {
		return connection != null && connection.hasOngoingHandshake() && 
			connection.getOngoingHandshake().hasBeenStartedByMessage(clientHello);
	}

	/**
	 * Checks whether the peer is able to receive data on the IP address indicated
	 * in its client hello message.
	 * <p>
	 * The check is done by means of comparing the cookie contained in the client hello
	 * message with the cookie computed for the request using the <code>generateCookie</code>
	 * method.
	 * </p>
	 * <p>This method sends a <em>HELLO_VERIFY_REQUEST</em> to the peer if the cookie contained
	 * in <code>clientHello</code> does not match the expected cookie.
	 * </p>
	 * 
	 * @param clientHello the peer's client hello method including the cookie to verify
	 * @param record the
	 * @return <code>true</code> if the client hello message contains a cookie and the cookie
	 *             is identical to the cookie expected from the peer address
	 */
	private boolean isClientInControlOfSourceIpAddress(ClientHello clientHello, Record record, Connection connection) {
		// verify client's ability to respond on given IP address
		// by exchanging a cookie as described in section 4.2.1 of the DTLS 1.2 spec
		// see http://tools.ietf.org/html/rfc6347#section-4.2.1
		try {
			byte[] expectedCookie = null;
			byte[] providedCookie = clientHello.getCookie();
			if (providedCookie != null && providedCookie.length > 0) {
				expectedCookie = cookieGenerator.generateCookie(clientHello);
				// if cookie is present, it must match
				if (Arrays.equals(expectedCookie, providedCookie)) {
					return true;
				}
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("provided cookie must {} match {}. Send verify request to {}",
							StringUtil.byteArray2HexString(providedCookie, StringUtil.NO_SEPARATOR, 6),
							StringUtil.byteArray2HexString(expectedCookie, StringUtil.NO_SEPARATOR, 6),
							record.getPeerAddress());
				}
				// otherwise send verify request
			} else if (!config.isVerifyRequestOnResumptionEnabled()) {
				Connection sessionConnection = connectionStore.find(clientHello.getSessionId());
				if (sessionConnection != null) {
					// found provided session.
					if (record.getPeerAddress().equals(sessionConnection.getPeerAddress())) {
						// same peer wants to resume his session
						return true;
					}
					if (connection == null || !connection.hasEstablishedSession()) {
						// only new connections or connections without
						// established sessions
						return true;
					}
					// for connection with other established session,
					// use the verify request
				}
			}
			if (expectedCookie == null) {
				expectedCookie = cookieGenerator.generateCookie(clientHello);
			}
			// for all cases not detected above, use a verify request.
			sendHelloVerify(clientHello, record, expectedCookie);
			return false;
		} catch (GeneralSecurityException e) {
			throw new DtlsHandshakeException("Cannot compute cookie for peer", AlertDescription.INTERNAL_ERROR,
					AlertLevel.FATAL, clientHello.getPeer(), e);
		}
	}

	/**
	 * 
	 * @param clientHello
	 * @param record
	 * @throws HandshakeException if the parameters provided in the client hello message
	 *           cannot be used to start a handshake with the peer
	 */
	private void startNewHandshake(final ClientHello clientHello, final Record record) throws HandshakeException {
		Connection peerConnection = new Connection(record.getPeerAddress(), config.getAutoResumptionTimeoutMillis());
		if (!connectionStore.put(peerConnection)) {
			terminateOngoingHandshake(record.getPeerAddress(), new IllegalStateException("connection store exhausted!"),
					AlertDescription.INTERNAL_ERROR);
			return;
		}

		// use the record sequence number from CLIENT_HELLO as initial sequence number
		// for records sent to the client (see section 4.2.1 of RFC 6347 (DTLS 1.2))
		DTLSSession newSession = new DTLSSession(record.getPeerAddress(), false, record.getSequenceNumber());
		// initialize handshaker based on CLIENT_HELLO (this accounts
		// for the case that multiple cookie exchanges have taken place)
		Handshaker handshaker = new ServerHandshaker(clientHello.getMessageSeq(), newSession,
				getRecordLayerForPeer(peerConnection), peerConnection.getSessionListener(), config,
				maximumTransmissionUnit);
		initializeHandshaker(handshaker);
		handshaker.processMessage(record);
	}

	/**
	 * 
	 * @param clientHello
	 * @param record
	 * @throws HandshakeException if the session cannot be resumed based on the parameters
	 *             provided in the client hello message
	 */
	private void resumeExistingSession(final ClientHello clientHello, final Record record, final Connection connection) throws HandshakeException {
		LOGGER.debug("Client [{}] wants to resume session with ID [{}]", clientHello.getPeer(),
				clientHello.getSessionId());
		final Connection previousConnection = connectionStore.find(clientHello.getSessionId());
		if (previousConnection != null && previousConnection.isActive()) {

			// session has been found in cache, resume it
			Connection peerConnection = new Connection(record.getPeerAddress(), config.getAutoResumptionTimeoutMillis());
			SessionTicket ticket = null;
			if (previousConnection.hasEstablishedSession()) {
				ticket = previousConnection.getEstablishedSession().getSessionTicket();
			} else if (previousConnection.hasSessionTicket()) {
				ticket = previousConnection.getSessionTicket();
			} else {
				// TODO: fall back to full handshake
			}
			final DTLSSession sessionToResume = new DTLSSession(clientHello.getSessionId(), record.getPeerAddress(),
					ticket, record.getSequenceNumber());

			final Handshaker handshaker = new ResumingServerHandshaker(clientHello.getMessageSeq(), sessionToResume,
					getRecordLayerForPeer(peerConnection), peerConnection.getSessionListener(), config,
					maximumTransmissionUnit);
			initializeHandshaker(handshaker);

			if (previousConnection.hasEstablishedSession()) {
				// client wants to resume a session that has been negotiated by this node
				// make sure that the same client only has a single active connection to this server
				if (!previousConnection.getPeerAddress().equals(peerConnection.getPeerAddress())) {
					// client has a new IP address, terminate previous connection once new session has been established
					handshaker.addSessionListener(new SessionAdapter() {
						@Override
						public void sessionEstablished(final Handshaker currentHandshaker, final DTLSSession establishedSession)
								throws HandshakeException {
							LOGGER.debug(
									"Discarding existing connection to [{}] after successful resumption of session [ID={}] by peer [{}]",
											previousConnection.getPeerAddress(),
											establishedSession.getSessionIdentifier(),
											establishedSession.getPeer());
							previousConnection.cancelPendingFlight();
							connectionStore.remove(previousConnection, false);
						}
					});
				} else {
					// immediately remove previous connection
					previousConnection.cancelPendingFlight();
					connectionStore.remove(previousConnection, false);
				}
			} else {
				// client wants to resume a session that has been established with another node
				// simply start the abbreviated handshake
			}

			if (connection != null) {
				final Handshaker pendingHandshaker = connection.getOngoingHandshake();
				if (pendingHandshaker != null) {
					pendingHandshaker.handshakeFailed(new IOException("ongoing handshake resumed!"));
				}
			}

			// add the new one to the store
			connectionStore.put(peerConnection);

			// process message
			handshaker.processMessage(record);
		} else {
			LOGGER.debug(
					"Client [{}] tries to resume non-existing session [ID={}], performing full handshake instead ...",
					clientHello.getPeer(), clientHello.getSessionId());
			terminateConnection(connectionStore.get(clientHello.getPeer()));
			startNewHandshake(clientHello, record);
		}
	}

	private void sendHelloVerify(ClientHello clientHello, Record record, byte[] expectedCookie) {
		// send CLIENT_HELLO_VERIFY with cookie in order to prevent
		// DOS attack as described in DTLS 1.2 spec
		LOGGER.debug("Verifying client IP address [{}] using HELLO_VERIFY_REQUEST", record.getPeerAddress());
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
		try {
			sendRecord(helloVerify);
		} catch (IOException e) {
			// already logged ...
		}
	}

	void send(AlertMessage alert, DTLSSession session) {
		if (alert == null) {
			throw new IllegalArgumentException("Alert must not be NULL");
		} else if (session == null) {
			throw new IllegalArgumentException("Session must not be NULL");
		} else {
			try {
				sendRecord(new Record(ContentType.ALERT, session.getWriteEpoch(), session.getSequenceNumber(), alert, session));
			} catch (IOException e) {
				// already logged ...
			} catch (GeneralSecurityException e) {
				LOGGER.debug("Cannot create ALERT message for peer [{}]", session.getPeer(), e);
			}
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public final void send(final RawData msg) {
		if (msg == null) {
			throw new NullPointerException("Message must not be null");
		}
		SerialExecutor serialExecutor = null;
		RuntimeException error = null;

		if (!running.get()) {
			error = new IllegalStateException("connector must be started before sending messages is possible");
		} else if (msg.getSize() > MAX_PLAINTEXT_FRAGMENT_LENGTH) {
			error = new IllegalArgumentException(
					"Message data must not exceed " + MAX_PLAINTEXT_FRAGMENT_LENGTH + " bytes");
		} else {
			serialExecutor = getSerialExecutor(msg.getInetSocketAddress());
			if (serialExecutor == null) {
				error = new IllegalStateException("connector's serial-executors-cache is exhausted!");
			}
		}
		if (error != null) {
			msg.onError(error);
			throw error;
		}

		if (pendingOutboundMessagesCountdown.decrementAndGet() >= 0) {
			try {
				serialExecutor.execute(new Runnable() {

					@Override
					public void run() {
						try {
							if (running.get()) {
								sendMessage(msg);
							} else {
								msg.onError(new InterruptedIOException("Connector is not running."));
							}
						} catch (Exception e) {
							if (running.get()) {
								LOGGER.debug("Exception thrown by executor thread [{}]", Thread.currentThread().getName(),
										e);
							}
							msg.onError(e);
						} finally {
							pendingOutboundMessagesCountdown.incrementAndGet();
						}
					}
				});
			} catch (RejectedExecutionException e) {
				LOGGER.debug("Execution rejected while sending application record [peer: {}]",
						msg.getInetSocketAddress(), e);
				msg.onError(new InterruptedIOException("Connector is not running."));
			}
		} else {
			pendingOutboundMessagesCountdown.incrementAndGet();
			LOGGER.warn("Outbound message overflow! Dropping outbound message to peer [{}]",
					msg.getInetSocketAddress());
			msg.onError(new IllegalStateException("Outbound message overflow!"));
		}
	}

	/**
	 * Sends a raw message to a peer.
	 * <p>
	 * This method encrypts and sends the bytes contained in the message using an
	 * already established session with the peer. If no session exists yet, a
	 * new handshake with the peer is initiated and the sending of the message is
	 * deferred to after the handshake has been completed and a session is established.
	 * </p>
	 * 
	 * @param message the data to send to the peer
	 */
	private void sendMessage(final RawData message) throws HandshakeException {

		InetSocketAddress peerAddress = message.getInetSocketAddress();
		LOGGER.debug("Sending application layer message to peer [{}]", peerAddress);
		Connection connection = connectionStore.get(peerAddress);

		// TODO make sure that only ONE handshake is in progress with a peer
		// at all times

		if (connection == null) {
			connection = new Connection(peerAddress, config.getAutoResumptionTimeoutMillis());
			connectionStore.put(connection);
		}

		DTLSSession session = connection.getEstablishedSession();
		SessionTicket ticket = connection.getSessionTicket();
		if (session == null && ticket == null) {
			if (!checkOutboundEndpointContext(message, null)) {
				return;
			}
			message.onConnecting();
			Handshaker handshaker = connection.getOngoingHandshake();
			if (handshaker == null) {
				// no session with peer established yet, create new empty session &
				// start handshake
				handshaker = new ClientHandshaker(
					DTLSSession.newClientSession(peerAddress, message.getEndpointContext().getVirtualHost()),
					getRecordLayerForPeer(connection),
					connection.getSessionListener(),
					config,
					maximumTransmissionUnit);
				initializeHandshaker(handshaker);
				handshaker.startHandshake();
			}
			handshaker.addApplicationDataForDeferredProcessing(message);
		}
		// TODO what if there already is an ongoing handshake with the peer
		else if (connection.isResumptionRequired()) {
			// create the session to resume from the previous one.
			message.onConnecting();
			SessionId sessionId;
			if (ticket == null) {
				ticket = session.getSessionTicket();
				sessionId = session.getSessionIdentifier();
			} else {
				sessionId = connection.getSessionIdentity();
			}
			DTLSSession resumableSession = new DTLSSession(sessionId, peerAddress, ticket, 0);

			// terminate the previous connection and add the new one to the store
			Connection newConnection = new Connection(peerAddress, config.getAutoResumptionTimeoutMillis());
			connection.cancelPendingFlight();
			connectionStore.remove(connection, false);
			connectionStore.put(newConnection);
			Handshaker handshaker = new ResumingClientHandshaker(resumableSession, getRecordLayerForPeer(newConnection),
					newConnection.getSessionListener(), config, maximumTransmissionUnit);
			initializeHandshaker(handshaker);
			Handshaker previous = connection.getOngoingHandshake();
			if (previous != null) {
				handshaker.takeDeferredApplicationData(previous);
			}
			handshaker.addApplicationDataForDeferredProcessing(message);
			handshaker.startHandshake();
		} else {
			// session with peer has already been established, use it to send encrypted message
			sendMessage(message, session);
		}
	}

	private void sendMessage(final RawData message, final DTLSSession session) {
		try {
			final EndpointContext ctx = session.getConnectionWriteContext();
			if (!checkOutboundEndpointContext(message, ctx)) {
				return;
			}
			
			message.onContextEstablished(ctx);
			Record record = new Record(
					ContentType.APPLICATION_DATA,
					session.getWriteEpoch(),
					session.getSequenceNumber(),
					new ApplicationMessage(message.getBytes(), message.getInetSocketAddress()),
					session);
			
			sendRecord(record);
			message.onSent();
			InetSocketAddress peerAddress = message.getInetSocketAddress();
			Connection connection = connectionStore.get(peerAddress);
			if (connection != null) {
				connection.refreshAutoResumptionTime();
			}
		} catch (IOException e) {
			message.onError(e);
		} catch (GeneralSecurityException e) {
			LOGGER.debug("Cannot send APPLICATION record to peer [{}]", message.getInetSocketAddress(), e);
			message.onError(e);
		}
	}

	/**
	 * Check, if the endpoint context match for outgoing messages using
	 * {@link #endpointContextMatcher}.
	 * 
	 * @param message message to be checked
	 * @param connectionContext endpoint context of the connection. May be
	 *            null, if not established.
	 * @return true, if outgoing message matches, false, if not and should NOT
	 *         be send.
	 * @see EndpointContextMatcher#isToBeSent(EndpointContext, EndpointContext)
	 */
	private boolean checkOutboundEndpointContext(final RawData message, final EndpointContext connectionContext) {
		final EndpointContextMatcher endpointMatcher = getEndpointContextMatcher();
		if (null != endpointMatcher && !endpointMatcher.isToBeSent(message.getEndpointContext(), connectionContext)) {
			LOGGER.warn("DTLSConnector ({}) drops {} bytes to {}:{}",
					new Object[] {this, message.getSize(), message.getAddress(),
					message.getPort() });
			message.onError(new EndpointMismatchException());
			return false;
		}
		return true;
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

	private void sendHandshakeFlight(DTLSFlight flight, Connection connection) {
		if (flight != null) {
			if (flight.isRetransmissionNeeded()) {
				connection.setPendingFlight(flight);
				scheduleRetransmission(flight);
			} else {
				connection.cancelPendingFlight();
			}
			try {
				sendFlight(flight);
			} catch (IOException e) {
				LOGGER.warn("Could not send handshake flight", e);
			}
		}
	}

	private void sendFlight(DTLSFlight flight) throws IOException {
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

		for (Record record : flight.getMessages()) {

			byte[] recordBytes = record.toByteArray();
			if (recordBytes.length > maxDatagramSize) {
				LOGGER.info("{} record of {} bytes for peer [{}] exceeds max. datagram size [{}], discarding...",
						record.getType(), recordBytes.length, record.getPeerAddress(), maxDatagramSize);
				// TODO: inform application layer, e.g. using error handler
				continue;
			}
			LOGGER.trace("Sending record of {} bytes to peer [{}]:\n{}", recordBytes.length, flight.getPeerAddress(),
					record);

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

		DatagramPacket datagram = new DatagramPacket(payload, payload.length, flight.getPeerAddress().getAddress(),
				flight.getPeerAddress().getPort());
		datagrams.add(datagram);

		// send it over the UDP socket
		LOGGER.debug("Sending flight of {} message(s) to peer [{}] using {} datagram(s) of max. {} bytes",
				flight.getMessages().size(), flight.getPeerAddress(), datagrams.size(), maxDatagramSize);
		for (DatagramPacket datagramPacket : datagrams) {
			sendNextDatagramOverNetwork(datagramPacket);
		}
	}

	protected void sendRecord(Record record) throws IOException {
		byte[] recordBytes = record.toByteArray();
		DatagramPacket datagram = new DatagramPacket(recordBytes, recordBytes.length, record.getPeerAddress());
		sendNextDatagramOverNetwork(datagram);
	}

	protected void sendNextDatagramOverNetwork(final DatagramPacket datagramPacket) throws IOException {
		DatagramSocket socket = getSocket();
		if (socket != null && !socket.isClosed()) {
			try {
				socket.send(datagramPacket);
			} catch(IOException e) {
				LOGGER.warn("Could not send record", e);
				throw e;
			}
		} else {
			LOGGER.debug("Socket [{}] is closed, discarding packet ...", config.getAddress());
			throw new IOException("Socket closed.");
		}
	}

	private void handleTimeout(DTLSFlight flight, boolean resend) {

		Connection connection = connectionStore.get(flight.getPeerAddress());
		if (null != connection) {
			Handshaker handshaker = connection.getOngoingHandshake();
			if (null != handshaker) {
				Exception cause = null;
				if (resend) {
					// set DTLS retransmission maximum
					final int max = config.getMaxRetransmissions();

					// check if limit of retransmissions reached
					if (flight.getTries() < max) {
						LOGGER.debug("Re-transmitting flight for [{}], [{}] retransmissions left",
								flight.getPeerAddress(), max - flight.getTries() - 1);

						try {
							flight.incrementTries();
							flight.setNewSequenceNumbers();
							sendFlight(flight);

							// schedule next retransmission
							scheduleRetransmission(flight);
							handshaker.handshakeFlightRetransmitted(flight.getFlightNumber());
							return;
						} catch (IOException e) {
							// stop retransmission on IOExceptions
							cause = e;
							LOGGER.info("Cannot retransmit flight to peer [{}]", flight.getPeerAddress(), e);
						} catch (GeneralSecurityException e) {
							LOGGER.info("Cannot retransmit flight to peer [{}]", flight.getPeerAddress(), e);
							cause = e;
						}
					} else {
						LOGGER.debug("Flight for [{}] has reached maximum no. [{}] of retransmissions, discarding ...",
								flight.getPeerAddress(), max);
					}
				}
				if (cause == null) {
					cause = new Exception("handshake flight " + flight.getFlightNumber() + " timeout!");
				} else {
					cause = new Exception("handshake flight " + flight.getFlightNumber() + " failed!", cause);
				}

				// inform handshaker
				handshaker.handshakeFailed(cause);
			}
		}
	}

	private void scheduleRetransmission(DTLSFlight flight) {

		if (flight.isRetransmissionNeeded()) {

			// calculate timeout using exponential back-off
			if (flight.getTimeout() == 0) {
				// use initial timeout
				flight.setTimeout(config.getRetransmissionTimeout());
			} else {
				// double timeout
				flight.incrementTimeout();
			}

			// schedule retransmission task
			ScheduledFuture<?> f = timer.schedule(new RetransmitTask(flight), flight.getTimeout(), TimeUnit.MILLISECONDS);
			flight.setRetransmitTask(f);
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
	public final int getMaximumTransmissionUnit() {
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
	public final int getMaximumFragmentLength(InetSocketAddress peer) {
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
		DatagramSocket socket = getSocket();
		if (socket == null) {
			return config.getAddress();
		} else {
			return new InetSocketAddress(socket.getLocalAddress(), socket.getLocalPort());
		}
	}

	/**
	 * Checks if this connector is running.
	 * 
	 * @return {@code true} if running.
	 */
	public final boolean isRunning() {
		return running.get();
	}

	private RecordLayer getRecordLayerForPeer(final Connection connection) {
		return new RecordLayer() {

			@Override
			public void sendRecord(Record record) {
				sendRecord(record);
			}

			@Override
			public void sendFlight(DTLSFlight flight) {
				sendHandshakeFlight(flight, connection);
			}

			public void cancelRetransmissions() {
				// TODO remove this check when this experimental feature will be
				// not experimental anymore ^^
				if (config.isEarlyStopRetransmission()) {
					connection.cancelPendingFlight();
				}
			}
		};
	}

	private class RetransmitTask implements Runnable {

		private DTLSFlight flight;

		RetransmitTask(final DTLSFlight flight) {
			this.flight = flight;
		}

		@Override
		public void run() {
			if (running.get()) {
				final SerialExecutor serialExecutor = getSerialExecutor(flight.getPeerAddress());
				if (serialExecutor == null) {
					LOGGER.debug("Execution cache is full while retransmission of flight [peer: {}]",
							flight.getPeerAddress());
				} else {
					try {
						serialExecutor.execute(new Runnable() {

							@Override
							public void run() {
								if (!flight.isRetransmissionCancelled()) {
									handleTimeout(flight, true);
								}
							}
						});
						return;
					} catch (RejectedExecutionException e) {
						LOGGER.debug("Execution rejected while retransmission of flight [peer: {}]",
								flight.getPeerAddress(), e);
					}
				}
			}
			handleTimeout(flight, false);
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
		protected Worker(String name) {
			super(NamedThreadFactory.SCANDIUM_THREAD_GROUP, name);
		}

		@Override
		public void run() {
			try {
				LOGGER.info("Starting worker thread [{}]", getName());
				while (running.get()) {
					try {
						doWork();
					} catch (ClosedByInterruptException e) {
						LOGGER.info("Worker thread [{}] has been interrupted", getName());
					} catch (Exception e) {
						if (running.get()) {
							LOGGER.debug("Exception thrown by worker thread [{}]", getName(), e);
						}
					}
				}
			} finally {
				LOGGER.info("Worker thread [{}] has terminated", getName());
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
	public void setRawDataReceiver(final RawDataChannel messageHandler) {
		if (isRunning()) {
			throw new IllegalStateException("message handler cannot be set on running connector");
		}
		this.messageHandler = messageHandler;
	}

	@Override
	public synchronized void setEndpointContextMatcher(EndpointContextMatcher endpointContextMatcher) {
		this.endpointContextMatcher = endpointContextMatcher;
	}

	private synchronized EndpointContextMatcher getEndpointContextMatcher() {
		return endpointContextMatcher;
	}

	/**
	 * Sets a handler to call back if an alert message is received from a peer.
	 * <p>
	 * Setting a handler using this method is useful to be notified when a peer closes
	 * an existing connection, i.e. when the alert message has not been received during
	 * a handshake but after the connection has been established.
	 * <p>
	 * The handler can be set (and changed) at any time, either before the connector has
	 * been started or when the connector is already running.
	 * <p>
	 * Application code interested in being notified when a particular message cannot be sent,
	 * e.g. due to a failing DTLS handshake that has been triggered as part of sending
	 * the message, should instead register a
	 * {@code org.eclipse.californium.core.coap.MessageObserver} on the message and
	 * implement its <em>onSendError</em> method accordingly.
	 * 
	 * @param handler The handler to notify.
	 */
	public final void setAlertHandler(AlertHandler handler) {
		synchronized (alertHandlerLock) {
			this.alertHandler = handler;
		}
	}

	private void handleExceptionDuringHandshake(HandshakeException cause, AlertLevel level, AlertDescription description, Record record) {
		// discard none fatal alert exception
		if (!AlertLevel.FATAL.equals(level)) {
			discardRecord(record, cause);
			return;
		}

		// "Unknown identity" and "bad PSK" should be both handled in a same way.
		// Generally "bad PSK" means invalid MAC on FINISHED message.
		// In production both should be silently ignored : https://bugs.eclipse.org/bugs/show_bug.cgi?id=533258
		if (AlertDescription.UNKNOWN_PSK_IDENTITY == description) {
			discardRecord(record, cause);
			return;
		}

		// in other cases terminate handshake
		terminateOngoingHandshake(record.getPeerAddress(), cause, description);
	}

	private static void discardRecord(final Record record, final Throwable cause) {
		if (LOGGER.isTraceEnabled()) {
			LOGGER.trace("Discarding {} record from peer [{}]: ", record.getType(), record.getPeerAddress(), cause);
		} else if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(
				"Discarding {} record from peer [{}]: {}",
				new Object[]{record.getType(), record.getPeerAddress(), cause.getMessage()});
		}
	}

	@Override
	public String getProtocol() {
		return "DTLS";
	}

	@Override
	public String toString() {
		return getProtocol() + "-" + getAddress();
	}	
}
