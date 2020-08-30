/*******************************************************************************
 * Copyright (c) 2015, 2018 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove unused RecordLayer.sendRecord
 *    Achim Kraus (Bosch Software Innovations GmbH) - redesign DTLSFlight and RecordLayer
 *                                                    add timeout for handshakes
 *    Achim Kraus (Bosch Software Innovations GmbH) - move serial executor into connection
 *                                                    process new CLIENT_HELLOs without
 *                                                    serial executor.
 ******************************************************************************/
package org.eclipse.californium.scandium;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.PortUnreachableException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.exception.EndpointMismatchException;
import org.eclipse.californium.elements.exception.EndpointUnconnectedException;
import org.eclipse.californium.elements.exception.MulticastNotSupportedException;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.LeastRecentlyUsedCache;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.NoPublicAPI;
import org.eclipse.californium.elements.util.SerialExecutor;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.ApplicationMessage;
import org.eclipse.californium.scandium.dtls.AvailableConnections;
import org.eclipse.californium.scandium.dtls.ClientHandshaker;
import org.eclipse.californium.scandium.dtls.ClientHello;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.ConnectionEvictedException;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.ConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.ContentType;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.DtlsHandshakeException;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.HandshakeMessage;
import org.eclipse.californium.scandium.dtls.Handshaker;
import org.eclipse.californium.scandium.dtls.HelloVerifyRequest;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.dtls.PskSecretResultHandler;
import org.eclipse.californium.scandium.dtls.MaxFragmentLengthExtension;
import org.eclipse.californium.scandium.dtls.ProtocolVersion;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.RecordLayer;
import org.eclipse.californium.scandium.dtls.ResumingClientHandshaker;
import org.eclipse.californium.scandium.dtls.ResumingServerHandshaker;
import org.eclipse.californium.scandium.dtls.ResumptionSupportingConnectionStore;
import org.eclipse.californium.scandium.dtls.ServerHandshaker;
import org.eclipse.californium.scandium.dtls.ServerNameExtension;
import org.eclipse.californium.scandium.dtls.SessionAdapter;
import org.eclipse.californium.scandium.dtls.SessionCache;
import org.eclipse.californium.scandium.dtls.SessionId;
import org.eclipse.californium.scandium.dtls.SessionListener;
import org.eclipse.californium.scandium.dtls.SessionTicket;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedPskStore;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * A {@link Connector} using <em>Datagram TLS</em> (DTLS) as specified in
 * <a href="http://tools.ietf.org/html/rfc6347">RFC 6347</a> for securing data
 * exchanged between networked clients and a server application.
 */
public class DTLSConnector implements Connector, RecordLayer {

	/**
	 * The {@code EndpointContext} key used to store the host name indicated by a
	 * client in an SNI hello extension.
	 */
	public static final String KEY_TLS_SERVER_HOST_NAME = "TLS_SERVER_HOST_NAME";

	private static final Logger LOGGER = LoggerFactory.getLogger(DTLSConnector.class);
	private static final Logger DROP_LOGGER = LoggerFactory.getLogger(LOGGER.getName() + ".drops");
	private static final int MAX_PLAINTEXT_FRAGMENT_LENGTH = 16384; // max. DTLSPlaintext.length (2^14 bytes)
	private static final int MAX_CIPHERTEXT_EXPANSION = CipherSuite.getOverallMaxCiphertextExpansion();
	private static final int MAX_DATAGRAM_BUFFER_SIZE = MAX_PLAINTEXT_FRAGMENT_LENGTH
			+ DTLSSession.DTLS_HEADER_LENGTH
			+ MAX_CIPHERTEXT_EXPANSION;

	/**
	 * Additional padding used by the new record type introduced with the
	 * connection id. May be randomized to obfuscate the payload length. Due to
	 * the ongoing discussion in draft-ietf-tls-dtls-connection-id, currently
	 * only a fixed value.
	 */
	private static final int TLS12_CID_PADDING = 0;

	private static final long CLIENT_HELLO_TIMEOUT_MILLIS = TimeUnit.SECONDS.toMillis(60);

	/** all the configuration options for the DTLS connector */ 
	private final DtlsConnectorConfig config;

	private final ResumptionSupportingConnectionStore connectionStore;

	/**
	 * General auto resumption timeout in milliseconds. {@code null}, if auto
	 * resumption is not used.
	 */
	private final Long autoResumptionTimeoutMillis;

	private final int thresholdHandshakesWithoutVerifiedPeer;
	private final AtomicInteger pendingHandshakesWithoutVerifiedPeer = new AtomicInteger();
	private final DtlsHealth health;

	private final boolean serverOnly;
	private final String defaultHandshakeMode;
	/**
	 * Apply record filter only for records within the receive window.
	 */
	private final int useExtendedWindowFilter;
	/**
	 * Apply record filter.
	 */
	private final boolean useFilter;
	/**
	 * Apply address update only for newer records based on epoch/sequence_number.
	 */
	private final boolean useCidUpdateAddressOnNewerRecordFilter;

	/**
	 * (Down-)counter for pending outbound messages. Initialized with
	 * {@link DtlsConnectorConfig#getOutboundMessageBufferSize()}.
	 */
	private final AtomicInteger pendingOutboundMessagesCountdown = new AtomicInteger();

	private final List<Thread> receiverThreads = new LinkedList<Thread>();

	/**
	 * Configure connection id generator. May be {@code null}, if connection id
	 * should not be supported.
	 */
	private final ConnectionIdGenerator connectionIdGenerator;

	private ScheduledFuture<?> statusLogger;

	private InetSocketAddress lastBindAddress;
	/**
	 * Provided or configured maximum transmission unit.
	 */
	private Integer maximumTransmissionUnit;
	/**
	 * IPv4 maximum transmission unit.
	 * @since 2.4
	 */
	private int ipv4Mtu = DEFAULT_IPV4_MTU;
	/**
	 * IPv6 maximum transmission unit.
	 * @since 2.4
	 */
	private int ipv6Mtu = DEFAULT_IPV6_MTU;
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
	 * @see #sendMessage(RawData, Connection)
	 * @see #sendMessage(RawData, Connection, DTLSSession)
	 */
	private volatile EndpointContextMatcher endpointContextMatcher;

	private RawDataChannel messageHandler;
	private AlertHandler alertHandler;
	private SessionListener sessionListener;
	private ConnectionExecutionListener connectionExecutionListener;
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
						sessionCache).setTag(configuration.getLoggingTag()));
	}

	/**
	 * Creates a DTLS connector for a given set of configuration options.
	 * 
	 * The connection store must use the same connection id generator as
	 * configured in the provided configuration.
	 * 
	 * @param configuration The configuration options.
	 * @param connectionStore The registry to use for managing connections to
	 *            peers.
	 * @throws NullPointerException if any of the parameters is
	 *             <code>null</code>.
	 * @throws IllegalArgumentException if the connection store uses a different
	 *             cid generator than the configuration.
	 */
	protected DTLSConnector(final DtlsConnectorConfig configuration, final ResumptionSupportingConnectionStore connectionStore) {
		if (configuration == null) {
			throw new NullPointerException("Configuration must not be null");
		} else if (connectionStore == null) {
			throw new NullPointerException("Connection store must not be null");
		} else {
			this.connectionIdGenerator = configuration.getConnectionIdGenerator();
			this.config = configuration;
			this.pendingOutboundMessagesCountdown.set(config.getOutboundMessageBufferSize());
			this.autoResumptionTimeoutMillis = config.getAutoResumptionTimeoutMillis();
			this.serverOnly = config.isServerOnly();
			this.defaultHandshakeMode = config.getDefaultHandshakeMode();
			this.useExtendedWindowFilter = config.useExtendedWindowFilter();
			this.useFilter = config.useAntiReplayFilter() || useExtendedWindowFilter != 0;
			this.useCidUpdateAddressOnNewerRecordFilter = config.useCidUpdateAddressOnNewerRecordFilter();
			this.connectionStore = connectionStore;
			this.connectionStore.attach(connectionIdGenerator);
			this.connectionStore.setConnectionListener(config.getConnectionListener());
			ConnectionListener listener = config.getConnectionListener();
			if (listener instanceof ConnectionExecutionListener) {
				this.connectionExecutionListener = (ConnectionExecutionListener) listener;
			}
			AdvancedPskStore advancedPskStore = config.getAdvancedPskStore();
			if (advancedPskStore != null) {
				advancedPskStore.setResultHandler(new PskSecretResultHandler() {

					@Override
					public void apply(PskSecretResult masterSecretResult) {
						processAsyncPskSecretResult(masterSecretResult);
					}
				});
			}
			DtlsHealth healthHandler = config.getHealthHandler();
			Integer healthStatusInterval = config.getHealthStatusInterval();
			// this is a useful health metric
			// that could later be exported to some kind of monitoring interface
			if (healthHandler == null && healthStatusInterval != null && healthStatusInterval > 0) {
				healthHandler = new DtlsHealthLogger(configuration.getLoggingTag());
				if (!healthHandler.isEnabled()) {
					healthHandler = null;
				}
			}
			this.health = healthHandler;
			this.sessionListener = new SessionAdapter() {

				@Override
				public void sessionEstablished(Handshaker handshaker, DTLSSession establishedSession)
						throws HandshakeException {
					DTLSConnector.this.sessionEstablished(handshaker, establishedSession);
				}

				@Override
				public void handshakeCompleted(final Handshaker handshaker) {
					if (health != null) {
						health.endHandshake(true);
					}
					final Connection connection = handshaker.getConnection();
					ScheduledExecutorService timer = DTLSConnector.this.timer;
					if (timer != null) {
						try {
							timer.schedule(new Runnable() {

								@Override
								public void run() {
									connection.startByClientHello(null);
								}
							}, CLIENT_HELLO_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
							return;
						} catch (RejectedExecutionException ex) {
							LOGGER.debug("stopping.");
						}
					}
					// fallback, if execution is rejected
					connection.startByClientHello(null);
				}

				@Override
				public void handshakeFailed(Handshaker handshaker, Throwable error) {
					if (health != null) {
						health.endHandshake(false);
					}
					List<RawData> listOut = handshaker.takeDeferredApplicationData();
					if (!listOut.isEmpty()) {
						LOGGER.debug("Handshake with [{}] failed, report error to deferred {} messages",
								handshaker.getPeerAddress(), listOut.size());
						for (RawData message : listOut) {
							message.onError(error);
						}
					}
					Connection connection = handshaker.getConnection();
					if (handshaker.isRemovingConnection()) {
						connectionStore.remove(connection, false);
					} else if (handshaker.isProbing()) {
						LOGGER.debug("Handshake with [{}] failed within probe!", handshaker.getPeerAddress());
					} else if (connection.getEstablishedSession() == handshaker.getSession()) {
						if (error instanceof HandshakeException) {
							AlertMessage alert = ((HandshakeException)error).getAlert();
							if (alert != null && alert.getDescription() == AlertDescription.CLOSE_NOTIFY) {
								LOGGER.debug("Handshake with [{}] closed after session was established!",
										handshaker.getPeerAddress());
							} else {
								LOGGER.warn("Handshake with [{}] failed after session was established! {}",
										handshaker.getPeerAddress(), alert);
							}
						} else {
							// failure after established (last FINISH),
							// but before completed (first data)
							if (error instanceof ConnectionEvictedException) {
								LOGGER.debug("Handshake with [{}] never get APPLICATION_DATA",
										handshaker.getPeerAddress(), error);
							} else {
								LOGGER.warn("Handshake with [{}] failed after session was established!",
										handshaker.getPeerAddress(), error);
							}
						}
					} else if (connection.hasEstablishedSession()) {
						LOGGER.warn("Handshake with [{}] failed, but has an established session!",
								handshaker.getPeerAddress());
					} else {
						LOGGER.warn("Handshake with [{}] failed, connection preserved!", handshaker.getPeerAddress());
					}
				}
			};
			int maxConnections = configuration.getMaxConnections();
			// calculate absolute threshold from relative.
			long thresholdInPercent = config.getVerifyPeersOnResumptionThreshold();
			long threshold = (((long) maxConnections * thresholdInPercent) + 50L) / 100L;
			if (threshold == 0 && thresholdInPercent > 0) {
				threshold = 1;
			}
			this.thresholdHandshakesWithoutVerifiedPeer = (int) threshold;
		}
	}

	private final void sessionEstablished(Handshaker handshaker, final DTLSSession establishedSession)
			throws HandshakeException {
		try {
			final Connection connection = handshaker.getConnection();
			connectionStore.putEstablishedSession(establishedSession, connection);
			final SerialExecutor serialExecutor = connection.getExecutor();
			List<RawData> listOut = handshaker.takeDeferredApplicationData();
			if (!listOut.isEmpty()) {
				LOGGER.trace("Session with [{}] established, now process deferred {} messages",
						establishedSession.getPeer(), listOut.size());
				for (RawData message : listOut) {
					final RawData rawData = message;
					serialExecutor.execute(new Runnable() {

						@Override
						public void run() {
							sendMessage(rawData, connection, establishedSession);
						}
					});
				}
			}
			List<Record> listIn = handshaker.takeDeferredRecords();
			if (!listIn.isEmpty()) {
				LOGGER.trace("Session with [{}] established, now process deferred {} messages",
						establishedSession.getPeer(), listIn.size());
				for (Record message : listIn) {
					final Record record = message;
					serialExecutor.execute(new Runnable() {

						@Override
						public void run() {
							processRecord(record, connection);
						}
					});
				}
			}
		} catch (RejectedExecutionException ex) {
			LOGGER.debug("stopping.");
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
			if (health != null) {
				health.startHandshake();
			}
		}
		onInitializeHandshaker(handshaker);
	}

	/**
	 * Sets the executor to be used for processing records.
	 * <p>
	 * If this property is not set before invoking the {@linkplain #start()
	 * start method}, a new {@link ExecutorService} is created with a thread
	 * pool of {@linkplain DtlsConnectorConfig#getConnectionThreadCount() size}.
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
	 * @throws IllegalStateException if executor cache is exceeded.
	 */
	public final void close(InetSocketAddress peerAddress) {
		final Connection connection = getConnection(peerAddress, null, false);
		if (connection != null && connection.hasEstablishedSession()) {
			SerialExecutor serialExecutor = connection.getExecutor();
			serialExecutor.execute(new Runnable() {

				@Override
				public void run() {
					DTLSSession session = connection.getEstablishedSession();
					if (session != null) {
						terminateConnection(connection, new AlertMessage(AlertLevel.WARNING,
								AlertDescription.CLOSE_NOTIFY, connection.getPeerAddress()), session);
					}
				}
			});
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
	 * Note: intended for unit tests only!
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

	private synchronized ExecutorService getExecutorService() {
		return executorService;
	}

	/**
	 * Start connector.
	 * 
	 * @param bindAddress address to bind socket.
	 * @throws IOException I/O error
	 */
	protected void start(InetSocketAddress bindAddress) throws IOException {
		if (running.get()) {
			return;
		}
		init(bindAddress, new DatagramSocket(null), config.getMaxTransmissionUnit());
	}

	/**
	 * Initialize socket ad start connector.
	 * 
	 * @param bindAddress address to bind socket
	 * @param socket socket
	 * @param mtu mtu of socket, or {@code null}, if socket implementation
	 *            doesn't use a special mtu.
	 * @throws IOException I/O error
	 * @since 2.1
	 */
	protected void init(InetSocketAddress bindAddress, DatagramSocket socket, Integer mtu) throws IOException {
		this.socket = socket;
		pendingOutboundMessagesCountdown.set(config.getOutboundMessageBufferSize());

		if (bindAddress.getPort() != 0 && config.isAddressReuseEnabled()) {
			// make it easier to stop/start a server consecutively without delays
			LOGGER.info("Enable address reuse for socket!");
			socket.setReuseAddress(true);
			if (!socket.getReuseAddress()) {
				LOGGER.warn("Enable address reuse for socket failed!");
			}
		}

		Integer size = config.getSocketReceiveBufferSize();
		try {
			if (size != null && size != 0) {
				socket.setReceiveBufferSize(size);
			}
			size = config.getSocketSendBufferSize();
			if (size != null && size != 0) {
				socket.setSendBufferSize(size);
			}
		} catch(IllegalArgumentException ex) {
			LOGGER.error("failed to apply {}", size, ex);
		}
		// don't try to access the buffer sizes,
		// when receive may already lock the socket!
		int recvBuffer = socket.getReceiveBufferSize();
		int sendBuffer = socket.getSendBufferSize();

		socket.bind(bindAddress);
		if (lastBindAddress != null && (!socket.getLocalAddress().equals(lastBindAddress.getAddress()) || socket.getLocalPort() != lastBindAddress.getPort())){
			if (connectionStore instanceof ResumptionSupportingConnectionStore) {
				((ResumptionSupportingConnectionStore) connectionStore).markAllAsResumptionRequired();
			} else {
				connectionStore.clear();
			}
		}

		if (config.getMaxFragmentLengthCode() != null) {
			MaxFragmentLengthExtension.Length lengthCode = MaxFragmentLengthExtension.Length.fromCode(
					config.getMaxFragmentLengthCode());
			// reduce inbound buffer size accordingly
			inboundDatagramBufferSize = lengthCode.length()
					+ MAX_CIPHERTEXT_EXPANSION
					+ 25; // 12 bytes DTLS message headers, 13 bytes DTLS record headers
		}

		if (config.getMaxTransmissionUnit() != null) {
			this.maximumTransmissionUnit = config.getMaxTransmissionUnit();
			LOGGER.info("Configured MTU [{}]", this.maximumTransmissionUnit);
		} else if (mtu != null) {
			this.maximumTransmissionUnit = mtu;
			LOGGER.info("Forced MTU [{}]", this.maximumTransmissionUnit);
		} else {
			InetAddress localInterfaceAddress = bindAddress.getAddress();
			if (localInterfaceAddress.isAnyLocalAddress()) {
				ipv4Mtu = NetworkInterfacesUtil.getIPv4Mtu();
				ipv6Mtu = NetworkInterfacesUtil.getIPv6Mtu();
				LOGGER.info("multiple network interfaces, using smallest MTU [IPv4 {}, IPv6 {}]", ipv4Mtu, ipv6Mtu);
			} else {
				NetworkInterface ni = NetworkInterface.getByInetAddress(localInterfaceAddress);
				boolean ipv6 = localInterfaceAddress instanceof Inet6Address;
				if (ni != null && ni.getMTU() > 0) {
					if (ipv6) {
						ipv6Mtu = ni.getMTU();
					} else {
						ipv4Mtu = ni.getMTU();
					}
				} else if (ipv6) {
					ipv6Mtu = NetworkInterfacesUtil.getIPv6Mtu();
					LOGGER.info("Cannot determine MTU of network interface, using minimum MTU [{}] of IPv6 instead", ipv6Mtu);
				} else {
					ipv4Mtu = NetworkInterfacesUtil.getIPv4Mtu();
					LOGGER.info("Cannot determine MTU of network interface, using minimum MTU [{}] of IPv4 instead", ipv4Mtu);
				}
			}
			if (inboundDatagramBufferSize > config.getMaxTransmissionUnitLimit()) {
				if (ipv4Mtu > config.getMaxTransmissionUnitLimit()) {
					ipv4Mtu = config.getMaxTransmissionUnitLimit();
					LOGGER.info("Limit MTU IPv4[{}]", ipv4Mtu);
				}
				if (ipv6Mtu > config.getMaxTransmissionUnitLimit()) {
					ipv6Mtu = config.getMaxTransmissionUnitLimit();
					LOGGER.info("Limit MTU IPv6[{}]", ipv6Mtu);
				}
			} else {
				if (ipv4Mtu > inboundDatagramBufferSize) {
					ipv4Mtu = inboundDatagramBufferSize;
					LOGGER.info("Buffersize MTU IPv4[{}]", ipv4Mtu);
				}
				if (ipv6Mtu > inboundDatagramBufferSize) {
					ipv6Mtu = inboundDatagramBufferSize;
					LOGGER.info("Buffersize MTU IPv6[{}]", ipv6Mtu);
				}
			}
		}

		lastBindAddress = new InetSocketAddress(socket.getLocalAddress(), socket.getLocalPort());

		if (executorService instanceof ScheduledExecutorService) {
			timer = (ScheduledExecutorService) executorService;
		} else {
			timer = ExecutorsUtil.newSingleThreadScheduledExecutor(new DaemonThreadFactory(
					"DTLS-Timer-" + lastBindAddress + "#", NamedThreadFactory.SCANDIUM_THREAD_GROUP)); //$NON-NLS-1$
		}

		if (executorService == null) {
			int threadCount = config.getConnectionThreadCount();
			if (threadCount > 1) {
				executorService = ExecutorsUtil.newFixedThreadPool(threadCount - 1, new DaemonThreadFactory(
						"DTLS-Worker-" + lastBindAddress + "#", NamedThreadFactory.SCANDIUM_THREAD_GROUP)); //$NON-NLS-1$
			} else {
				executorService = timer;
			}
			this.hasInternalExecutor = true;
		}

		running.set(true);

		int receiverThreadCount = config.getReceiverThreadCount();
		for (int i = 0; i < receiverThreadCount; i++) {
			Worker receiver = new Worker("DTLS-Receiver-" + i + "-" + lastBindAddress) {

				private final byte[] receiverBuffer = new byte[inboundDatagramBufferSize];
				private final DatagramPacket packet = new DatagramPacket(receiverBuffer, inboundDatagramBufferSize);

				@Override
				public void doWork() throws Exception {
					MDC.clear();
					packet.setLength(inboundDatagramBufferSize);
					receiveNextDatagramFromNetwork(packet);
				}
			};
			receiver.setDaemon(true);
			receiver.start();
			receiverThreads.add(receiver);
		}

		String mtuDescription = maximumTransmissionUnit != null ? maximumTransmissionUnit.toString() : "IPv4 " + ipv4Mtu + " / IPv6 " + ipv6Mtu;
		LOGGER.info("DTLSConnector listening on {}, recv buf = {}, send buf = {}, recv packet size = {}, MTU = {}",
				lastBindAddress, recvBuffer, sendBuffer, inboundDatagramBufferSize, mtuDescription);

		// this is a useful health metric
		// that could later be exported to some kind of monitoring interface
		if (health != null && health.isEnabled()) {
			final Integer healthStatusInterval = config.getHealthStatusInterval();
			if (healthStatusInterval != null) {
				statusLogger = timer.scheduleAtFixedRate(new Runnable() {

					@Override
					public void run() {
						health.dump(config.getLoggingTag(), config.getMaxConnections(), connectionStore.remainingCapacity(), pendingHandshakesWithoutVerifiedPeer.get());
					}

				}, healthStatusInterval, healthStatusInterval, TimeUnit.SECONDS);
			}
		}
	}

	/**
	 * Force connector to an abbreviated handshake. See <a href="https://tools.ietf.org/html/rfc5246#section-7.3">RFC 5246</a>.
	 * 
	 * The abbreviated handshake will be done next time data will be sent with {@link #send(RawData)}.
	 * @param peer the peer for which we will force to do an abbreviated handshake
	 */
	public final synchronized void forceResumeSessionFor(InetSocketAddress peer) {
		Connection peerConnection = connectionStore.get(peer);
		if (peerConnection != null && peerConnection.hasEstablishedSession()) {
			peerConnection.setResumptionRequired(true);
		}
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

	private final DatagramSocket getSocket() {
		return socket;
	}

	@Override
	public final void stop() {
		ExecutorService shutdownTimer = null;
		ExecutorService shutdown = null;
		List<Runnable> pending = new ArrayList<>();
		synchronized (this) {
			if (running.compareAndSet(true, false)) {
				if (statusLogger != null) {
					statusLogger.cancel(false);
					statusLogger = null;
				}
				LOGGER.info("Stopping DTLS connector on [{}]", lastBindAddress);
				for (Thread t : receiverThreads) {
					t.interrupt();
				}
				if (socket != null) {
					socket.close();
					socket = null;
				}
				maximumTransmissionUnit = null;
				ipv4Mtu = DEFAULT_IPV4_MTU;
				ipv6Mtu = DEFAULT_IPV6_MTU;
				connectionStore.stop(pending);
				if (executorService != timer) {
					pending.addAll(timer.shutdownNow());
					shutdownTimer = timer;
					timer = null;
				}
				if (hasInternalExecutor) {
					pending.addAll(executorService.shutdownNow());
					shutdown = executorService;
					executorService = null;
					hasInternalExecutor = false;
				}
				for (Thread t : receiverThreads) {
					t.interrupt();
					try {
						t.join(500);
					} catch (InterruptedException e) {
					}
				}
				receiverThreads.clear();
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
			try {
				job.run();
			} catch (Exception e) {
				LOGGER.warn("Shutdown DTLS connector:", e);
			}
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
	 * Start to terminate connections related to the provided principals.
	 * 
	 * Note: if {@link SessionCache} is used, it's not possible to remove a
	 * cache entry, if no related connection is in the connection store.
	 * 
	 * @param principal principal, which connections are to terminate
	 * @return future to cancel or wait for completion
	 */
	public Future<Void> startDropConnectionsForPrincipal(final Principal principal) {
		if (principal == null) {
			throw new NullPointerException("principal must not be null!");
		}
		LeastRecentlyUsedCache.Predicate<Principal> handler = new LeastRecentlyUsedCache.Predicate<Principal>() {

			@Override
			public boolean accept(Principal connectionPrincipal) {
				return principal.equals(connectionPrincipal);
			}
		};
		return startTerminateConnectionsForPrincipal(handler);
	}

	/**
	 * Start to terminate connections applying the provided handler to the
	 * principals of all connections.
	 * 
	 * Note: if {@link SessionCache} is used, it's not possible to remove a
	 * cache entry, if no related connection is in the connection store.
	 * 
	 * @param principalHandler handler to be called within the serial execution
	 *            of the related connection. If {@code true} is returned, the
	 *            related connection is terminated
	 * @return future to cancel or wait for completion
	 */
	public Future<Void> startTerminateConnectionsForPrincipal(
			final LeastRecentlyUsedCache.Predicate<Principal> principalHandler) {
		if (principalHandler == null) {
			throw new NullPointerException("principal handler must not be null!");
		}
		LeastRecentlyUsedCache.Predicate<Connection> connectionHandler = new LeastRecentlyUsedCache.Predicate<Connection>() {

			@Override
			public boolean accept(Connection connection) {
				Principal peer = null;
				SessionTicket ticket = connection.getSessionTicket();
				if (ticket != null) {
					peer = ticket.getClientIdentity();
				} else {
					DTLSSession session = connection.getSession();
					if (session != null) {
						peer = session.getPeerIdentity();
					}
				}
				if (peer != null && principalHandler.accept(peer)) {
					connectionStore.remove(connection, true);
				}
				return false;
			}
		};
		return startForEach(connectionHandler);
	}

	/**
	 * Start applying provided handler to all connections.
	 * 
	 * @param handler handler to be called within the serial execution of the
	 *            passed in connection. If {@code true} is returned, iterating
	 *            is stopped.
	 * @return future to cancel or wait for completion
	 */
	public Future<Void> startForEach(LeastRecentlyUsedCache.Predicate<Connection> handler) {
		if (handler == null) {
			throw new NullPointerException("handler must not be null!");
		}
		ForEachFuture result = new ForEachFuture();
		nextForEach(connectionStore.iterator(), handler, result);
		return result;
	}

	/**
	 * Calls provided handler for each connection returned be the provided
	 * iterator.
	 * 
	 * @param iterator iterator over connections
	 * @param handler handler to be called for all connections returned by the
	 *            iterator. Iteration is stopped, when handler returns
	 *            {@code true}
	 * @param result future to get cancelled or signal completion
	 */
	private void nextForEach(final Iterator<Connection> iterator,
			final LeastRecentlyUsedCache.Predicate<Connection> handler, final ForEachFuture result) {

		if (!result.isStopped() && iterator.hasNext()) {
			final Connection next = iterator.next();
			try {
				next.getExecutor().execute(new Runnable() {

					@Override
					public void run() {
						boolean done = true;
						try {
							if (!result.isStopped() && !handler.accept(next)) {
								done = false;
								nextForEach(iterator, handler, result);
							}
						} catch (Exception exception) {
							result.failed(exception);
						} finally {
							if (done) {
								result.done();
							}
						}
					}
				});
				return;
			} catch (RejectedExecutionException ex) {
				if (!handler.accept(next)) {
					while (iterator.hasNext()) {
						if (handler.accept(iterator.next())) {
							break;
						}
						if (result.isStopped()) {
							break;
						}
					}
				}
			}
		}
		result.done();
	}

	/**
	 * Get connection to communication with peer.
	 * 
	 * @param peerAddress socket address of peer
	 * @param cid connection id. {@code null}, if cid extension is not used
	 * @param create {@code true}, create new connection, if connection is not
	 *            available.
	 * @return connection to communication with peer. {@code null}, if store is
	 *         exhausted or if the connection is not available and the provided
	 *         parameter create is {@code false}.
	 */
	private final Connection getConnection(InetSocketAddress peerAddress, ConnectionId cid, boolean create) {
		ExecutorService executor = getExecutorService();
		synchronized (connectionStore) {
			Connection connection;
			if (cid != null) {
				connection = connectionStore.get(cid);
			} else {
				connection = connectionStore.get(peerAddress);
				if (connection == null && create) {
					LOGGER.trace("create new connection for {}", peerAddress);
					Connection newConnection = new Connection(peerAddress, new SerialExecutor(executor));
					newConnection.setExecutionListener(connectionExecutionListener);
					if (running.get()) {
						// only add, if connector is running!
						if (!connectionStore.put(newConnection)) {
							return null;
						}
					}
					return newConnection;
				}
			}
			if (connection == null) {
				LOGGER.trace("no connection available for {},{}", peerAddress, cid);
			} else if (!connection.isExecuting() && running.get()) {
				LOGGER.trace("revive connection for {},{}", peerAddress, cid);
				connection.setExecutor(new SerialExecutor(executor));
			} else {
				LOGGER.trace("connection available for {},{}", peerAddress, cid);
			}
			return connection;
		}
	}

	/**
	 * Receive the next datagram from network.
	 * 
	 * Potentially called by multiple threads.
	 * 
	 * @param packet datagram the be read from network
	 * @throws IOException if anio- error occurred
	 * @see #processDatagram(DatagramPacket)
	 */
	protected void receiveNextDatagramFromNetwork(DatagramPacket packet) throws IOException {

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

		processDatagram(packet);
	}

	/**
	 * Process received datagram.
	 * 
	 * Potentially called by multiple threads.
	 * 
	 * @param packet datagram filled with the received data and source address.
	 */
	protected void processDatagram(DatagramPacket packet) {
		InetSocketAddress peerAddress = new InetSocketAddress(packet.getAddress(), packet.getPort());
		MDC.put("PEER", StringUtil.toString(peerAddress));
		if (health != null) {
			health.receivingRecord(false);
		}
		long timestamp = ClockUtil.nanoRealtime();

		DatagramReader reader = new DatagramReader(packet.getData(), packet.getOffset(), packet.getLength());
		List<Record> records = Record.fromReader(reader, peerAddress, connectionIdGenerator, timestamp);
		LOGGER.trace("Received {} DTLS records from {} using a {} byte datagram buffer",
				records.size(), peerAddress, inboundDatagramBufferSize);

		if (records.isEmpty()) {
			DROP_LOGGER.trace("Discarding {} malicious record with {} bytes from [{}]", packet.getLength(), peerAddress);
			if (health != null) {
				health.receivingRecord(true);
			}
			return;
		}

		if (!running.get()) {
			DROP_LOGGER.trace("Discarding {} records, startting with {} from [{}] on shutdown", records.size(),
					records.get(0).getType(), peerAddress);
			LOGGER.debug("Execution shutdown while processing incoming records from peer: {}", peerAddress);
			if (health != null) {
				health.receivingRecord(true);
			}
			return;
		}

		final Record firstRecord = records.get(0);

		if (records.size() == 1 && firstRecord.isNewClientHello()) {
			executorService.execute(new Runnable() {

				@Override
				public void run() {
					MDC.put("PEER", StringUtil.toString(firstRecord.getPeerAddress()));
					processNewClientHello(firstRecord);
					MDC.clear();
				}
			});
			return;
		}

		final ConnectionId connectionId = firstRecord.getConnectionId();
		final Connection connection = getConnection(peerAddress, connectionId, false);

		if (connection == null) {
			if (health != null) {
				health.receivingRecord(true);
			}
			if (connectionId == null) {
				DROP_LOGGER.trace("Discarding {} records from [{}] received without existing connection",
						records.size(), peerAddress);
			} else {
				DROP_LOGGER.trace("Discarding {} records from [{},{}] received without existing connection",
						records.size(), peerAddress, connectionId);
			}
			return;
		}

		SerialExecutor serialExecutor = connection.getExecutor();

		for (final Record record : records) {
			try {

				serialExecutor.execute(new Runnable() {

					@Override
					public void run() {
						if (running.get()) {
							processRecord(record, connection);
						}
					}
				});
			} catch (RejectedExecutionException e) {
				// dont't terminate connection on shutdown!
				LOGGER.debug("Execution rejected while processing record [type: {}, peer: {}]",
						record.getType(), peerAddress, e);
				break;
			} catch (RuntimeException e) {
				LOGGER.warn("Unexpected error occurred while processing record [type: {}, peer: {}]",
						record.getType(), peerAddress, e);
				terminateConnection(connection, e, AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR);
				break;
			}
		}
	}

	/**
	 * Process received record.
	 * 
	 * @param record received record.
	 * @param connection connection to process record.
	 */
	@Override
	public void processRecord(Record record, Connection connection) {

		try {
			// ensure, that connection is still related to record 
			// and not changed by processing an other record before 
			if (record.getConnectionId() == null && !connection.equalsPeerAddress(record.getPeerAddress())) {
				long delay = TimeUnit.NANOSECONDS.toMillis(ClockUtil.nanoRealtime() - record.getReceiveNanos());
				DROP_LOGGER.debug("Drop received record {}, connection changed address {} => {}! (shift {}ms)", record.getType(),
						record.getPeerAddress(), connection.getPeerAddress(), delay);
				if (health != null) {
					health.receivingRecord(true);
				}
				return;
			}

			int epoch = record.getEpoch();
			LOGGER.trace("Received DTLS record of type [{}], length: {}, [epoche:{},rseqn:{}]", 
					record.getType(), record.getFragmentLength(), epoch, record.getSequenceNumber());

			Handshaker handshaker = connection.getOngoingHandshake();
			if (handshaker != null && handshaker.isExpired()) {
				// handshake expired during Android / OS "deep sleep"
				// on receiving, fail to remove connection, if session is not established 
				handshaker.handshakeFailed(new Exception("handshake already expired!"));
				if (connectionStore.get(connection.getConnectionId()) != connection) {
					// connection removed, then drop record
					DROP_LOGGER.debug("Discarding {} record [epoch {}, rseqn {}] received from peer [{}], handshake expired!",
							record.getType(), epoch, record.getSequenceNumber(), record.getPeerAddress(), epoch);
					if (health != null) {
						health.receivingRecord(true);
					}
					return;
				}
				handshaker = null;
			}

			DTLSSession session = connection.getSession(epoch);

			if (session == null) {
				if (handshaker != null && handshaker.getSession().getReadEpoch() == 0 && epoch == 1) {
					// future records, apply session after handshake finished.
					handshaker.addRecordsForDeferredProcessing(record);
				} else {
					DROP_LOGGER.debug("Discarding {} record [epoch {}, rseqn {}] received from peer [{}] without an active session",
							record.getType(), epoch, record.getSequenceNumber(), record.getPeerAddress());
					if (health != null) {
						health.receivingRecord(true);
					}
				}
				return;
			}

			// The DTLS 1.2 spec (section 4.1.2.6) advises to do replay detection
			// before MAC validation based on the record's sequence numbers
			// see http://tools.ietf.org/html/rfc6347#section-4.1.2.6
			boolean closed = connection.isClosed();
			boolean discard = (useFilter || closed) && (session != null)
					&& !session.isRecordProcessable(epoch, record.getSequenceNumber(), useExtendedWindowFilter);
			// closed and no session => discard it
			discard |= (closed && session == null);
			if (discard) {
				if (closed) {
					DROP_LOGGER.debug("Discarding {} record [epoch {}, rseqn {}] received from closed peer [{}]", record.getType(),
							epoch, record.getSequenceNumber(), record.getPeerAddress());
				} else {
					DROP_LOGGER.debug("Discarding duplicate {} record [epoch {}, rseqn {}] received from peer [{}]",
							record.getType(), epoch, record.getSequenceNumber(), record.getPeerAddress());
				}
				if (health != null) {
					health.receivingRecord(true);
				}
				return;
			}

			boolean useCid = connectionIdGenerator != null && connectionIdGenerator.useConnectionId();
			if (record.getType() == ContentType.TLS12_CID) {
				// !useCid already dropped in Record.fromByteArray
				if (epoch == 0) {
					DROP_LOGGER.debug("Discarding TLS_CID record received from peer [{}] during handshake",
							record.getPeerAddress());
					if (health != null) {
						health.receivingRecord(true);
					}
					return;
				}
			} else if (epoch > 0 && useCid && connection.expectCid()) {
				DROP_LOGGER.debug("Discarding record received from peer [{}], CID required!", record.getPeerAddress());
				if (health != null) {
					health.receivingRecord(true);
				}
				return;
			}

			if (!record.isDecoded() || record.getType() != ContentType.APPLICATION_DATA) {
				// application data may be deferred again until the session is really established
				record.applySession(session);
			}

			if (handshaker != null && handshaker.isProbing()) {
				// received record, probe successful
				if (connection.hasEstablishedSession()) {
					connectionStore.removeFromEstablishedSessions(connection.getEstablishedSession(), connection);
				}
				connection.resetSession();
				handshaker.resetProbing();
				LOGGER.trace("handshake probe successful {}", connection.getPeerAddress());
			}

			switch (record.getType()) {
			case APPLICATION_DATA:
				processApplicationDataRecord(record, connection);
				break;
			case ALERT:
				processAlertRecord(record, connection, session);
				break;
			case CHANGE_CIPHER_SPEC:
				processChangeCipherSpecRecord(record, connection);
				break;
			case HANDSHAKE:
				processHandshakeRecord(record, connection);
				break;
			default:
				DROP_LOGGER.debug("Discarding record of unsupported type [{}] from peer [{}]",
					record.getType(), record.getPeerAddress());
			}
		} catch (RuntimeException e) {
			if (health != null) {
				health.receivingRecord(true);
			}
			LOGGER.warn("Unexpected error occurred while processing record from peer [{}]",
					record.getPeerAddress(), e);
			terminateConnection(connection, e, AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR);
		} catch (GeneralSecurityException e) {
			DROP_LOGGER.debug("Discarding {} received from peer [{}] caused by {}",
					record.getType(), record.getPeerAddress(), e.getMessage());
			if (health != null) {
				health.receivingRecord(true);
			}
			LOGGER.debug("error occurred while processing record from peer [{}]",
					record.getPeerAddress(), e);
		} catch (HandshakeException e) {
			LOGGER.debug("error occurred while processing record from peer [{}]",
					record.getPeerAddress(), e);
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
	 * @param connection the peer to terminate the handshake with
	 * @param cause the exception that is the cause for terminating the handshake
	 * @param description the reason to indicate in the message sent to the peer before terminating the handshake
	 */
	private void terminateOngoingHandshake(final Connection connection, final HandshakeException cause, final AlertDescription description) {

		Handshaker handshaker = connection.getOngoingHandshake();
		if (handshaker != null) {
			if (LOGGER.isTraceEnabled()) {
				LOGGER.trace("Aborting handshake with peer [{}]:", connection.getPeerAddress(), cause);
			} else if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Aborting handshake with peer [{}]: {}", connection.getPeerAddress(), cause.getMessage());
			}
			handshaker.setFailureCause(cause);
			DTLSSession session = handshaker.getSession();
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, description, connection.getPeerAddress());
			if (!connection.hasEstablishedSession()) {
				terminateConnection(connection, alert, session);
			} else {
				// keep established session intact and only terminate ongoing handshake
				// failure after established (last FINISH), but before completed (first data)
				if (connection.getEstablishedSession() == handshaker.getSession()) {
					AlertMessage causingAlert = cause.getAlert();
					if (causingAlert != null && causingAlert.getDescription() == AlertDescription.CLOSE_NOTIFY) {
						LOGGER.debug("Handshake with [{}] closed after session was established!",
								handshaker.getPeerAddress());
					} else {
						LOGGER.warn("Handshake with [{}] failed after session was established! {}",
								handshaker.getPeerAddress(), causingAlert);
					}
				} else {
					LOGGER.warn("Handshake with [{}] failed, but has an established session!", handshaker.getPeerAddress());
				}
				send(alert, session);
			}
			handshaker.handshakeFailed(cause);
		}
	}

	private void terminateConnection(Connection connection) {
		if (connection != null) {
			// clear session & (pending) handshaker
			connectionStore.remove(connection);
		}
	}

	private void terminateConnection(Connection connection, Throwable cause, AlertLevel level, AlertDescription description) {
		if (connection.hasEstablishedSession()) {
			terminateConnection(
					connection,
					new AlertMessage(level, description, connection.getPeerAddress()),
					connection.getEstablishedSession());
		} else if (connection.hasOngoingHandshake()) {
			terminateConnection(
					connection,
					new AlertMessage(level, description, connection.getPeerAddress()),
					connection.getOngoingHandshake().getSession());
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
	 * @throws IllegalArgumentException if alert is provided, but session not.
	 */
	private void terminateConnection(Connection connection, AlertMessage alert, DTLSSession session) {
		if (alert == null) {
			LOGGER.trace("Terminating connection with peer [{}]", connection.getPeerAddress());
		} else {
			if (session == null) {
				throw new IllegalArgumentException("Session must not be null, if alert message is to be sent");
			}
			LOGGER.trace("Terminating connection with peer [{}], reason [{}]", connection.getPeerAddress(),
					alert.getDescription());
			send(alert, session);
		}
		if (alert != null && alert.getLevel() == AlertLevel.WARNING && alert.getDescription() == AlertDescription.CLOSE_NOTIFY) {
			// request resumption, keep connection and session
			connection.setResumptionRequired(true);
		} else {
			// clear session & (pending) handshaker
			connectionStore.remove(connection);
		}
	}

	/**
	 * Process application data record.
	 * 
	 * @param record application data record
	 * @param connection connection to process the received record
	 */
	private void processApplicationDataRecord(final Record record, final Connection connection) {
		final Handshaker ongoingHandshake = connection.getOngoingHandshake();
		final DTLSSession session = connection.getEstablishedSession();
		if (session != null && !connection.isResumptionRequired()) {
			// APPLICATION_DATA can only be processed within the context of
			// an established, i.e. fully negotiated, session
			ApplicationMessage message = (ApplicationMessage) record.getFragment();
			InetSocketAddress newAddress = record.getPeerAddress();
			if (connectionStore.get(newAddress) == connection) {
				// no address update required!
				newAddress = null;
			}
			// the fragment could be de-crypted, mark it
			if (!session.markRecordAsRead(record.getEpoch(), record.getSequenceNumber())
					&& useCidUpdateAddressOnNewerRecordFilter) {
				// suppress address update!
				newAddress = null;
			}
			if (ongoingHandshake != null) {
				// the handshake has been completed successfully
				ongoingHandshake.handshakeCompleted();
			}
			connection.refreshAutoResumptionTime();
			connectionStore.update(connection, newAddress);

			final RawDataChannel channel = messageHandler;
			// finally, forward de-crypted message to application layer
			if (channel != null) {
				// create application message.
				DtlsEndpointContext context;
				if (session.getPeer() == null) {
					// endpoint context would fail ...
					session.setPeer(record.getPeerAddress());
					context = session.getConnectionWriteContext();
					session.setPeer(null);
					LOGGER.warn("Received APPLICATION_DATA from deprecated {}", record.getPeerAddress());
				} else {
					context = session.getConnectionWriteContext();
				}
				LOGGER.trace("Received APPLICATION_DATA for {}", context);
				RawData receivedApplicationMessage = RawData.inbound(message.getData(), context, false, record.getReceiveNanos());
				channel.receiveData(receivedApplicationMessage);
			}
		} else if (ongoingHandshake != null) {
			// wait for FINISH
			// the record is already decoded, so adding it for deferred processing
			// requires to protect it from applying the session again in processRecord!
			ongoingHandshake.addRecordsForDeferredProcessing(record);
		} else {
			DROP_LOGGER.debug("Discarding APPLICATION_DATA record received from peer [{}]",
					record.getPeerAddress());
		}
	}

	/**
	 * Process alert record.
	 * 
	 * @param record alert record
	 * @param connection connection to process the received record
	 * @param session session applied to decode record
	 */
	private void processAlertRecord(Record record, Connection connection, DTLSSession session) {
		AlertMessage alert = (AlertMessage) record.getFragment();
		Handshaker handshaker = connection.getOngoingHandshake();
		HandshakeException error = null;
		LOGGER.trace("Processing {} ALERT from [{}]: {}",
				alert.getLevel(), alert.getPeer(), alert.getDescription());
		if (AlertDescription.CLOSE_NOTIFY.equals(alert.getDescription())) {
			// according to section 7.2.1 of the TLS 1.2 spec
			// (http://tools.ietf.org/html/rfc5246#section-7.2.1)
			// we need to respond with a CLOSE_NOTIFY alert and
			// then close and remove the connection immediately
			if (connection.hasEstablishedSession()) {
				InetSocketAddress newAddress = record.getPeerAddress();
				if (connectionStore.get(newAddress) == connection) {
					// no address update required!
					newAddress = null;
				}
				// the fragment could be de-crypted, mark it
				if (!session.markRecordAsRead(record.getEpoch(), record.getSequenceNumber())
						&& useCidUpdateAddressOnNewerRecordFilter) {
					// suppress address update!
					newAddress = null;
				}
				if (handshaker != null) {
					handshaker.handshakeCompleted();
				}
				connection.refreshAutoResumptionTime();
				connectionStore.update(connection, newAddress);
			} else {
				error = new HandshakeException("Received 'close notify'", alert);
				if (handshaker != null) {
					handshaker.setFailureCause(error);
				}
			}
			if (!connection.isResumptionRequired()) {
				if (session.getPeer() != null) {
					send(new AlertMessage(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY, alert.getPeer()), session);
				}
				if (connection.hasEstablishedSession()) {
					connection.close(record);
				} else {
					terminateConnection(connection);
				}
			}
		} else if (AlertLevel.FATAL.equals(alert.getLevel())) {
			// according to section 7.2 of the TLS 1.2 spec
			// (http://tools.ietf.org/html/rfc5246#section-7.2)
			// the connection needs to be terminated immediately
			error = new HandshakeException("Received 'fatal alert'", alert);
			if (handshaker != null) {
				handshaker.setFailureCause(error);
			}
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
	}

	/**
	 * Process change cipher spec record.
	 * 
	 * @param record change cipher spec record
	 * @param connection connection to process the received record
	 */
	private void processChangeCipherSpecRecord(Record record, Connection connection) {
		Handshaker ongoingHandshaker = connection.getOngoingHandshake();
		if (ongoingHandshaker != null) {
			// processing a CCS message does not result in any additional flight to be sent
			try {
				ongoingHandshaker.processMessage(record);
			} catch (HandshakeException e) {
				handleExceptionDuringHandshake(e, e.getAlert().getLevel(), e.getAlert().getDescription(), connection, record);
			}
		} else {
			// change cipher spec can only be processed within the
			// context of an existing handshake -> ignore record
			DROP_LOGGER.debug("Received CHANGE_CIPHER_SPEC record from peer [{}] with no handshake going on", record.getPeerAddress());
		}
	}

	/**
	 * Process handshake record.
	 * 
	 * @param record handshake record
	 * @param connection connection to process the record.
	 */
	private void processHandshakeRecord(final Record record, final Connection connection) {
		LOGGER.trace("Received {} record from peer [{}]", record.getType(), record.getPeerAddress());
		try {
			if (record.isNewClientHello()) {
				throw new IllegalArgumentException("new CLIENT_HELLO must be processed by processClientHello!");
			}
			HandshakeMessage handshakeMessage = (HandshakeMessage) record.getFragment();
			switch (handshakeMessage.getMessageType()) {
			case CLIENT_HELLO:
				// We do not support re-negotiation as recommended in :
				// https://tools.ietf.org/html/rfc7925#section-17
				DROP_LOGGER.debug("Reject re-negotiation from peer {}", record.getPeerAddress());
				DTLSSession session = connection.getEstablishedSession();
				send(new AlertMessage(AlertLevel.WARNING, AlertDescription.NO_RENEGOTIATION, record.getPeerAddress()),
						session);
				break;
			case HELLO_REQUEST:
				processHelloRequest(connection);
				break;
			default:
				Handshaker handshaker = connection.getOngoingHandshake();
				if (handshaker != null) {
					handshaker.processMessage(record);
				} else {
					DROP_LOGGER.debug(
							"Discarding HANDSHAKE message [epoch={}] from peer [{}], no ongoing handshake!",
							record.getEpoch(), record.getPeerAddress());
				}
				break;
			}
		} catch (HandshakeException e) {
			handleExceptionDuringHandshake(e, e.getAlert().getLevel(), e.getAlert().getDescription(), connection, record);
		}
	}

	/**
	 * Process HELLO_REQUEST.
	 * 
	 * @param connection connection to process HELLO_REQUEST message.
	 * @throws HandshakeException if the message to initiate the handshake with
	 *             the peer cannot be created
	 */
	private void processHelloRequest(final Connection connection) throws HandshakeException {
		if (connection.hasOngoingHandshake()) {
			// TLS 1.2, Section 7.4 advises to ignore HELLO_REQUEST messages
			// arriving while in an ongoing handshake
			// (http://tools.ietf.org/html/rfc5246#section-7.4)
			DROP_LOGGER.debug("Ignoring HELLO_REQUEST received from [{}] while already in an ongoing handshake with peer",
					connection.getPeerAddress());
		} else {
			// We do not support re-negotiation as recommended in :
			// https://tools.ietf.org/html/rfc7925#section-17
			DTLSSession session = connection.getEstablishedSession();
			send(new AlertMessage(AlertLevel.WARNING, AlertDescription.NO_RENEGOTIATION, connection.getPeerAddress()),
					session);
		}
	}

	/**
	 * Process new CLIENT_HELLO message.
	 * 
	 * Executed outside the serial execution. Checks for either a valid session
	 * id or a valid cookie. If the check is passed successfully, check next, if
	 * a connection for that CLIENT_HELLO already exists using the client random
	 * contained in the CLIENT_HELLO message. If the connection already exists,
	 * take that, otherwise create a new one and pass the execution to the
	 * serial execution of that connection.
	 * 
	 * @param record record of CLIENT_HELLO message
	 */
	private void processNewClientHello(final Record record) {
		InetSocketAddress peerAddress = record.getPeerAddress();
		if (LOGGER.isTraceEnabled()) {
			StringBuilder msg = new StringBuilder("Processing new CLIENT_HELLO from peer [")
					.append(peerAddress).append("]").append(":").append(StringUtil.lineSeparator()).append(record);
			LOGGER.trace(msg.toString());
		}
		try {
			// CLIENT_HELLO with epoch 0 is not encrypted, so use DTLSConnectionState.NULL 
			record.applySession(null);
			final ClientHello clientHello = (ClientHello) record.getFragment();

			// before starting a new handshake or resuming an established
			// session we need to make sure that the peer is in possession of
			// the IP address indicated in the client hello message
			final AvailableConnections connections = new AvailableConnections();
			if (isClientInControlOfSourceIpAddress(clientHello, record, connections)) {
				boolean verify = false;
				Connection connection;
				synchronized (connectionStore) {
					connection = connectionStore.get(peerAddress);
					if (connection != null && !connection.isStartedByClientHello(clientHello)) {
						Connection sessionConnection = connections.getConnectionBySessionId();
						if (sessionConnection != null && sessionConnection != connection) {
							// don't overwrite
							verify = true;
						} else {
							if (sessionConnection != null && sessionConnection == connection) {
								connections.setRemoveConnectionBySessionId(true);
							}
							connection = null;
						}
					}
					if (connection == null) {
						connection = new Connection(peerAddress, new SerialExecutor(getExecutorService()));
						connection.setExecutionListener(connectionExecutionListener);
						connection.startByClientHello(clientHello);
						if (!connectionStore.put(connection)) {
							return;
						}
					}
				}
				if (verify) {
					sendHelloVerify(clientHello, record, null);
				} else {
					connections.setConnectionByAddress(connection);
					try {
						connection.getExecutor().execute(new Runnable() {
							@Override
							public void run() {
								if (running.get()) {
									processClientHello(clientHello, record, connections);
								}
							}
						});
					} catch (RejectedExecutionException e) {
						// dont't terminate connection on shutdown!
						LOGGER.debug("Execution rejected while processing record [type: {}, peer: {}]",
								record.getType(), peerAddress, e);
					} catch (RuntimeException e) {
						LOGGER.warn("Unexpected error occurred while processing record [type: {}, peer: {}]",
								record.getType(), peerAddress, e);
						terminateConnection(connections.getConnectionByAddress(), e, AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR);
					}
				}
			}
		} catch (HandshakeException e) {
			LOGGER.debug("Processing new CLIENT_HELLO from peer [{}] failed!", record.getPeerAddress(), e);
		} catch (GeneralSecurityException e) {
			DROP_LOGGER.debug("Processing new CLIENT_HELLO from peer [{}] failed!", record.getPeerAddress(), e);
		} catch (RuntimeException e) {
			LOGGER.warn("Processing new CLIENT_HELLO from peer [{}] failed!", record.getPeerAddress(), e);
		}
	}

	/**
	 * Process CLIENT_HELLO message.
	 * 
	 * @param clientHello CLIENT_HELLO message
	 * @param record record of CLIENT_HELLO message
	 * @param connections available connections to process handshake message
	 */
	private void processClientHello(ClientHello clientHello, Record record, AvailableConnections connections) {
		if (connections == null) {
			throw new NullPointerException("available connections must not be null!");
		}
		Connection connection = connections.getConnectionByAddress();
		if (connection == null) {
			throw new NullPointerException("connection by address must not be null!");
		} else if (!connection.equalsPeerAddress(record.getPeerAddress())) {
			DROP_LOGGER.info("Drop received CLIENT_HELLO, changed address {} => {}!", record.getPeerAddress(),
					connection.getPeerAddress());
			return;
		}
		if (LOGGER.isTraceEnabled()) {
			StringBuilder msg = new StringBuilder("Processing CLIENT_HELLO from peer [").append(record.getPeerAddress())
					.append("]").append(":").append(StringUtil.lineSeparator()).append(record);
			LOGGER.trace(msg.toString());
		}

		try {
			if (connection.hasEstablishedSession() || connection.getOngoingHandshake() != null) {
				DROP_LOGGER.debug("Discarding received duplicate CLIENT_HELLO message [epoch={}] from peer [{}]!", record.getEpoch(),
						record.getPeerAddress());
			} else if (clientHello.hasSessionId()) {
				// client wants to resume a cached session
				resumeExistingSession(clientHello, record, connections);
			} else {
				// At this point the client has demonstrated reachability by completing a cookie exchange
				// so we terminate the previous connection and start a new handshake
				// (see section 4.2.8 of RFC 6347 (DTLS 1.2))
				startNewHandshake(clientHello, record, connection);
			}
		} catch (HandshakeException e) {
			handleExceptionDuringHandshake(e, e.getAlert().getLevel(), e.getAlert().getDescription(), connection, record);
		}
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
	 * <p>If a matching session id is contained, but no cookie, it depends on the
	 * number of pending resumption handshakes, if a
	 * <em>HELLO_VERIFY_REQUEST</em> is send to the peer, of a resumption
	 * handshake is started without.
	 * </p>
	 * May be Executed outside the serial execution, if the connection is
	 * {@code null}.
	 * 
	 * @param clientHello the peer's client hello method including the cookie to
	 *            verify
	 * @param record the received record
	 * @param connections used to set the
	 *            {@link AvailableConnections#bySessionId} with the result of
	 *            {@link ResumptionSupportingConnectionStore#find(SessionId)}.
	 * @return <code>true</code> if the client hello message contains a cookie
	 *         and the cookie is identical to the cookie expected from the peer
	 *         address, or it contains a matching session id.
	 */
	private boolean isClientInControlOfSourceIpAddress(ClientHello clientHello, Record record, AvailableConnections connections) {
		if (connections == null) {
			throw new NullPointerException("available connections must not be null!");
		}
		// verify client's ability to respond on given IP address
		// by exchanging a cookie as described in section 4.2.1 of the DTLS 1.2 spec
		// see http://tools.ietf.org/html/rfc6347#section-4.2.1
		try {
			byte[] expectedCookie = null;
			byte[] providedCookie = clientHello.getCookie();
			if (providedCookie.length > 0) {
				expectedCookie = cookieGenerator.generateCookie(clientHello);
				// if cookie is present, it must match
				if (MessageDigest.isEqual(expectedCookie, providedCookie)) {
					return true;
				}
				// check, if cookie of the past period matches
				byte[] pastCookie = cookieGenerator.generatePastCookie(clientHello);
				if (pastCookie != null && MessageDigest.isEqual(pastCookie, providedCookie)) {
					return true;
				}
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("provided cookie must {} match {}. Send verify request to {}",
							StringUtil.byteArray2HexString(providedCookie, StringUtil.NO_SEPARATOR, 6),
							StringUtil.byteArray2HexString(expectedCookie, StringUtil.NO_SEPARATOR, 6),
							record.getPeerAddress());
				}
				// otherwise send verify request
			} else {
				// threshold 0 always use a verify request
				if (0 < thresholdHandshakesWithoutVerifiedPeer) {
					int pending = pendingHandshakesWithoutVerifiedPeer.get();
					LOGGER.trace("pending fast resumptions [{}], threshold [{}]", pending,
							thresholdHandshakesWithoutVerifiedPeer);
					if (pending < thresholdHandshakesWithoutVerifiedPeer) {
						// use short resumption (without verify request)
						// only, if the number of the pending short
						// resumption handshakes is below the threshold
						Connection sessionConnection = connectionStore.find(clientHello.getSessionId());
						connections.setConnectionBySessionId(sessionConnection);
						if (sessionConnection != null) {
							// found provided session.
							return true;
						}
					}
				}
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
	 * Start a new handshake.
	 * 
	 * @param clientHello CLIENT_HELLO message.
	 * @param record record containing the CLIENT_HELLO message.
	 * @param connection connection to start handshake.
	 * @throws HandshakeException if the parameters provided in the client hello message
	 *           cannot be used to start a handshake with the peer
	 */
	private void startNewHandshake(final ClientHello clientHello, final Record record, final Connection connection) throws HandshakeException {
		// use the record sequence number from CLIENT_HELLO as initial sequence number
		// for records sent to the client (see section 4.2.1 of RFC 6347 (DTLS 1.2))
		DTLSSession newSession = new DTLSSession(record.getPeerAddress(), record.getSequenceNumber());
		// initialize handshaker based on CLIENT_HELLO (this accounts
		// for the case that multiple cookie exchanges have taken place)
		Handshaker handshaker = new ServerHandshaker(clientHello.getMessageSeq(), newSession, this, timer, connection, config);
		initializeHandshaker(handshaker);
		handshaker.processMessage(record);
	}

	/**
	 * Resume existing session.
	 * 
	 * @param clientHello CLIENT_HELLO message.
	 * @param record record containing the CLIENT_HELLO message.
	 * @param connections available connections to resume
	 * @throws HandshakeException if the session cannot be resumed based on the parameters
	 *             provided in the client hello message
	 */
	private void resumeExistingSession(ClientHello clientHello, Record record, final AvailableConnections connections)
			throws HandshakeException {
		InetSocketAddress peerAddress = record.getPeerAddress();
		LOGGER.trace("Client [{}] wants to resume session with ID [{}]", peerAddress, clientHello.getSessionId());

		if (connections == null) {
			throw new NullPointerException("available connections must not be null!");
		}
		Connection connection = connections.getConnectionByAddress();
		if (connection == null) {
			throw new NullPointerException("connection by address must not be null!");
		} else if (!connection.equalsPeerAddress(peerAddress)) {
			throw new IllegalArgumentException("connection must have records address!");
		}

		SessionTicket ticket = null;
		if (!connections.isConnectionBySessionIdKnown()) {
			connections.setConnectionBySessionId(connectionStore.find(clientHello.getSessionId()));
		}
		Connection previousConnection = connections.getConnectionBySessionId();
		if (previousConnection != null && previousConnection.isActive()) {
			if (previousConnection.hasEstablishedSession()) {
				ticket = previousConnection.getEstablishedSession().getSessionTicket();
			} else {
				ticket = previousConnection.getSessionTicket();
			}
			boolean ok = true;
			if (ticket != null && config.isSniEnabled()) {
				ServerNames serverNames1 = ticket.getServerNames();
				ServerNames serverNames2 = null;
				ServerNameExtension extension = clientHello.getServerNameExtension();
				if (extension != null) {
					serverNames2 = extension.getServerNames();
				}
				if (serverNames1 != null) {
					ok = serverNames1.equals(serverNames2);
				} else if (serverNames2 != null) {
					// invalidate ticket, server names mismatch
					ok = false;
				}
			}
			if (!ok && ticket != null) {
				SecretUtil.destroy(ticket);
				ticket = null;
			}
		}
		if (ticket != null) {
			// session has been found in cache, resume it
			final DTLSSession sessionToResume = new DTLSSession(clientHello.getSessionId(), peerAddress, ticket,
					record.getSequenceNumber());
			final Handshaker handshaker = new ResumingServerHandshaker(clientHello.getMessageSeq(), sessionToResume,
					this, timer, connection, config);
			initializeHandshaker(handshaker);
			SecretUtil.destroy(ticket);

			if (previousConnection.hasEstablishedSession()) {
				// client wants to resume a session that has been negotiated by this node
				// make sure that the same client only has a single active connection to this server
				if (connections.isRemoveConnectionBySessionId()) {
					// immediately remove previous connection
					connectionStore.remove(previousConnection, false);
				} else if (clientHello.getCookie().length == 0) {
					// short resumption without verify request
					pendingHandshakesWithoutVerifiedPeer.incrementAndGet();
					handshaker.addSessionListener(new SessionAdapter() {

						@Override
						public void sessionEstablished(final Handshaker currentHandshaker,
								final DTLSSession establishedSession) throws HandshakeException {
							pendingHandshakesWithoutVerifiedPeer.decrementAndGet();
						}

						@Override
						public void handshakeFailed(Handshaker handshaker, Throwable error) {
							pendingHandshakesWithoutVerifiedPeer.decrementAndGet();
						}

					});
				}
			}

			// process message
			handshaker.processMessage(record);
		} else {
			LOGGER.trace(
					"Client [{}] tries to resume non-existing session [ID={}], performing full handshake instead ...",
					peerAddress, clientHello.getSessionId());
			startNewHandshake(clientHello, record, connection);
		}
	}

	private void sendHelloVerify(ClientHello clientHello, Record record, byte[] expectedCookie) throws GeneralSecurityException {
		// send CLIENT_HELLO_VERIFY with cookie in order to prevent
		// DOS attack as described in DTLS 1.2 spec
		LOGGER.trace("Verifying client IP address [{}] using HELLO_VERIFY_REQUEST", record.getPeerAddress());
		if (expectedCookie == null) {
			expectedCookie = cookieGenerator.generateCookie(clientHello);
		}
		HelloVerifyRequest msg = new HelloVerifyRequest(ProtocolVersion.VERSION_DTLS_1_2, expectedCookie, record.getPeerAddress());
		// because we do not have a handshaker in place yet that
		// manages message_seq numbers, we need to set it explicitly
		// use message_seq from CLIENT_HELLO in order to allow for
		// multiple consecutive cookie exchanges with a client
		msg.setMessageSeq(clientHello.getMessageSeq());
		// use epoch 0 and sequence no from CLIENT_HELLO record as
		// mandated by section 4.2.1 of the DTLS 1.2 spec
		// see http://tools.ietf.org/html/rfc6347#section-4.2.1
		Record helloVerify = new Record(ContentType.HANDSHAKE, record.getSequenceNumber(), msg, record.getPeerAddress());
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
				boolean useCid = session.getWriteEpoch() > 0;
				LOGGER.trace("send ALERT {} for peer {}.", alert, session.getPeer());
				sendRecord(new Record(ContentType.ALERT, session.getWriteEpoch(), session.getSequenceNumber(), alert,
						session, useCid, TLS12_CID_PADDING));
			} catch (IOException e) {
				// already logged ...
			} catch (GeneralSecurityException e) {
				DROP_LOGGER.warn("Cannot create ALERT message for peer [{}]", session.getPeer(), e);
			}
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public final void send(final RawData message) {
		if (message == null) {
			throw new NullPointerException("Message must not be null");
		}
		if (health != null) {
			health.sendingRecord(false);
		}
		if (message.isMulticast()) {
			DROP_LOGGER.warn("DTLSConnector drops {} outgoing bytes to multicast {}:{}", message.getSize(), message.getAddress(), message.getPort());
			message.onError(new MulticastNotSupportedException("DTLS doesn't support multicast!"));
			if (health != null) {
				health.sendingRecord(true);
			}
			return;
		}
		final Connection connection;
		RuntimeException error = null;

		if (!running.get()) {
			connection = null;
			error = new IllegalStateException("connector must be started before sending messages is possible");
		} else if (message.getSize() > MAX_PLAINTEXT_FRAGMENT_LENGTH) {
			connection = null;
			error = new IllegalArgumentException(
					"Message data must not exceed " + MAX_PLAINTEXT_FRAGMENT_LENGTH + " bytes");
		} else {
			boolean create = !serverOnly;
			if (create) {
				create = !getEffectiveHandshakeMode(message).equals(DtlsEndpointContext.HANDSHAKE_MODE_NONE);
			}
			connection = getConnection(message.getInetSocketAddress(), null, create);
			if (connection == null) {
				if (create) {
					error = new IllegalStateException("connection store is exhausted!");
				} else {
					if (serverOnly) {
						message.onError(new EndpointUnconnectedException("server only, connection missing!"));
					} else {
						message.onError(new EndpointUnconnectedException("connection missing!"));
					}
					DROP_LOGGER.debug("DTLSConnector drops {} outgoing bytes to {}:{}, connection missing!", message.getSize(), message.getAddress(), message.getPort());
					if (health != null) {
						health.sendingRecord(true);
					}
					return;
				}
			}
		}
		if (error != null) {
			DROP_LOGGER.debug("DTLSConnector drops {} outgoing bytes to {}:{}, {}!", message.getSize(),
					message.getAddress(), message.getPort(), error.getMessage());
			message.onError(error);
			if (health != null) {
				health.sendingRecord(true);
			}
			throw error;
		}

		final long now =ClockUtil.nanoRealtime();
		if (pendingOutboundMessagesCountdown.decrementAndGet() >= 0) {
			try {
				SerialExecutor executor = connection.getExecutor();
				if (executor == null) {
					throw new NullPointerException("missing executor for connection! " + connection.getPeerAddress());
				}
				executor.execute(new Runnable() {

					@Override
					public void run() {
						try {
							if (running.get()) {
								sendMessage(now, message, connection);
							} else {
								DROP_LOGGER.trace("DTLSConnector drops {} outgoing bytes to {}:{}, connector not running!", message.getSize(), message.getAddress(), message.getPort());
								message.onError(new InterruptedIOException("Connector is not running."));
								if (health != null) {
									health.sendingRecord(true);
								}
							}
						} catch (Exception e) {
							if (running.get()) {
								LOGGER.warn("Exception thrown by executor thread [{}]",
										Thread.currentThread().getName(), e);
							}
							DROP_LOGGER.trace("DTLSConnector drops {} outgoing bytes to {}:{}, {}", message.getSize(), message.getAddress(), message.getPort(), e.getMessage());
							if (health != null) {
								health.sendingRecord(true);
							}
							message.onError(e);
						} finally {
							pendingOutboundMessagesCountdown.incrementAndGet();
						}
					}
				});
			} catch (RejectedExecutionException e) {
				LOGGER.debug("Execution rejected while sending application record [peer: {}]",
						message.getInetSocketAddress(), e);
				DROP_LOGGER.trace("DTLSConnector drops {} outgoing bytes to {}:{}, {}", message.getSize(), message.getAddress(), message.getPort(), e.getMessage());
				message.onError(new InterruptedIOException("Connector is not running."));
				if (health != null) {
					health.sendingRecord(true);
				}
			}
		} else {
			pendingOutboundMessagesCountdown.incrementAndGet();
			DROP_LOGGER.warn("Outbound message overflow! Dropping outbound message to peer [{}]",
					message.getInetSocketAddress());
			message.onError(new IllegalStateException("Outbound message overflow!"));
			if (health != null) {
				health.sendingRecord(true);
			}
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
	 * @param nanos system nanoseconds of receiving the data
	 * @param message the data to send to the peer
	 * @param connection connection of the peer
	 * @throws HandshakeException if starting the handshake fails
	 */
	private void sendMessage(final long nanos, final RawData message, final Connection connection) throws HandshakeException {

		if (connection.getPeerAddress() == null) {
			long delay = TimeUnit.NANOSECONDS.toMillis(ClockUtil.nanoRealtime() - nanos);
			DROP_LOGGER.info("Drop outgoing record with {} bytes, connection lost address {}! (shift {}ms)", message.getSize(),
					message.getInetSocketAddress(), delay);
			message.onError(new EndpointUnconnectedException("connection not longer assigned to address!"));
			if (health != null) {
				health.sendingRecord(true);
			}
			return;
		}
		LOGGER.trace("Sending application layer message to [{}]", message.getEndpointContext());

		Handshaker handshaker = connection.getOngoingHandshake();
		if (handshaker != null && !handshaker.hasSessionEstablished()) {
			if (handshaker.isExpired()) {
				// handshake expired during Android / OS "deep sleep"
				// on sending, abort, keep connection for new handshake
				handshaker.handshakeAborted(new Exception("handshake already expired!"));
			} else if (handshaker.isProbing()) {
				if (checkOutboundEndpointContext(message, null)) {
					message.onConnecting();
					handshaker.addApplicationDataForDeferredProcessing(message);
				}
				return;
			}
		}

		if (connection.isActive() && !connection.isClosed()) {
			sendMessageWithSession(message, connection);
		} else {
			sendMessageWithoutSession(message, connection);
		}
	}

	/**
	 * Send message without session.
	 * 
	 * Starts handshake, if not already pending, and queue message.
	 * 
	 * @param message message to send after handshake completes
	 * @param connection connection to send message
	 * @throws HandshakeException If exception occurred starting the handshake
	 * @since 2.1
	 */
	private void sendMessageWithoutSession(final RawData message, final Connection connection)
			throws HandshakeException {

		if (!checkOutboundEndpointContext(message, null)) {
			return;
		}
		Handshaker handshaker = connection.getOngoingHandshake();
		if (handshaker == null) {
			if (serverOnly) {
				DROP_LOGGER.trace("DTLSConnector drops {} outgoing bytes to {}:{}, server only, connection missing!", message.getSize(), message.getAddress(), message.getPort());
				message.onError(new EndpointUnconnectedException("server only, connection missing!"));
				if (health != null) {
					health.sendingRecord(true);
				}
				return;
			}
			boolean none = getEffectiveHandshakeMode(message).contentEquals(DtlsEndpointContext.HANDSHAKE_MODE_NONE);
			if (none) {
				DROP_LOGGER.trace("DTLSConnector drops {} outgoing bytes to {}:{}, connection missing!", message.getSize(), message.getAddress(), message.getPort());
				message.onError(new EndpointUnconnectedException("connection missing!"));
				if (health != null) {
					health.sendingRecord(true);
				}
				return;
			}
			DTLSSession session = new DTLSSession(message.getInetSocketAddress());
			session.setHostName(message.getEndpointContext().getVirtualHost());
			// no session with peer established nor handshaker started yet,
			// create new empty session & start handshake
			handshaker = new ClientHandshaker(session, this, timer, connection, config, false);
			initializeHandshaker(handshaker);
			message.onConnecting();
			handshaker.addApplicationDataForDeferredProcessing(message);
			handshaker.startHandshake(); // may fail with IOException!
		} else {
			message.onConnecting();
			handshaker.addApplicationDataForDeferredProcessing(message);
		}
	}

	/**
	 * Send message with session.
	 * 
	 * Starts handshake, if requested by resumption or {@link DtlsEndpointContext#KEY_HANDSHAKE_MODE}.
	 * 
	 * @param message message to send
	 * @param connection connection to send message
	 * @throws HandshakeException If exception occurred starting the handshake
	 * @since 2.1
	 */
	private void sendMessageWithSession(final RawData message, final Connection connection) throws HandshakeException {

		DTLSSession session = connection.getEstablishedSession();
		boolean markedAsClosed = session != null && session.isMarkedAsClosed();
		String handshakeMode = getEffectiveHandshakeMode(message);
		boolean none = DtlsEndpointContext.HANDSHAKE_MODE_NONE.equals(handshakeMode);
		if (none) {
			if (markedAsClosed || connection.isResumptionRequired()) {
				DROP_LOGGER.trace("DTLSConnector drops {} outgoing bytes to {}:{}, resumption required!", message.getSize(), message.getAddress(), message.getPort());
				message.onError(new EndpointUnconnectedException("resumption required!"));
				if (health != null) {
					health.sendingRecord(true);
				}
				return;
			}
		} else {
			boolean probing = DtlsEndpointContext.HANDSHAKE_MODE_PROBE.equals(handshakeMode);
			boolean full = DtlsEndpointContext.HANDSHAKE_MODE_FORCE_FULL.equals(handshakeMode);
			boolean force = probing || full || DtlsEndpointContext.HANDSHAKE_MODE_FORCE.equals(handshakeMode);
			if (force || markedAsClosed || connection.isAutoResumptionRequired(getAutResumptionTimeout(message))) {
				// create the session to resume from the previous one.
				if (serverOnly) {
					DROP_LOGGER.trace("DTLSConnector drops {} outgoing bytes to {}:{}, server only, resumption requested failed!", message.getSize(), message.getAddress(), message.getPort());
					message.onError(new EndpointUnconnectedException("server only, resumption requested failed!"));
					if (health != null) {
						health.sendingRecord(true);
					}
					return;
				}
				message.onConnecting();
				Handshaker previousHandshaker = connection.getOngoingHandshake();
				SessionTicket ticket = null;
				SessionId sessionId = null;
				if (!full) {
					if (session != null) {
						sessionId = session.getSessionIdentifier();
					} else {
						sessionId = connection.getSessionIdentity();
					}
					full = sessionId.isEmpty();
					if (!full) {
						if (session != null) {
							try {
								ticket = session.getSessionTicket();
							} catch (IllegalStateException ex) {
								LOGGER.debug("Not possible to resume incomplete session!");
							}
						} else {
							ticket = connection.getSessionTicket();
						}
					}
				}
				if (session != null) {
					if (!probing) {
						connectionStore.removeFromEstablishedSessions(session, connection);
					}
				} else {
					probing = false;
				}
				if (probing) {
					// Only reset the resumption trigger, but keep the session for now
					// the session will be reseted with the first received data
					connection.setResumptionRequired(false);
				} else {
					connection.resetSession();
				}
				Handshaker newHandshaker;
				if (ticket == null) {
					// server may use a empty session id to indicate,
					// that resumption is not supported
					// https://tools.ietf.org/html/rfc5246#section-7.4.1.3
					DTLSSession newSession = new DTLSSession(message.getInetSocketAddress());
					newSession.setHostName(message.getEndpointContext().getVirtualHost());
					newHandshaker = new ClientHandshaker(newSession, this, timer, connection, config, probing);
				} else {
					DTLSSession resumableSession = new DTLSSession(sessionId, message.getInetSocketAddress(), ticket, 0);
					SecretUtil.destroy(ticket);
					resumableSession.setHostName(message.getEndpointContext().getVirtualHost());
					newHandshaker = new ResumingClientHandshaker(resumableSession, this, timer, connection, config, probing);
				}
				initializeHandshaker(newHandshaker);
				if (previousHandshaker != null) {
					newHandshaker.takeDeferredApplicationData(previousHandshaker);
					// abort, keep connection
					previousHandshaker.handshakeAborted(new Exception("handshake replaced!"));
				}
				newHandshaker.addApplicationDataForDeferredProcessing(message);
				newHandshaker.startHandshake();
				return;
			}
		}
		// session with peer has already been established,
		// use it to send encrypted message
		sendMessage(message, connection, session);
	}

	private void sendMessage(final RawData message, final Connection connection, final DTLSSession session) {
		try {
			LOGGER.trace("send {}-{} using {}-{}", connection.getConnectionId(), connection.getPeerAddress(),
					session.getSessionIdentifier(), session.getPeer());
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
					session, true, TLS12_CID_PADDING);
			sendRecord(record);
			message.onSent();
			connection.refreshAutoResumptionTime();
		} catch (IOException e) {
			message.onError(e);
		} catch (GeneralSecurityException e) {
			DROP_LOGGER.warn("Cannot send APPLICATION record to peer [{}]", message.getInetSocketAddress(), e);
			message.onError(e);
		}
	}

	/**
	 * Check, if the endpoint context match for outgoing messages using
	 * {@link #endpointContextMatcher}.
	 * 
	 * @param message message to be checked
	 * @param connectionContext endpoint context of the connection. May be
	 *            {@code null}, if not established.
	 * @return {@code true}, if outgoing message matches, {@code false}, if not
	 *         and should NOT be send.
	 * @see EndpointContextMatcher#isToBeSent(EndpointContext, EndpointContext)
	 */
	private boolean checkOutboundEndpointContext(final RawData message, final EndpointContext connectionContext) {
		final EndpointContextMatcher endpointMatcher = getEndpointContextMatcher();
		if (null != endpointMatcher && !endpointMatcher.isToBeSent(message.getEndpointContext(), connectionContext)) {
			if (DROP_LOGGER.isInfoEnabled()) {
				DROP_LOGGER.info("DTLSConnector ({}) drops {} bytes outgoing, {} != {}", this, message.getSize(),
						endpointMatcher.toRelevantState(message.getEndpointContext()),
						endpointMatcher.toRelevantState(connectionContext));
			}
			message.onError(new EndpointMismatchException());
			if (health != null) {
				health.sendingRecord(true);
			}
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

	@Override
	public void dropReceivedRecord(Record record) {
		DROP_LOGGER.debug("Discarding {} record [epoch {}, rseqn {}] dropped by handshaker for peer [{}]", record.getType(),
				record.getEpoch(), record.getSequenceNumber(), record.getPeerAddress());
		if (health != null) {
			health.receivingRecord(true);
		}
	}

	@Override
	public int getMaxDatagramSize(boolean ipv6) {
		int headerSize = ipv6 ? IPV6_HEADER_LENGTH : IPV4_HEADER_LENGTH;
		int mtu = maximumTransmissionUnit != null ? maximumTransmissionUnit : (ipv6 ? ipv6Mtu : ipv4Mtu);
		int size = mtu - headerSize;
		if (size < 64) {
			throw new IllegalStateException(
					String.format("%s, datagram size %d, mtu %d", ipv6 ? "IPV6" : "IPv4", size, mtu));
		}
		return mtu - headerSize;
	}

	@NoPublicAPI
	@Override
	public void sendFlight(List<DatagramPacket> datagrams) throws IOException {
		// send it over the UDP socket
		for (DatagramPacket datagramPacket : datagrams) {
			if (health != null) {
				health.sendingRecord(false);
			}
			sendNextDatagramOverNetwork(datagramPacket);
		}
	}

	protected void sendRecord(Record record) throws IOException {
		if (health != null && record.getType() != ContentType.APPLICATION_DATA) {
			health.sendingRecord(false);
		}
		byte[] recordBytes = record.toByteArray();
		DatagramPacket datagram = new DatagramPacket(recordBytes, recordBytes.length, record.getPeerAddress());
		sendNextDatagramOverNetwork(datagram);
	}

	protected void sendNextDatagramOverNetwork(final DatagramPacket datagramPacket) throws IOException {
		DatagramSocket socket = getSocket();
		if (socket != null && !socket.isClosed()) {
			try {
				socket.send(datagramPacket);
				return;
			} catch (PortUnreachableException e) {
				if (!socket.isClosed()) {
					LOGGER.warn("Could not send record, destination {} unreachable!",
							StringUtil.toString((InetSocketAddress) datagramPacket.getSocketAddress()));
				}
			} catch (IOException e) {
				if (!socket.isClosed()) {
					LOGGER.warn("Could not send record", e);
					throw e;
				}
			}
		}
		InetSocketAddress address = lastBindAddress;
		if (address == null) {
			address = config.getAddress();
		}
		DROP_LOGGER.debug("Socket [{}] is closed, discarding packet ...", address);
		throw new IOException("Socket closed.");
	}

	/**
	 * Process psk secret result.
	 * 
	 * @param secretResult asynchronous psk secret result
	 * @since 2.3
	 */
	private void processAsyncPskSecretResult(final PskSecretResult secretResult) {
		final Connection connection = connectionStore.get(secretResult.getConnectionId());
		if (connection != null && connection.hasOngoingHandshake()) {
			SerialExecutor serialExecutor = connection.getExecutor();

			try {

				serialExecutor.execute(new Runnable() {

					@Override
					public void run() {
						if (running.get()) {
							Handshaker handshaker = connection.getOngoingHandshake();
							if (handshaker != null) {
								try {
									handshaker.processAsyncPskSecretResult(secretResult);
								} catch (HandshakeException e) {
									handleExceptionDuringHandshake(e, e.getAlert().getLevel(), e.getAlert().getDescription(), connection, null);
								} catch (IllegalStateException e) {
									LOGGER.warn("Exception while processing psk secret result [{}]", connection, e);
								}
							} else {
								LOGGER.debug("No ongoing handshake for psk secret result [{}]", connection);
							}
						} else {
							LOGGER.debug("Execution stopped while processing psk secret result [{}]", connection);
						}
					}
				});
			} catch (RejectedExecutionException e) {
				// dont't terminate connection on shutdown!
				LOGGER.debug("Execution rejected while processing master secret result [{}]", connection, e);
			} catch (RuntimeException e) {
				LOGGER.warn("Unexpected error occurred while processing master secret result [{}]", connection, e);
			}
		} else {
			LOGGER.debug("No connection or ongoing handshake for master secret result [{}]", connection);
		}
	}

	/**
	 * Get auto resumption timeout.
	 * 
	 * Check, if {@link DtlsEndpointContext#KEY_RESUMPTION_TIMEOUT} is provided,
	 * or use {@link #autoResumptionTimeoutMillis} as default.
	 * 
	 * @param message message to check for auto resumption timeout.
	 * @return resulting timeout in milliseconds. {@code null} for no auto
	 *         resumption.
	 * @since 2.1
	 */
	private Long getAutResumptionTimeout(RawData message) {
		Long timeout = autoResumptionTimeoutMillis;
		String contextTimeout = message.getEndpointContext().get(DtlsEndpointContext.KEY_RESUMPTION_TIMEOUT);
		if (contextTimeout != null) {
			if (contextTimeout.isEmpty()) {
				timeout = null;
			} else {
				try {
					timeout = Long.valueOf(contextTimeout);
				} catch (NumberFormatException e) {
				}
			}
		}
		return timeout;
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
	 * @deprecated use {@link #getMaxDatagramSize(boolean)} instead
	 */
	@Deprecated
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
	 *                     - IP header length (20 bytes IPv4, 120 IPv6)
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
		if (con != null && con.hasEstablishedSession()) {
			return con.getEstablishedSession().getMaxFragmentLength();
		} else {
			return getMaxDatagramSize(peer.getAddress() instanceof Inet6Address) - DTLSSession.DTLS_HEADER_LENGTH;
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
		int localPort = socket == null ? -1 : socket.getLocalPort();
		if (localPort < 0) {
			return config.getAddress();
		} else {
			return new InetSocketAddress(socket.getLocalAddress(), localPort);
		}
	}

	/**
	 * Checks if this connector is running.
	 * 
	 * @return {@code true} if running.
	 */
	@Override
	public final boolean isRunning() {
		return running.get();
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
					} catch (InterruptedIOException e) {
						if (running.get()) {
							LOGGER.info("Worker thread [{}] has been interrupted", getName());
						}
					} catch (InterruptedException e) {
						if (running.get()) {
							LOGGER.info("Worker thread [{}] has been interrupted", getName());
						}
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

	/**
	 * Future implementation for tasks passed in to the serial executors for each
	 * connection.
	 */
	private static class ForEachFuture implements Future<Void> {

		private final Lock lock = new ReentrantLock();
		private final Condition waitDone = lock.newCondition();
		private volatile boolean cancel;
		private volatile boolean done;
		private volatile Exception exception;

		/**
		 * {@inheritDoc}
		 * 
		 * Cancel iteration for each connection.
		 * 
		 * Note: if a connection serial execution busy executing a different
		 * blocking task, cancel will not interrupt that task!
		 */
		@Override
		public boolean cancel(boolean mayInterruptIfRunning) {
			boolean cancelled = false;
			lock.lock();
			try {
				if (!done && !cancel) {
					cancelled = true;
					cancel = true;
				}
			} finally {
				lock.unlock();
			}
			return cancelled;
		}

		@Override
		public boolean isCancelled() {
			return cancel;
		}

		@Override
		public boolean isDone() {
			return done;
		}

		@Override
		public Void get() throws InterruptedException, ExecutionException {
			lock.lock();
			try {
				if (!done) {
					waitDone.await();
				}
				if (exception != null) {
					throw new ExecutionException(exception);
				}
			} finally {
				lock.unlock();
			}
			return null;
		}

		@Override
		public Void get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
			lock.lock();
			try {
				if (!done) {
					waitDone.await(timeout, unit);
				}
				if (exception != null) {
					throw new ExecutionException(exception);
				}
			} finally {
				lock.unlock();
			}
			return null;
		}

		/**
		 * Signals, that the task has completed.
		 */
		public void done() {
			lock.lock();
			try {
				done = true;
				waitDone.signalAll();
			} finally {
				lock.unlock();
			}
		}

		public void failed(Exception exception) {
			lock.lock();
			try {
				this.exception = exception;
				done = true;
				waitDone.signalAll();
			} finally {
				lock.unlock();
			}
		}

		public boolean isStopped() {
			return done || cancel;
		}
	}

	@Override
	public void setRawDataReceiver(final RawDataChannel messageHandler) {
		if (isRunning()) {
			throw new IllegalStateException("message handler cannot be set on running connector");
		}
		this.messageHandler = messageHandler;
	}

	@Override
	public void setEndpointContextMatcher(EndpointContextMatcher endpointContextMatcher) {
		this.endpointContextMatcher = endpointContextMatcher;
	}

	private EndpointContextMatcher getEndpointContextMatcher() {
		return endpointContextMatcher;
	}

	/**
	 * Get effective handshake mode.
	 * 
	 * Either the handshake mode provided in the message's endpoint-context, see
	 * {@link DtlsEndpointContext#KEY_HANDSHAKE_MODE}, or, if that is not
	 * available, the default from the configuration
	 * {@link DtlsConnectorConfig#getDefaultHandshakeMode()}.
	 * 
	 * @param message message to be sent
	 * @return effective handshake mode.
	 * @since 2.1
	 */
	private String getEffectiveHandshakeMode(RawData message) {
		String mode = message.getEndpointContext().get(DtlsEndpointContext.KEY_HANDSHAKE_MODE);
		if (mode == null) {
			mode = defaultHandshakeMode;
		}
		return mode;
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

	/**
	 * Handle a exception occurring during the handshake.
	 * 
	 * @param cause exception
	 * @param level alert level
	 * @param description alert description
	 * @param connection connection
	 * @param record related received record. Since 2.3, this may be
	 *            {@code null} in order to support exception during processing
	 *            of a asynchronous master secret result.
	 */
	private void handleExceptionDuringHandshake(HandshakeException cause, AlertLevel level, AlertDescription description, Connection connection, Record record) {
		// discard none fatal alert exception
		if (!AlertLevel.FATAL.equals(level)) {
			if (record != null) {
				discardRecord(record, cause);
			}
			return;
		}

		// "Unknown identity" and "bad PSK" should be both handled in a same way.
		// Generally "bad PSK" means invalid MAC on FINISHED message.
		// In production both should be silently ignored : https://bugs.eclipse.org/bugs/show_bug.cgi?id=533258
		if (AlertDescription.UNKNOWN_PSK_IDENTITY == description) {
			if (record != null) {
				discardRecord(record, cause);
			}
			return;
		}

		// in other cases terminate handshake
		terminateOngoingHandshake(connection, cause, description);
	}

	private void discardRecord(final Record record, final Throwable cause) {
		if (health != null) {
			health.receivingRecord(true);
		}
		byte[] bytes = record.getFragmentBytes();
		if (DROP_LOGGER.isTraceEnabled()) {
			String hexString = StringUtil.byteArray2HexString(bytes, StringUtil.NO_SEPARATOR, 64);
			DROP_LOGGER.trace("Discarding received {} record (epoch {}, payload: {}) from peer [{}]: ", record.getType(),
					record.getEpoch(), hexString, record.getPeerAddress(), cause);
		} else if (DROP_LOGGER.isDebugEnabled()) {
			String hexString = StringUtil.byteArray2HexString(bytes, StringUtil.NO_SEPARATOR, 16);
			DROP_LOGGER.debug("Discarding received {} record (epoch {}, payload: {}) from peer [{}]: {}", record.getType(),
					record.getEpoch(), hexString, record.getPeerAddress(), cause.getMessage());
		}
	}

	@Override
	public String getProtocol() {
		return "DTLS";
	}

	@Override
	public String toString() {
		return getProtocol() + "-" + StringUtil.toString(getAddress());
	}
	
}
