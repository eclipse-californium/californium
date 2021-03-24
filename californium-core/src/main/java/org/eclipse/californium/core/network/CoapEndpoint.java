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
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - logging
 *    Kai Hudalla (Bosch Software Innovations GmbH) - include client identity in Requests
 *                                                    (465073)
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use static reference to Serializer
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use Logger's message formatting instead of
 *                                                    explicit String concatenation
 *    Bosch Software Innovations GmbH - use correlation context to improve matching
 *                                      of Response(s) to Request (fix GitHub issue #1)
 *    Bosch Software Innovations GmbH - adapt message parsing error handling
 *    Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 *    Bosch Software Innovations GmbH - adjust request scheme for TCP
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce CorrelationContextMatcher
 *                                                    (fix GitHub issue #104)
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CorrelationContext when
 *                                                     sending a message
 *                                                    (fix GitHub issue #104)
 *    Achim Kraus (Bosch Software Innovations GmbH) - use exchange.calculateRTT
 *    Achim Kraus (Bosch Software Innovations GmbH) - make exchangeStore in
 *                                                    BaseMatcher final
 *    Achim Kraus (Bosch Software Innovations GmbH) - use new MessageCallback functions
 *                                                    issue #305
 *    Achim Kraus (Bosch Software Innovations GmbH) - call Message.setReadyToSend() to fix
 *                                                    rare race condition in block1wise
 *                                                    when the generated token was copied
 *                                                    too late (after sending). 
 *    Achim Kraus (Bosch Software Innovations GmbH) - call Exchange.setComplete() for all
 *                                                    canceled messages
 *    Achim Kraus (Bosch Software Innovations GmbH) - use EndpointContext
 *    Achim Kraus (Bosch Software Innovations GmbH) - use connectors protocol
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - add Builder and deprecate 
 *                                                    constructors
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 *    Achim Kraus (Bosch Software Innovations GmbH) - add token generator
 *    Achim Kraus (Bosch Software Innovations GmbH) - workaround for open jdk URI bug
 *    Achim Kraus (Bosch Software Innovations GmbH) - add striped execution
 *                                                    based on exchange
 *    Achim Kraus (Bosch Software Innovations GmbH) - add coap-stack-factory
 *    Achim Kraus (Bosch Software Innovations GmbH) - use checkMID to support
 *                                                    rejection of previous notifications
 *    Achim Kraus (Bosch Software Innovations GmbH) - reject messages with MID only
 *                                                    (therefore tcp messages are not rejected)
 *    Achim Kraus (Bosch Software Innovations GmbH) - setup retransmitResponse for notifies
 *    Achim Kraus (Bosch Software Innovations GmbH) - forward onConnecting and onDtlsRetransmission
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace striped executor
 *                                                    with serial executor
 *    Achim Kraus (Bosch Software Innovations GmbH) - use executors util and only
 *                                                    report errors, when a different
 *                                                    executor is set after the endpoint
 *                                                    was started.
 *    Achim Kraus (Bosch Software Innovations GmbH) - cancel pending messages on stop().
 *    Achim Kraus (Bosch Software Innovations GmbH) - add support for multicast
 *    Achim Kraus (Bosch Software Innovations GmbH) - move response retransmission
 *                                                    setup to BaseCoapStack to include
 *                                                    it also in a try-catch
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Message.OffloadMode;
import org.eclipse.californium.core.coap.CoAPMessageFormatException;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.InternalMessageObserverAdapter;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageFormatException;
import org.eclipse.californium.core.coap.MessageObserver;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.EndpointManager.ClientMessageDeliverer;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.config.NetworkConfigDefaults;
import org.eclipse.californium.core.network.interceptors.MessageInterceptor;
import org.eclipse.californium.core.network.serialization.DataParser;
import org.eclipse.californium.core.network.serialization.DataSerializer;
import org.eclipse.californium.core.network.serialization.TcpDataParser;
import org.eclipse.californium.core.network.serialization.TcpDataSerializer;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.core.network.serialization.UdpDataSerializer;
import org.eclipse.californium.core.network.stack.BlockwiseLayer;
import org.eclipse.californium.core.network.stack.ObserveLayer;
import org.eclipse.californium.core.network.stack.ReliabilityLayer;
import org.eclipse.californium.core.network.stack.ExchangeCleanupLayer;
import org.eclipse.californium.core.network.stack.CoapStack;
import org.eclipse.californium.core.network.stack.CoapTcpStack;
import org.eclipse.californium.core.network.stack.CoapUdpStack;
import org.eclipse.californium.core.observe.InMemoryObservationStore;
import org.eclipse.californium.core.observe.NotificationListener;
import org.eclipse.californium.core.observe.ObservationStore;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.MessageCallback;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Endpoint encapsulates the stack that executes the CoAP protocol. Endpoint
 * forwards incoming messages to a {@link MessageDeliverer}. The deliverer will
 * deliver requests to its destination resource. The resource sends the response
 * back over the same endpoint. The endpoint sends outgoing messages over a
 * connector. The connector encapsulates the transport protocol.
 * <p>
 * The CoAP Draft 18 describes an endpoint as: "A CoAP Endpoint is is identified
 * by transport layer multiplexing information that can include a UDP port
 * number and a security association." (draft-ietf-core-coap-14: 1.2)
 * <p>
 * The following diagram describes the structure of an endpoint. The endpoint
 * implements CoAP in layers. Incoming and outgoing messages always travel from
 * layer to layer. An {@link Exchange} represents the known state about the
 * exchange between a request and one or more corresponding responses. The
 * matcher remembers outgoing messages and matches incoming responses, acks and
 * rsts to them. MessageInterceptors registered with
 * {@link #addInterceptor(MessageInterceptor)} receive every incoming and
 * outgoing message. By default, only one interceptor is used to log messages.
 * 
 * <pre>
 * +-----------------------+
 * |   {@link MessageDeliverer}    +--&gt; (Resource Tree)
 * +-------------A---------+
 *               |
 *             * A            
 * +-Endpoint--+-A---------+
 * |           v A         |
 * |           v A         |
 * | +---------v-+-------+ |
 * | | Stack Top         | |
 * | +-------------------+ |
 * | | {@link ExchangeCleanupLayer}      | |
 * | +-------------------+ |
 * | | {@link ObserveLayer}      | |
 * | +-------------------+ |
 * | | {@link BlockwiseLayer}    | |
 * | +-------------------+ |
 * | | {@link ReliabilityLayer}  | |
 * | +-------------------+ |
 * | | Stack Bottom      | |
 * | +--------+-+--------+ |
 * |          v A          |
 * |          v A          |
 * |        {@link Matcher}        |
 * |          v A          |
 * |   {@link MessageInterceptor}  |  
 * |          v A          |
 * |          v A          |
 * | +--------v-+--------+ |
 * +-|     {@link Connector}     |-+
 *   +--------+-A--------+
 *            v A
 *            v A
 *         (Network)
 * </pre>
 * <p>
 * The endpoint and its layers use an {@link ScheduledExecutorService} to
 * execute tasks, e.g., when a request arrives.
 * </p>
 * 
 * Note: using IPv6 interfaces with multiple addresses including permanent and
 * temporary (with potentially several different prefixes) currently causes
 * issues on the server side. The outgoing traffic in response to incoming may
 * select a different source address than the incoming destination address. To
 * overcome this, please ensure that the 'any address' is not used on the server
 * side and a separate CoapEndpoint is created for each address to receive
 * incoming traffic.
 * 
 */
public class CoapEndpoint implements Endpoint, MessagePostProcessInterceptors, MulticastReceivers {

	/** the logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(CoapEndpoint.class);

	/** The stack of layers that make up the CoAP protocol */
	protected final CoapStack coapstack;

	/** The connector over which the endpoint connects to the network */
	private final Connector connector;

	private final String scheme;

	/**
	 * Base MID for multicast MID range. All multicast requests use the same MID
	 * scope with MIDs in the range [base...65536). None multicast request use
	 * the range [0...base). 0 := disable multicast support.
	 */
	private final int multicastBaseMid;

	/**
	 * Offload incoming request on sending response.
	 * 
	 * @see Message#offload()
	 */
	private final boolean useRequestOffloading;

	/** The configuration of this endpoint */
	private final NetworkConfig config;

	/**
	 * The matcher which matches incoming responses, akcs and rsts an exchange
	 */
	private final Matcher matcher;

	/** Serializer to convert messages to datagrams. */
	private final DataSerializer serializer;

	/** Parser to convert datagrams to messages. */
	private final DataParser parser;

	/** A store containing data about message exchanges. */
	private final MessageExchangeStore exchangeStore;

	/** A Store containing data about observation. */
	private final ObservationStore observationStore;

	/** tag for logging */
	private final String tag;

	/**
	 * @deprecated use {@link MessageInterceptor} registered with
	 *             {@link #addPostProcessInterceptor(MessageInterceptor)}
	 *             instead.
	 */
	@Deprecated
	private final CoapEndpointHealth health;

	/** The executor to run tasks for this endpoint and its layers */
	private ExecutorService executor;

	/** Scheduled executor intended to be used for rare executing timers (e.g. cleanup tasks). */
	private ScheduledExecutorService secondaryExecutor;

	/** Indicates if the endpoint has been started */
	private volatile boolean started;

	/** The list of endpoint observers (has nothing to do with CoAP observe relations) */
	private List<EndpointObserver> observers = new CopyOnWriteArrayList<>();

	/** The list of interceptors */
	private List<MessageInterceptor> interceptors = new CopyOnWriteArrayList<>();

	/** The list of post process interceptors */
	private List<MessageInterceptor> postProcessInterceptors = new CopyOnWriteArrayList<>();

	/** The list of Notification listener (use for CoAP observer relations) */
	private List<NotificationListener> notificationListeners = new CopyOnWriteArrayList<>();

	/**
	 * The list of multicast receivers.
	 * 
	 * @since 2.3
	 */
	private List<Connector> multicastReceivers = new CopyOnWriteArrayList<>();

	private ScheduledFuture<?> statusLogger;

	private final EndpointReceiver endpointStackReceiver = new EndpointReceiver() {

		@Override
		public void receiveRequest(Exchange exchange, Request request) {
			exchange.setEndpoint(CoapEndpoint.this);
			if (health != null) {
				health.receivedRequest(request.isDuplicate());
			}
			coapstack.receiveRequest(exchange, request);
			notifyReceive(postProcessInterceptors, request);
		}

		@Override
		public void receiveResponse(Exchange exchange, Response response) {
			if (exchange != null && !response.isCanceled()) {
				exchange.setEndpoint(CoapEndpoint.this);
				response.setRTT(exchange.calculateRTT());
				if (health != null) {
					health.receivedResponse(response.isDuplicate());
				}
				coapstack.receiveResponse(exchange, response);
			}
			notifyReceive(postProcessInterceptors, response);
		}

		@Override
		public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
			if (exchange != null && !message.isCanceled()) {
				exchange.setEndpoint(CoapEndpoint.this);
				if (health != null && message.getType() == Type.RST) {
					health.receivedReject();
				}
				coapstack.receiveEmptyMessage(exchange, message);
			}
			notifyReceive(postProcessInterceptors, message);
		}

		@Override
		public void reject(final Message message) {
			EmptyMessage rst = EmptyMessage.newRST(message);
			if (rejectTransmission != null) {
				rst.addMessageObserver(rejectTransmission);
			}
			coapstack.sendEmptyMessage(null, rst);
		}
	};

	/**
	 * @deprecated use {@link MessageInterceptor} registered with
	 *             {@link #addPostProcessInterceptor(MessageInterceptor)}
	 *             instead.
	 */
	@Deprecated
	private final MessageObserver requestTransmission;

	/**
	 * @deprecated use {@link MessageInterceptor} registered with
	 *             {@link #addPostProcessInterceptor(MessageInterceptor)}
	 *             instead.
	 */
	@Deprecated
	private final MessageObserver responseTransmission;

	/**
	 * @deprecated use {@link MessageInterceptor} registered with
	 *             {@link #addPostProcessInterceptor(MessageInterceptor)}
	 *             instead.
	 */
	@Deprecated
	private final MessageObserver rejectTransmission;

	/**
	 * Creates a new endpoint for a connector, configuration, message exchange
	 * and observation store.
	 * <p>
	 * Intended to be called either by the {@link Builder} or a subclass
	 * constructor. The endpoint will support the connector's implemented scheme
	 * and will bind to the IP address and port the connector is configured for.
	 *
	 * @param connector The connector to use.
	 * @param applyConfiguration if {@code true}, apply network configuration to
	 *            connector. Requires a {@link UDPConnector}.
	 * @param config The configuration values to use.
	 * @param tokenGenerator token generator.
	 * @param store The store to use for keeping track of observations initiated
	 *            by this endpoint.
	 * @param exchangeStore The store to use for keeping track of message
	 *            exchanges.
	 * @param endpointContextMatcher endpoint context matcher for relating
	 *            responses to requests. If <code>null</code>, the result of
	 *            {@link EndpointContextMatcherFactory#create(Connector, NetworkConfig)}
	 *            is used as matcher.
	 * @param serializer message serializer. May be {@code null}.
	 * @param parser message parser. May be {@code null}.
	 * @param loggingTag logging tag.
	 *            {@link StringUtil#normalizeLoggingTag(String)} is applied to
	 *            the provided tag.
	 * @param health custom coap health handler. Deprecated see below.
	 * @param coapStackFactory coap-stack-factory factory to create coap-stack
	 * @param customStackArgument argument for custom stack, if required.
	 *            {@code null} for standard stacks, or if the custom stack
	 *            doesn't require specific arguments. My be a {@link Map}, if
	 *            multiple arguments are required.
	 * @throws IllegalArgumentException if applyConfiguration is {@code true},
	 *             but the connector is not a {@link UDPConnector}
	 * @deprecated use
	 *             {@link #CoapEndpoint(Connector, boolean, NetworkConfig, TokenGenerator, ObservationStore, MessageExchangeStore, EndpointContextMatcher, DataSerializer, DataParser, String, CoapStackFactory, Object)}
	 *             and {@link #addPostProcessInterceptor(MessageInterceptor)} instead.
	 */
	@Deprecated
	protected CoapEndpoint(Connector connector, boolean applyConfiguration, NetworkConfig config,
			TokenGenerator tokenGenerator, ObservationStore store, MessageExchangeStore exchangeStore,
			EndpointContextMatcher endpointContextMatcher, DataSerializer serializer, DataParser parser,
			String loggingTag, CoapEndpointHealth health, CoapStackFactory coapStackFactory,
			Object customStackArgument) {
		this.config = config;
		this.connector = connector;
		this.connector.setRawDataReceiver(new InboxImpl());
		this.scheme = CoAP.getSchemeForProtocol(connector.getProtocol());
		this.multicastBaseMid = config.getInt(Keys.MULTICAST_BASE_MID);
		this.tag = StringUtil.normalizeLoggingTag(loggingTag);

		// when remove the deprecated constructors,
		// this checks and defaults maybe also removed
		if (tokenGenerator == null) {
			tokenGenerator = new RandomTokenGenerator(config);
		}
		if (coapStackFactory == null) {
			coapStackFactory = getDefaultCoapStackFactory();
		}
		this.exchangeStore = (null != exchangeStore) ? exchangeStore
				: new InMemoryMessageExchangeStore(tag, config, tokenGenerator, endpointContextMatcher);
		observationStore = (null != store) ? store : new InMemoryObservationStore(config);
		if (null == endpointContextMatcher) {
			endpointContextMatcher = EndpointContextMatcherFactory.create(connector, config);
		}

		// keep for subclasses
		if (applyConfiguration) {
			if (connector instanceof UDPConnector) {
				UDPConnector udpConnector = (UDPConnector) connector;
				udpConnector.setReceiverThreadCount(config.getInt(Keys.NETWORK_STAGE_RECEIVER_THREAD_COUNT));
				udpConnector.setSenderThreadCount(config.getInt(Keys.NETWORK_STAGE_SENDER_THREAD_COUNT));

				udpConnector.setReceiveBufferSize(config.getInt(Keys.UDP_CONNECTOR_RECEIVE_BUFFER));
				udpConnector.setSendBufferSize(config.getInt(Keys.UDP_CONNECTOR_SEND_BUFFER));
				udpConnector.setReceiverPacketSize(config.getInt(Keys.UDP_CONNECTOR_DATAGRAM_SIZE));
			} else {
				throw new IllegalArgumentException("Connector must be a UDPConnector to use apply configuration!");
			}
		}

		final Executor exchangeExecutionHandler = new Executor() {

			@Override
			public void execute(Runnable command) {
				final Executor exchangeExecutor = executor;
				if (exchangeExecutor == null) {
					LOGGER.error("{}Executor not ready for exchanges!",
							tag, new Throwable("exchange execution failed!"));
				} else {
					exchangeExecutor.execute(command);
				}
			}
		};

		this.connector.setEndpointContextMatcher(endpointContextMatcher);
		LOGGER.info("{}{} uses {}", tag, getClass().getSimpleName(), endpointContextMatcher.getName());

		this.coapstack = coapStackFactory.createCoapStack(connector.getProtocol(), config, new OutboxImpl(), customStackArgument);

		if (CoAP.isTcpProtocol(connector.getProtocol())) {
			this.useRequestOffloading = false; // no deduplication
			this.matcher = new TcpMatcher(config, new NotificationDispatcher(), tokenGenerator, observationStore,
					this.exchangeStore, exchangeExecutionHandler, endpointContextMatcher);
			this.serializer = serializer != null ? serializer : new TcpDataSerializer();
			this.parser = parser != null ? parser : new TcpDataParser();
		} else {
			this.useRequestOffloading = config.getBoolean(Keys.USE_MESSAGE_OFFLOADING);
			this.matcher = new UdpMatcher(config, new NotificationDispatcher(), tokenGenerator, observationStore,
					this.exchangeStore, exchangeExecutionHandler, endpointContextMatcher);
			this.serializer = serializer != null ? serializer : new UdpDataSerializer();
			this.parser = parser != null ? parser : new UdpDataParser();
		}
		final int healthStatusInterval = config.getInt(Keys.HEALTH_STATUS_INTERVAL, NetworkConfigDefaults.DEFAULT_HEALTH_STATUS_INTERVAL); // seconds
		// this is a useful health metric
		// that could later be exported to some kind of monitoring interface
		boolean enableHealth = false;
		if (healthStatusInterval > 0) {
			if (health == null) {
				health = new CoapEndpointHealthLogger();
			}
			enableHealth = health.isEnabled();
		}
		if (enableHealth) {
			this.health = health;
			this.requestTransmission = new InternalMessageObserverAdapter() {

				@Override
				public void  onSendError(Throwable error) {
					CoapEndpoint.this.health.sendError();
				}

				@Override
				public void onSent(boolean retransmission) {
					CoapEndpoint.this.health.sentRequest(retransmission);
				}
			};

			this.responseTransmission = new InternalMessageObserverAdapter() {
				@Override
				public void  onSendError(Throwable error) {
					CoapEndpoint.this.health.sendError();
				}

				@Override
				public void onSent(boolean retransmission) {
					CoapEndpoint.this.health.sentResponse(retransmission);
				}
			};
			this.rejectTransmission = new InternalMessageObserverAdapter() {
				@Override
				public void  onSendError(Throwable error) {
					CoapEndpoint.this.health.sendError();
				}

				@Override
				public void onSent(boolean retransmission) {
					CoapEndpoint.this.health.sentReject();
				}
			};
		} else {
			this.health = null;
			this.requestTransmission = null;
			this.responseTransmission = null;
			this.rejectTransmission = null;
		}
	}

	/**
	 * Creates a new endpoint for a connector, configuration, message exchange
	 * and observation store.
	 * <p>
	 * Intended to be called either by the {@link Builder} or a subclass
	 * constructor. The endpoint will support the connector's implemented scheme
	 * and will bind to the IP address and port the connector is configured for.
	 *
	 * @param connector The connector to use.
	 * @param applyConfiguration if {@code true}, apply network configuration to
	 *            connector. Requires a {@link UDPConnector}.
	 * @param config The configuration values to use.
	 * @param tokenGenerator token generator.
	 * @param store The store to use for keeping track of observations initiated
	 *            by this endpoint.
	 * @param exchangeStore The store to use for keeping track of message
	 *            exchanges.
	 * @param endpointContextMatcher endpoint context matcher for relating
	 *            responses to requests. If <code>null</code>, the result of
	 *            {@link EndpointContextMatcherFactory#create(Connector, NetworkConfig)}
	 *            is used as matcher.
	 * @param loggingTag logging tag.
	 *            {@link StringUtil#normalizeLoggingTag(String)} is applied to
	 *            the provided tag.
	 * @param coapStackFactory coap-stack-factory factory to create coap-stack
	 * @param customStackArgument argument for custom stack, if required.
	 *            {@code null} for standard stacks, or if the custom stack
	 *            doesn't require specific arguments. My be a {@link Map}, if
	 *            multiple arguments are required.
	 * @throws IllegalArgumentException if applyConfiguration is {@code true},
	 *             but the connector is not a {@link UDPConnector}
	 * @deprecated use
	 *             {@link #CoapEndpoint(Connector, boolean, NetworkConfig, TokenGenerator, ObservationStore, MessageExchangeStore, EndpointContextMatcher, DataSerializer, DataParser, String, CoapStackFactory, Object)}
	 *             instead.
	 */
	@Deprecated
	protected CoapEndpoint(Connector connector, boolean applyConfiguration, NetworkConfig config,
			TokenGenerator tokenGenerator, ObservationStore store, MessageExchangeStore exchangeStore,
			EndpointContextMatcher endpointContextMatcher, 
			String loggingTag, CoapStackFactory coapStackFactory, Object customStackArgument) {
		this(connector, applyConfiguration, config, tokenGenerator, store, exchangeStore, endpointContextMatcher,
				null, null, loggingTag, null, coapStackFactory, customStackArgument);
	}

	/**
	 * Creates a new endpoint for a connector, configuration, message exchange
	 * and observation store.
	 * <p>
	 * Intended to be called either by the {@link Builder} or a subclass
	 * constructor. The endpoint will support the connector's implemented scheme
	 * and will bind to the IP address and port the connector is configured for.
	 *
	 * @param connector The connector to use.
	 * @param applyConfiguration if {@code true}, apply network configuration to
	 *            connector. Requires a {@link UDPConnector}.
	 * @param config The configuration values to use.
	 * @param tokenGenerator token generator.
	 * @param store The store to use for keeping track of observations initiated
	 *            by this endpoint.
	 * @param exchangeStore The store to use for keeping track of message
	 *            exchanges.
	 * @param endpointContextMatcher endpoint context matcher for relating
	 *            responses to requests. If <code>null</code>, the result of
	 *            {@link EndpointContextMatcherFactory#create(Connector, NetworkConfig)}
	 *            is used as matcher.
	 * @param serializer message serializer. May be {@code null}.
	 * @param parser message parser. May be {@code null}.
	 * @param loggingTag logging tag.
	 *            {@link StringUtil#normalizeLoggingTag(String)} is applied to
	 *            the provided tag.
	 * @param coapStackFactory coap-stack-factory factory to create coap-stack
	 * @param customStackArgument argument for custom stack, if required.
	 *            {@code null} for standard stacks, or if the custom stack
	 *            doesn't require specific arguments. My be a {@link Map}, if
	 *            multiple arguments are required.
	 * @throws IllegalArgumentException if applyConfiguration is {@code true},
	 *             but the connector is not a {@link UDPConnector}
	 * @since 2.6
	 */
	protected CoapEndpoint(Connector connector, boolean applyConfiguration, NetworkConfig config,
			TokenGenerator tokenGenerator, ObservationStore store, MessageExchangeStore exchangeStore,
			EndpointContextMatcher endpointContextMatcher, DataSerializer serializer, DataParser parser,
			String loggingTag, CoapStackFactory coapStackFactory, Object customStackArgument) {
		this(connector, applyConfiguration, config, tokenGenerator, store, exchangeStore, endpointContextMatcher,
				serializer, parser, loggingTag, null, coapStackFactory, customStackArgument);
	}

	@Override
	public synchronized void start() throws IOException {
		if (started) {
			LOGGER.debug("{}Endpoint at {} is already started", tag, getUri());
			return;
		}

		if (!this.coapstack.hasDeliverer()) {
			setMessageDeliverer(new ClientMessageDeliverer());
		}

		if (this.executor == null) {
			LOGGER.info("{}Endpoint [{}] requires an executor to start, using default single-threaded daemon executor", tag, getUri());

			// in production environments the executor should be set to a multi
			// threaded version in order to utilize all cores of the processor
			final ScheduledExecutorService executorService = ExecutorsUtil
					.newSingleThreadScheduledExecutor(new DaemonThreadFactory(":CoapEndpoint-" + connector + '#')); //$NON-NLS-1$
			setExecutors(executorService, executorService);
			addObserver(new EndpointObserver() {

				@Override
				public void started(final Endpoint endpoint) {
					// do nothing
				}

				@Override
				public void stopped(final Endpoint endpoint) {
					// do nothing
				}

				@Override
				public void destroyed(final Endpoint endpoint) {
					ExecutorsUtil.shutdownExecutorGracefully(1000, executorService);
				}
			});
		}

		try {
			LOGGER.debug("{}Starting endpoint at {}", tag, getUri());

			matcher.start();
			startMulticastReceivers();
			connector.start();
			coapstack.start();
			started = true;
			for (EndpointObserver obs : observers) {
				obs.started(this);
			}
			LOGGER.info("{}Started endpoint at {}", tag, getUri());
			if (health != null && secondaryExecutor != null) {
				final int healthStatusInterval = config.getInt(Keys.HEALTH_STATUS_INTERVAL,
						NetworkConfigDefaults.DEFAULT_HEALTH_STATUS_INTERVAL); // seconds
				// this is a useful health metric
				// that could later be exported to some kind of monitoring interface
				statusLogger = secondaryExecutor.scheduleAtFixedRate(new Runnable() {

					@Override
					public void run() {
						health.dump(tag);
					}

				}, healthStatusInterval, healthStatusInterval, TimeUnit.SECONDS);
			}
		} catch (IOException e) {
			// free partially acquired resources
			stop();
			throw e;
		}
	}

	@Override
	public synchronized void stop() {
		if (!started) {
			LOGGER.info("{}Endpoint at {} is already stopped", tag, getUri());
		} else {
			LOGGER.info("{}Stopping endpoint at {}", tag, getUri());
			started = false;
			if (statusLogger != null) {
				statusLogger.cancel(false);
				statusLogger = null;
			}
			for (Connector receiver : multicastReceivers) {
				receiver.stop();
			}
			connector.stop();
			matcher.stop();
			for (EndpointObserver obs : observers) {
				obs.stopped(this);
			}
		}
	}

	@Override
	public synchronized void destroy() {
		LOGGER.info("{}Destroying endpoint at {}", tag, getUri());
		if (started) {
			stop();
		}
		for (Connector receiver : multicastReceivers) {
			receiver.destroy();
		}
		connector.destroy();
		coapstack.destroy();
		for (EndpointObserver obs : observers) {
			obs.destroyed(this);
		}
	}

	@Override
	public void clear() {
		matcher.clear();
	}

	@Override
	public boolean isStarted() {
		return started;
	}

	@Override
	public void setExecutors(ScheduledExecutorService mainExecutor, ScheduledExecutorService secondaryExecutor) {
		if (mainExecutor == null || secondaryExecutor == null) {
			throw new IllegalArgumentException("executors must not be null");
		}
		if (this.executor == mainExecutor &&  this.secondaryExecutor == secondaryExecutor) {
			return;
		}
		if (started) {
			throw new IllegalStateException("endpoint already started!");
		}
		this.executor = mainExecutor;
		this.secondaryExecutor = secondaryExecutor;
		this.coapstack.setExecutors(mainExecutor, this.secondaryExecutor);
		this.exchangeStore.setExecutor(this.secondaryExecutor);
		this.observationStore.setExecutor(this.secondaryExecutor);
	}

	@Override
	public void addNotificationListener(final NotificationListener listener) {
		notificationListeners.add(listener);
	}

	@Override
	public void removeNotificationListener(final NotificationListener listener) {
		notificationListeners.remove(listener);
	}

	@Override
	public void addObserver(final EndpointObserver observer) {
		observers.add(observer);
	}

	@Override
	public void removeObserver(final EndpointObserver observer) {
		observers.remove(observer);
	}

	@Override
	public void addInterceptor(final MessageInterceptor interceptor) {
		interceptors.add(interceptor);
	}

	@Override
	public void removeInterceptor(final MessageInterceptor interceptor) {
		interceptors.remove(interceptor);
	}

	@Override
	public List<MessageInterceptor> getInterceptors() {
		return Collections.unmodifiableList(interceptors);
	}

	@Override
	public void addPostProcessInterceptor(MessageInterceptor interceptor) {
		postProcessInterceptors.add(interceptor);
	}

	@Override
	public void removePostProcessInterceptor(MessageInterceptor interceptor) {
		postProcessInterceptors.remove(interceptor);
	}

	@Override
	public List<MessageInterceptor> getPostProcessInterceptors() {
		return Collections.unmodifiableList(postProcessInterceptors);
	}

	@Override
	public void addMulticastReceiver(final Connector receiver) {
		if (receiver == null) {
			throw new NullPointerException("Connector must not be null!");
		}
		if (!NetworkInterfacesUtil.isMultiAddress(receiver.getAddress().getAddress())) {
			throw new IllegalArgumentException("Connector is not a valid multicast receiver!");
		}
		multicastReceivers.add(receiver);
		receiver.setRawDataReceiver(new MulticastReceiverInbox(receiver));
	}

	@Override
	public void removeMulticastReceiver(Connector receiver) {
		multicastReceivers.remove(receiver);
		receiver.setRawDataReceiver(null);
	}

	@Override
	public void startMulticastReceivers() throws IOException {
		for (Connector receiver : multicastReceivers) {
			receiver.start();
		}
	}

	@Override
	public void sendRequest(final Request request) {
		if (!started) {
			request.cancel();
			return;
		}
		// create context, if not already set
		request.prepareDestinationContext();

		InetSocketAddress destinationAddress = request.getDestinationContext().getPeerAddress();
		if (request.isMulticast()) {
			if (0 >= multicastBaseMid) {
				LOGGER.warn("{}multicast messaging to destination {} is not enabled! Please enable it configuring \""
						+ Keys.MULTICAST_BASE_MID + "\" greater than 0", tag, destinationAddress);
				request.setSendError(new IllegalArgumentException("multicast is not enabled!"));
				return;
			} else if (request.getType() == Type.CON) {
				LOGGER.warn(
						"{}CON request to multicast destination {} is not allowed, as per RFC 7252, 8.1, a client MUST use NON message type for multicast requests ",
						tag, destinationAddress);
				request.setSendError(new IllegalArgumentException("multicast is not supported for CON!"));
				return;
			} else if (request.hasMID() && request.getMID() < multicastBaseMid) {
				LOGGER.warn(
						"{}multicast request to group {} has mid {} which is not in the MULTICAST_MID range [{}-65535]",
						tag, destinationAddress, request.getMID(), multicastBaseMid);
				request.setSendError(
						new IllegalArgumentException("multicast mid is not in range [" + multicastBaseMid + "-65535]"));
				return;
			}
		} else if (0 < multicastBaseMid && request.getMID() >= multicastBaseMid) {
			LOGGER.warn("{}request to {} has mid {}, which is in the MULTICAST_MID range [{}-65535]", tag, destinationAddress,
					request.getMID(), multicastBaseMid);
			request.setSendError(
					new IllegalArgumentException("unicast mid is in multicast range [" + multicastBaseMid + "-65535]"));
			return;
		}
		if (destinationAddress.isUnresolved()) {
			LOGGER.warn("{}request has unresolved destination address", tag, destinationAddress);
			request.setSendError(
					new IllegalArgumentException(destinationAddress + " is a unresolved address!"));
			return;
		}

		final Exchange exchange = new Exchange(request, Origin.LOCAL, executor);
		exchange.execute(new Runnable() {

			@Override
			public void run() {
				if (requestTransmission != null) {
					request.addMessageObserver(requestTransmission);
				}
				coapstack.sendRequest(exchange, request);
			}
		});
	}

	@Override
	public void sendResponse(final Exchange exchange, final Response response) {
		if (!started) {
			response.cancel();
			return;
		}
		if (responseTransmission != null) {
			response.addMessageObserver(responseTransmission);
		}
		if (exchange.checkOwner()) {
			// send response while processing exchange.
			coapstack.sendResponse(exchange, response);
		} else {
			exchange.execute(new Runnable() {
				@Override
				public void run() {
					coapstack.sendResponse(exchange, response);
				}
			});
		}
	}

	@Override
	public void sendEmptyMessage(final Exchange exchange, final EmptyMessage message) {
		if (!started) {
			message.cancel();
			return;
		}
		if (rejectTransmission != null && message.getType() == Type.RST) {
			message.addMessageObserver(rejectTransmission);
		}
		if (exchange.checkOwner()) {
			// send response while processing exchange.
			coapstack.sendEmptyMessage(exchange, message);
		} else {
			exchange.execute(new Runnable() {

				@Override
				public void run() {
					coapstack.sendEmptyMessage(exchange, message);
				}
			});
		}
	}

	/**
	 * Sets a processor for incoming requests and responses to.
	 * <p>
	 * Incoming responses that represent notifications for observations 
	 * will also be forwarded to all notification listeners.
	 * </p>
	 * 
	 * @param deliverer the processor to deliver messages to.
	 * @throws NullPointerException if the given deliverer is {@code null}
	 */
	@Override
	public void setMessageDeliverer(MessageDeliverer deliverer) {
		coapstack.setDeliverer(deliverer);
	}

	@Override
	public InetSocketAddress getAddress() {
		return connector.getAddress();
	}

	@Override
	public URI getUri() {
		try {
			InetSocketAddress address = getAddress();
			String hostname = StringUtil.getUriHostname(address.getAddress());
			return new URI(scheme, null, hostname, address.getPort(), null, null, null);
		} catch (URISyntaxException e) {
			LOGGER.warn("{}URI", tag, e);
		}
		return null;
	}

	@Override
	public NetworkConfig getConfig() {
		return config;
	}

	public Connector getConnector() {
		return connector;
	}

	private class NotificationDispatcher implements NotificationListener {

		@Override
		public void onNotification(final Request request, final Response response) {

			// we can rely on the fact that the CopyOnWriteArrayList just provides a
			// "snapshot" iterator over the notification listeners
			for (NotificationListener notificationListener : notificationListeners) {
				notificationListener.onNotification(request, response);
			}
		}
	}

	private void notifySend(List<MessageInterceptor> list, Request request) {
		for (MessageInterceptor interceptor : list) {
			interceptor.sendRequest(request);
		}
	}

	private void notifySend(List<MessageInterceptor> list, Response response) {
		for (MessageInterceptor interceptor : list) {
			interceptor.sendResponse(response);
		}
	}

	private void notifySend(List<MessageInterceptor> list, EmptyMessage emptyMessage) {
		for (MessageInterceptor interceptor : list) {
			interceptor.sendEmptyMessage(emptyMessage);
		}
	}

	private void notifyReceive(List<MessageInterceptor> list, Request request) {
		for (MessageInterceptor interceptor : list) {
			interceptor.receiveRequest(request);
		}
	}

	private void notifyReceive(List<MessageInterceptor> list, Response response) {
		for (MessageInterceptor interceptor : list) {
			interceptor.receiveResponse(response);
		}
	}

	private void notifyReceive(List<MessageInterceptor> list, EmptyMessage emptyMessage) {
		for (MessageInterceptor interceptor : list) {
			interceptor.receiveEmptyMessage(emptyMessage);
		}
	}

	/**
	 * The stack of layers uses this Outbox to send messages. The OutboxImpl
	 * will then give them to the matcher, the interceptors, and finally send
	 * them over the connector.
	 */
	public class OutboxImpl implements Outbox {

		@Override
		public void sendRequest(final Exchange exchange, final Request request) {

			assertMessageHasDestinationAddress(request);
			exchange.setCurrentRequest(request);
			matcher.sendRequest(exchange);

			/*
			 * Logging here causes significant performance loss.
			 * If necessary, add an interceptor that logs the messages,
			 * e.g., the MessageTracer.
			 */
			notifySend(interceptors, request);
			request.setReadyToSend();

			if (!started) {
				request.cancel();
			}
			// Request may have been canceled already, e.g. by one of the interceptors
			// or client code
			if (request.isCanceled() || request.getSendError() != null) {

				// make sure we do necessary house keeping, e.g. removing the exchange from
				// ExchangeStore to avoid memory leak
				// The Exchange may already have been completed implicitly by client code
				// invoking Request.cancel().
				// However, that might have happened BEFORE the exchange got registered with the
				// ExchangeStore. So, to make sure that we do not leak memory we complete the
				// Exchange again here, triggering the "housekeeping" functionality in the Matcher
				exchange.executeComplete();

			} else {
				RawData message = serializer.serializeRequest(request,
						new ExchangeCallback<Request>(exchange, request) {

							@Override
							protected void notifyPostProcess(Request request) {
								notifySend(postProcessInterceptors, request);
							}

						});
				connector.send(message);
			}
		}

		@Override
		public void sendResponse(Exchange exchange, Response response) {

			assertMessageHasDestinationAddress(response);
			exchange.setCurrentResponse(response);
			matcher.sendResponse(exchange);

			/*
			 * Logging here causes significant performance loss.
			 * If necessary, add an interceptor that logs the messages,
			 * e.g., the MessageTracer.
			 */
			notifySend(interceptors, response);
			response.setReadyToSend();

			if (!started) {
				response.cancel();
			}

			// MessageInterceptor might have canceled
			if (response.isCanceled() || response.getSendError() != null) {
				exchange.executeComplete();
			} else {
				RawData data = serializer.serializeResponse(response,
						new ExchangeCallback<Response>(exchange, response) {

							@Override
							protected void notifyPostProcess(Response response) {
								notifySend(postProcessInterceptors, response);
								if (useRequestOffloading) {
									exchange.getCurrentRequest().offload(OffloadMode.FULL);
									response.offload(OffloadMode.PAYLOAD);
								}
							}
						});

				connector.send(data);
			}
		}

		@Override
		public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {

			assertMessageHasDestinationAddress(message);
			matcher.sendEmptyMessage(exchange, message);

			/*
			 * Logging here causes significant performance loss. If necessary,
			 * add an interceptor that logs the messages, e.g., the
			 * MessageTracer.
			 */
			notifySend(interceptors, message);
			message.setReadyToSend();

			if (!started) {
				message.cancel();
			}

			// MessageInterceptor might have canceled
			if (message.isCanceled() || message.getSendError() != null) {
				if (null != exchange) {
					exchange.executeComplete();
				}
			} else if (exchange != null) {
				connector.send(serializer.serializeEmptyMessage(message,
						new ExchangeCallback<EmptyMessage>(exchange, message) {

							@Override
							protected void notifyPostProcess(EmptyMessage message) {
								notifySend(postProcessInterceptors, message);
							}
						}));
			} else {
				connector.send(serializer.serializeEmptyMessage(message, new SendingCallback<EmptyMessage>(message) {

					@Override
					protected void notifyPostProcess(EmptyMessage message) {
						notifySend(postProcessInterceptors, message);
					}
				}));
			}
		}

		private void assertMessageHasDestinationAddress(final Message message) {
			if (message.getDestinationContext() == null) {
				throw new IllegalArgumentException("Message has no endpoint context");
			}
		}
	}

	/**
	 * The connector uses this channel to forward messages (in form of
	 * {@link RawData}) to the endpoint. The endpoint creates a new task to
	 * process the message. The task consists of invoking the matcher to look
	 * for an associated exchange and then forwards the message with the
	 * exchange to the stack of layers.
	 */
	private class InboxImpl implements RawDataChannel {

		@Override
		public void receiveData(final RawData raw) {
			if (raw.getEndpointContext() == null) {
				throw new IllegalArgumentException("received message that does not have a endpoint context");
			} else if (raw.getEndpointContext().getPeerAddress() == null) {
				throw new IllegalArgumentException("received message that does not have a source address");
			} else if (raw.getEndpointContext().getPeerAddress().getPort() == 0) {
				throw new IllegalArgumentException("received message that does not have a source port");
			} else {

				// Create a new task to process this message
				runInProtocolStage(new Runnable() {

					@Override
					public void run() {
						receiveMessage(raw);
					}
				});
			}
		}

		/*
		 * The endpoint's executor executes this method to convert the raw bytes
		 * into a message, look for an associated exchange and forward it to
		 * the stack of layers. If the message is a CON and cannot be parsed,
		 * e.g. because the message is malformed, an RST is sent back to the sender.
		 */
		private void receiveMessage(final RawData raw) {

			Message msg = null;

			try {
				msg = parser.parseMessage(raw);

				if (CoAP.isRequest(msg.getRawCode())) {

					receiveRequest((Request) msg);

				} else if (CoAP.isResponse(msg.getRawCode())) {

					receiveResponse((Response) msg);

				} else if (CoAP.isEmptyMessage(msg.getRawCode())) {

					receiveEmptyMessage((EmptyMessage) msg);

				} else {
					LOGGER.debug("{}silently ignoring non-CoAP message from {}", tag, raw.getEndpointContext());
				}

			} catch (CoAPMessageFormatException e) {

				if (e.isConfirmable() && e.hasMid()) {
					if (CoAP.isRequest(e.getCode()) && e.getToken() != null) {
						// respond with BAD OPTION erroneous reliably transmitted request as mandated by CoAP spec
						// https://tools.ietf.org/html/rfc7252#section-4.2
						responseBadOption(raw, e);
						LOGGER.debug("{}respond malformed request from [{}], reason: {}",
								tag, raw.getEndpointContext(), e.getMessage());
					} else {
						// reject erroneous reliably transmitted message as mandated by CoAP spec
						// https://tools.ietf.org/html/rfc7252#section-4.2
						reject(raw, e);
						LOGGER.debug("{}rejected malformed message from [{}], reason: {}",
								tag, raw.getEndpointContext(), e.getMessage());
					}
				} else {
					// ignore erroneous messages that are not transmitted reliably
					LOGGER.debug("{}discarding malformed message from [{}]: {}", tag, raw.getEndpointContext(), e.getMessage());
				}
			} catch (MessageFormatException e) {

				// ignore erroneous messages that are not transmitted reliably
				LOGGER.debug("{}discarding malformed message from [{}]: {}", tag, raw.getEndpointContext(), e.getMessage());
			}
		}

		private void responseBadOption(final RawData raw, final CoAPMessageFormatException cause) {
			Response response = new Response(ResponseCode.BAD_OPTION);
			response.setDestinationContext(raw.getEndpointContext());
			response.setToken(cause.getToken());
			response.setMID(cause.getMid());
			response.setType(Type.ACK);
			response.setPayload(cause.getMessage());
			if (responseTransmission != null) {
				response.addMessageObserver(responseTransmission);
			}
			/*
			 * Logging here causes significant performance loss.
			 * If necessary, add an interceptor that logs the messages,
			 * e.g., the MessageTracer.
			 */
			notifySend(interceptors, response);
			response.setReadyToSend();

			if (!started) {
				response.cancel();
			}

			RawData data = serializer.serializeResponse(response,
					new SendingCallback<Response>(response) {

						@Override
						protected void notifyPostProcess(Response response) {
							notifySend(postProcessInterceptors, response);
						}
					});

			connector.send(data);
		}

		private void reject(final RawData raw, final CoAPMessageFormatException cause) {

			// Generate RST
			EmptyMessage rst = new EmptyMessage(Type.RST);
			rst.setMID(cause.getMid());
			rst.setDestinationContext(raw.getEndpointContext());
			if (rejectTransmission != null) {
				rst.addMessageObserver(rejectTransmission);
			}

			coapstack.sendEmptyMessage(null, rst);
		}

		private void receiveRequest(final Request request) {

			// set request attributes from raw data
			request.setScheme(scheme);

			if (!started) {
				LOGGER.debug("{}not running, drop request {}", tag, request);
				return;
			}

			/* 
			 * Logging here causes significant performance loss.
			 * If necessary, add an interceptor that logs the messages,
			 * e.g., the MessageTracer.
			 */
			notifyReceive(interceptors, request);

			// MessageInterceptor might have canceled
			if (!request.isCanceled()) {
				matcher.receiveRequest(request, endpointStackReceiver);
			}
		}

		private void receiveResponse(final Response response) {

			/*
			 * Logging here causes significant performance loss.
			 * If necessary, add an interceptor that logs the messages,
			 * e.g., the MessageTracer.
			 */
			notifyReceive(interceptors, response);

			// MessageInterceptor might have canceled
			if (!response.isCanceled()) {
				matcher.receiveResponse(response, endpointStackReceiver);
			}
		}

		private void receiveEmptyMessage(final EmptyMessage message) {

			/*
			 * Logging here causes significant performance loss.
			 * If necessary, add an interceptor that logs the messages,
			 * e.g., the MessageTracer.
			 */
			notifyReceive(interceptors, message);

			// MessageInterceptor might have canceled
			if (!message.isCanceled()) {
				// CoAP Ping
				if ((message.getType() == Type.CON || message.getType() == Type.NON) && message.hasMID()) {
					LOGGER.debug("{}responding to ping from {}", tag, message.getSourceContext());
					endpointStackReceiver.reject(message);
				} else {
					 matcher.receiveEmptyMessage(message, endpointStackReceiver);
				}
			}
		}
	}

	/**
	 * A multicast receiver uses this channel to forward requests (in form of
	 * {@link RawData}) to the endpoint. The endpoint creates a new task to
	 * process the message. The multicast group is set as destionation of the
	 * received request, {@link Request#isMulticast()} returns therfore
	 * {@code true}. The task consists of invoking the matcher to look for an
	 * associated exchange and then forwards the message with the exchange to
	 * the stack of layers. Responses and empty messages are silently ignored.
	 * 
	 * @since 2.3
	 */
	private class MulticastReceiverInbox implements RawDataChannel {

		private final Connector connector;
		private final String scheme;

		private MulticastReceiverInbox(Connector connector) {
			this.connector = connector;
			this.scheme = CoAP.getSchemeForProtocol(connector.getProtocol());
		}

		@Override
		public void receiveData(final RawData raw) {
			if (raw.getEndpointContext() == null) {
				throw new IllegalArgumentException("multicast-receiver received message that does not have a endpoint context");
			} else if (raw.getEndpointContext().getPeerAddress() == null) {
				throw new IllegalArgumentException("multicast-receiver received message that does not have a source address");
			} else if (raw.getEndpointContext().getPeerAddress().getPort() == 0) {
				throw new IllegalArgumentException("multicast-receiver received message that does not have a source port");
			} else if (!raw.isMulticast()) {
				throw new IllegalArgumentException("multicast-receiver received message is not from multicast group");
			} else {

				// Create a new task to process this message
				runInProtocolStage(new Runnable() {

					@Override
					public void run() {
						receiveMessage(raw);
					}
				});
			}
		}

		/*
		 * The endpoint's executor executes this method to convert the raw bytes
		 * into a message, look for an associated exchange and forward it to the
		 * stack of layers. If the message is a CON and cannot be parsed, e.g.
		 * because the message is malformed, an RST is sent back to the sender.
		 */
		private void receiveMessage(final RawData raw) {

			Message msg = null;

			try {
				msg = parser.parseMessage(raw);

				if (CoAP.isRequest(msg.getRawCode())) {

					receiveRequest((Request) msg);

				} else if (CoAP.isResponse(msg.getRawCode())) {

					LOGGER.debug("{}multicast-receiver silently ignoring responses from {}", tag, raw.getEndpointContext());

				} else if (CoAP.isEmptyMessage(msg.getRawCode())) {

					LOGGER.debug("{}multicast-receiver silently ignoring empty messages from {}", tag, raw.getEndpointContext());

				} else {
					LOGGER.debug("{}multicast-receiver silently ignoring non-CoAP message from {}", tag, raw.getEndpointContext());
				}

			} catch (MessageFormatException e) {

				// ignore erroneous messages that are not transmitted reliably
				LOGGER.debug("{}multicast-receiver discarding malformed message from [{}]", tag, raw.getEndpointContext());
			}
		}

		private void receiveRequest(final Request request) {

			// set request attributes from raw data
			request.setScheme(scheme);
			InetSocketAddress in = connector.getAddress();
			if (NetworkInterfacesUtil.isMultiAddress(in.getAddress())) {
				request.setDestinationContext(new AddressEndpointContext(in));
			} else {
				LOGGER.warn("{}multicast-receiver is not in multicast group, drop request {}", tag, request);
				return;
			}

			if (!started) {
				LOGGER.debug("{}not running, drop request {}", tag, request);
				return;
			}

			/*
			 * Logging here causes significant performance loss. If necessary,
			 * add an interceptor that logs the messages, e.g., the
			 * MessageTracer.
			 */
			notifyReceive(interceptors, request);

			// MessageInterceptor might have canceled
			if (!request.isCanceled()) {
				matcher.receiveRequest(request, endpointStackReceiver);
			}
		}
	}

	/**
	 * Base message callback implementation. Forwards callbacks to
	 * {@link Message}
	 */
	private static abstract class SendingCallback<T extends Message> implements MessageCallback {

		/**
		 * Related send message.
		 */
		private final T message;

		/**
		 * Creates a new message callback.
		 * 
		 * @param message related send message
		 * @throws NullPointerException if message is {@code null}
		 */
		public SendingCallback(final T message) {
			if (null == message) {
				throw new NullPointerException("message must not be null");
			}
			this.message = message;
		}

		@Override
		public void onConnecting() {
			message.onConnecting();
		}

		@Override
		public void onDtlsRetransmission(int flight) {
			message.onDtlsRetransmission(flight);
		}

		@Override
		public final void onContextEstablished(EndpointContext context) {
			long now = ClockUtil.nanoRealtime();
			message.setNanoTimestamp(now);
			onContextEstablished(context, now);
		}

		@Override
		public void onSent() {
			if (message.isSent()) {
				message.setDuplicate(true);
			}
			message.setSent(true);
			notifyPostProcess(message);
		}

		@Override
		public void onError(Throwable error) {
			message.setSendError(error);
			notifyPostProcess(message);
		}

		protected abstract void notifyPostProcess(T message);

		protected void onContextEstablished(EndpointContext context, long nanoTimestamp) {
		}
	}

	/**
	 * Message callback for exchanges. Additional calls
	 * {@link Exchange#setEndpointContext(EndpointContext)}.
	 */
	private static abstract class ExchangeCallback<T extends Message> extends SendingCallback<T> {

		/**
		 * Exchange of send message.
		 */
		protected final Exchange exchange;

		/**
		 * Create a new instance.
		 * 
		 * @param exchange related exchange
		 * @param message related message
		 * @throws NullPointerException if exchange or request is {@code null}
		 */
		public ExchangeCallback(final Exchange exchange, final T message) {
			super(message);
			if (null == exchange) {
				throw new NullPointerException("exchange must not be null");
			}
			this.exchange = exchange;
		}

		@Override
		protected void onContextEstablished(EndpointContext context, long nanoTimestamp) {
			exchange.setSendNanoTimestamp(nanoTimestamp == 0 ? -1 : nanoTimestamp);
			exchange.setEndpointContext(context);
		}
	}

	@Override
	public void cancelObservation(Token token) {
		matcher.cancelObserve(token);
	}

	/**
	 * Execute the specified task on the endpoint's executor (protocol stage).
	 *
	 * @param task the task
	 */
	private void runInProtocolStage(final Runnable task) {
		try {
			executor.execute(new Runnable() {

				@Override
				public void run() {
					try {
						task.run();
					} catch (final Throwable t) {
						LOGGER.error("{}exception in protocol stage thread: {}", tag, t.getMessage(), t);
					}
				}
			});
		} catch (RejectedExecutionException e) {
			LOGGER.debug("{} execute:", tag, e);
		}
	}

	/**
	 * Builder to create CoapEndpoints.
	 */
	public static class Builder {

		/**
		 * Network configuration to be applied.
		 * 
		 * @see #setNetworkConfig(NetworkConfig)
		 */
		private NetworkConfig config = null;
		/**
		 * Socket address of interface to bind. Alternatively used with
		 * {@link #connector}.
		 * 
		 * @see #setInetSocketAddress(InetSocketAddress)
		 * @see #setPort(int)
		 */
		private InetSocketAddress bindAddress = null;
		/**
		 * Indicate to apply configuration to connector. Requires a
		 * {@link UDPConnector}.
		 * 
		 * @see #setConnector(Connector)
		 * @see #setConnectorWithAutoConfiguration(UDPConnector)
		 */
		private boolean applyConfiguration = true;
		/**
		 * Connector for communication.
		 * 
		 * @see #setConnector(Connector)
		 * @see #setConnectorWithAutoConfiguration(UDPConnector)
		 */
		private Connector connector = null;
		/**
		 * Observation store for endpoint.
		 * 
		 * @see #setObservationStore(ObservationStore)
		 */
		private ObservationStore observationStore = null;
		/**
		 * Message exchange store for endpoint.
		 * 
		 * @see #setMessageExchangeStore(MessageExchangeStore)
		 */
		private MessageExchangeStore exchangeStore = null;
		/**
		 * Endpoint context matcher for endpoint.
		 * 
		 * @see #setEndpointContextMatcher(EndpointContextMatcher)
		 */
		private EndpointContextMatcher endpointContextMatcher = null;
		/**
		 * Token generator for endpoint.
		 */
		private TokenGenerator tokenGenerator;
		/**
		 * Coap-stack-factory to create coap-stack.
		 */
		private CoapStackFactory coapStackFactory;
		/**
		 * Serializer to convert messages to datagrams.
		 */
		private DataSerializer serializer;
		/**
		 * Parser to convert datagrams to messages.
		 */
		private DataParser parser;
		/**
		 * Logging tag.
		 */
		private String tag;
		/**
		 * Additional argument for custom coap stack.
		 */
		private Object customStackArgument;

		/**
		 * Create new builder.
		 */
		public Builder() {
		}

		/**
		 * Set network configuration to be used for this endpoint. If not
		 * provided, {@link NetworkConfig#getStandard()} is used.
		 * 
		 * Provides a fluent API to chain setters.
		 * 
		 * @param config network configuration
		 * @return this
		 * @see #config
		 */
		public Builder setNetworkConfig(NetworkConfig config) {
			this.config = config;
			return this;
		}

		/**
		 * Set port to bind the connector to.
		 * 
		 * Uses any interface when creating the {@link InetSocketAddress}.
		 * Creates a {@link UDPConnector} for the provided address on
		 * {@link #build()}. The {@link #bindAddress} could be defined at most
		 * once, so only one setter of {@link #setPort(int)},
		 * {@link #setInetSocketAddress(InetSocketAddress)}, or
		 * {@link #setConnector(Connector)}, or
		 * {@link #setConnectorWithAutoConfiguration(UDPConnector)} could be
		 * used.
		 * 
		 * Not recommended for the server side on IPv6 systems with multiple
		 * addresses assigned to single network interfaces.
		 * 
		 * Provides a fluent API to chain setters.
		 * 
		 * @param port port number for socket. A port number of {@code 0} will
		 *            let the system pick up an ephemeral port
		 * @return this
		 * @throws IllegalStateException if {@link #bindAddress} is already
		 *             defined
		 * @see #bindAddress
		 * @see #connector
		 */
		public Builder setPort(int port) {
			if (this.bindAddress != null || this.connector != null) {
				throw new IllegalArgumentException("bind address already defined!");
			}
			this.bindAddress = new InetSocketAddress(port);
			return this;
		}

		/**
		 * Set local address to bind the connector to.
		 * 
		 * Creates a {@link UDPConnector} for the provided address on
		 * {@link #build()}. The {@link #bindAddress} could be defined at most
		 * once, so only one setter of {@link #setPort(int)},
		 * {@link #setInetSocketAddress(InetSocketAddress)}, or
		 * {@link #setConnector(Connector)}, or
		 * {@link #setConnectorWithAutoConfiguration(UDPConnector)} could be
		 * used.
		 * 
		 * Note: using IPv6 interfaces with multiple addresses including
		 * permanent and temporary (with potentially several different prefixes)
		 * currently causes issues on the server side. The outgoing traffic in
		 * response to incoming may select a different source address than the
		 * incoming destination address. To overcome this, please ensure that
		 * the 'any address' is not used on the server side and a separate
		 * CoapEndpoint is created for each address to receive incoming traffic.
		 * 
		 * Provides a fluent API to chain setters.
		 * 
		 * @param address local address to bin to
		 * @return this
		 * @throws IllegalStateException if {@link #bindAddress} is already
		 *             defined
		 * @see #bindAddress
		 * @see #connector
		 */
		public Builder setInetSocketAddress(InetSocketAddress address) {
			if (this.bindAddress != null || this.connector != null) {
				throw new IllegalArgumentException("bind address already defined!");
			}
			this.bindAddress = address;
			return this;
		}

		/**
		 * Set connector to be used by endpoint.
		 * 
		 * The {@link #bindAddress} could be defined at most once, so only one
		 * setter of {@link #setPort(int)},
		 * {@link #setInetSocketAddress(InetSocketAddress)},
		 * {@link #setConnector(Connector)}, or
		 * {@link #setConnectorWithAutoConfiguration(UDPConnector)} could be
		 * used. Intended to be used with already configured connectors,
		 * therefore doesn't apply network configuration to connector.
		 * 
		 * Provides a fluent API to chain setters.
		 * 
		 * @param connector connector to be used
		 * @return this
		 * @throws IllegalStateException if {@link #bindAddress} is already
		 *             defined
		 * @see #bindAddress
		 * @see #connector
		 */
		public Builder setConnector(Connector connector) {
			if (this.bindAddress != null || this.connector != null) {
				throw new IllegalArgumentException("bind address already defined!");
			}
			this.connector = connector;
			this.applyConfiguration = false;

			return this;
		}

		/**
		 * Set connector to be configured and used by endpoint .
		 * 
		 * The {@link #bindAddress} could be defined at most once, so only one
		 * setter of {@link #setPort(int)},
		 * {@link #setInetSocketAddress(InetSocketAddress)}, or
		 * {@link #setConnector(Connector)}, or
		 * {@link #setConnectorWithAutoConfiguration(UDPConnector)} could be
		 * used.
		 * 
		 * Provides a fluent API to chain setters.
		 * 
		 * @param connector connector to be used
		 * @return this
		 * @throws IllegalStateException if {@link #bindAddress} is already
		 *             defined
		 * @throws IllegalArgumentException if applyConfiguration is
		 *             {@code true}, but the connector is not a
		 *             {@link UDPConnector}
		 * @see #bindAddress
		 * @see #connector
		 */
		public Builder setConnectorWithAutoConfiguration(UDPConnector connector) {
			if (this.bindAddress != null || this.connector != null) {
				throw new IllegalArgumentException("bind address already defined!");
			}
			this.connector = connector;

			return this;
		}

		/**
		 * Set observation store.
		 * 
		 * Provides a fluent API to chain setters.
		 * 
		 * @param store observation store
		 * @return this
		 * @see #observationStore
		 */
		public Builder setObservationStore(ObservationStore store) {
			this.observationStore = store;
			return this;
		}

		/**
		 * Set message exchange store.
		 * 
		 * Provides a fluent API to chain setters.
		 * 
		 * @param exchangeStore message exchange store
		 * @return this
		 * @see #exchangeStore
		 */
		public Builder setMessageExchangeStore(MessageExchangeStore exchangeStore) {
			this.exchangeStore = exchangeStore;
			return this;
		}

		/**
		 * Set endpoint context matcher.
		 * 
		 * Provides a fluent API to chain setters.
		 * 
		 * @param endpointContextMatcher endpoint context matcher
		 * @return this
		 * @see #endpointContextMatcher
		 */
		public Builder setEndpointContextMatcher(EndpointContextMatcher endpointContextMatcher) {
			this.endpointContextMatcher = endpointContextMatcher;
			return this;
		}

		/**
		 * Set token generator.
		 * 
		 * Provides a fluent API to chain setters.
		 * 
		 * @param tokenGenerator token generator
		 * @return this
		 * @see #tokenGenerator
		 */
		public Builder setTokenGenerator(TokenGenerator tokenGenerator) {
			this.tokenGenerator = tokenGenerator;
			return this;
		}

		/**
		 * Set coap-stack-factory.
		 * 
		 * Provides a fluent API to chain setters.
		 * 
		 * @param coapStackFactory factory for coap-stack
		 * @return this
		 * @see #coapStackFactory
		 */
		public Builder setCoapStackFactory(CoapStackFactory coapStackFactory) {
			this.coapStackFactory = coapStackFactory;
			return this;
		}

		/**
		 * Set custom data serializer and parser.
		 * 
		 * @param serializer custom data serializer
		 * @param parser custom data parser
		 * @return this
		 * @since 2.6
		 */
		public Builder setDataSerializerAndParser(DataSerializer serializer, DataParser parser) {
			this.serializer = serializer;
			this.parser = parser;
			return this;
		}

		/**
		 * Set logging tag.
		 * 
		 * @param tag logging tag. Defautls to connector's scheme.
		 * @return this
		 */
		public Builder setLoggingTag(String tag) {
			this.tag = tag;
			return this;
		}

		/**
		 * Set additional argument for custom coap stack.
		 * 
		 * @param customStackArgument argument for custom stack, if required.
		 *            {@code null} for standard stacks, or if the custom stack
		 *            doesn't require specific arguments. My be a {@link Map},
		 *            if multiple arguments are required.
		 * @return this
		 * @see #customStackArgument
		 */
		public Builder setCustomCoapStackArgument(Object customStackArgument) {
			this.customStackArgument = customStackArgument;
			return this;
		}

		/**
		 * Create {@link CoapEndpoint} using the provided parameter or defaults.
		 * 
		 * @return new endpoint
		 */
		public CoapEndpoint build() {
			if (config == null) {
				config = NetworkConfig.getStandard();
			}
			if (connector == null) {
				if (bindAddress == null) {
					bindAddress = new InetSocketAddress(0);
				}
				connector = new UDPConnector(bindAddress);
			}
			if (tokenGenerator == null) {
				tokenGenerator = new RandomTokenGenerator(config);
			}
			if (observationStore == null) {
				observationStore = new InMemoryObservationStore(config);
			}
			if (endpointContextMatcher == null) {
				endpointContextMatcher = EndpointContextMatcherFactory.create(connector, config);
			}
			if (tag == null) {
				tag = CoAP.getSchemeForProtocol(connector.getProtocol());
			}
			tag = StringUtil.normalizeLoggingTag(tag);
			if (exchangeStore == null) {
				exchangeStore = new InMemoryMessageExchangeStore(tag, config, tokenGenerator,
						endpointContextMatcher);
			}
			if (coapStackFactory == null) {
				coapStackFactory = getDefaultCoapStackFactory();
			}
			return new CoapEndpoint(connector, applyConfiguration, config, tokenGenerator, observationStore,
					exchangeStore, endpointContextMatcher, serializer, parser, tag, coapStackFactory, customStackArgument);
		}
	}

	/**
	 * Standard coap-stack-factory.
	 * 
	 * This will be also the default, if no other default gets provided with
	 * {@link #setDefaultCoapStackFactory(CoapStackFactory)}. If an other
	 * default factory is used, this one may be used to build a standard
	 * coap-stack on demand.
	 */
	public static final CoapStackFactory STANDARD_COAP_STACK_FACTORY = new CoapStackFactory() {

		public CoapStack createCoapStack(String protocol, NetworkConfig config, Outbox outbox, Object customStackArgument) {
			if (CoAP.isTcpProtocol(protocol)) {
				return new CoapTcpStack(config, outbox);
			} else {
				return new CoapUdpStack(config, outbox);
			}
		}
	};

	/**
	 * Default coap-stack-factory. Intended to be set only once.
	 */
	private static CoapStackFactory defaultCoapStackFactory;

	/**
	 * Get default coap-stack-factory. Setup default implementation, if factory
	 * is not provided before.
	 * 
	 * @return default coap-stack-factory
	 */
	private static synchronized CoapStackFactory getDefaultCoapStackFactory() {
		if (defaultCoapStackFactory == null) {
			defaultCoapStackFactory = STANDARD_COAP_STACK_FACTORY;
		}
		return defaultCoapStackFactory;
	}

	/**
	 * Setup default coap-stack-factory.
	 * 
	 * Intended to be setup initially. Therefore a {@link IllegalStateException}
	 * will be caused, if called twice or after creating the first endpoint.
	 * 
	 * @param newFactory new coap-stack-factory
	 * @throws NullPointerException if new factory is {@code null}
	 * @throws IllegalStateException if factory is already set.
	 */
	public static synchronized void setDefaultCoapStackFactory(CoapStackFactory newFactory) {
		if (defaultCoapStackFactory != null) {
			throw new IllegalStateException("Default coap-stack-factory already set!");
		}
		if (newFactory == null) {
			throw new NullPointerException("new coap-stack-factory must not be null!");
		}
		defaultCoapStackFactory = newFactory;
	}

}
