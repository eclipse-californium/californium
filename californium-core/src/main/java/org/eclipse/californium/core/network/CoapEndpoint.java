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
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.CoAPMessageFormatException;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageFormatException;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.EndpointManager.ClientMessageDeliverer;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageInterceptor;
import org.eclipse.californium.core.network.serialization.DataParser;
import org.eclipse.californium.core.network.serialization.DataSerializer;
import org.eclipse.californium.core.network.serialization.TcpDataParser;
import org.eclipse.californium.core.network.serialization.TcpDataSerializer;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.core.network.serialization.UdpDataSerializer;
import org.eclipse.californium.core.network.stack.BlockwiseLayer;
import org.eclipse.californium.core.network.stack.CoapStack;
import org.eclipse.californium.core.network.stack.CoapTcpStack;
import org.eclipse.californium.core.network.stack.CoapUdpStack;
import org.eclipse.californium.core.observe.InMemoryObservationStore;
import org.eclipse.californium.core.observe.NotificationListener;
import org.eclipse.californium.core.observe.ObservationStore;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.MessageCallback;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
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
 * rsts to them. MessageInterceptors receive every incoming and outgoing
 * message. By default, only one interceptor is used to log messages.
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
 */
public class CoapEndpoint implements Endpoint {

	/** the logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(CoapEndpoint.class.getCanonicalName());

	/** The stack of layers that make up the CoAP protocol */
	protected CoapStack coapstack;

	/** The connector over which the endpoint connects to the network */
	private final Connector connector;

	private final String scheme;

	/** The configuration of this endpoint */
	protected final NetworkConfig config;

	/** The matcher which matches incoming responses, akcs and rsts an exchange */
	private final Matcher matcher;

	/** Serializer to convert messages to datagrams. */
	private final DataSerializer serializer;

	/** Parser to convert datagrams to messages. */
	private final DataParser parser;

	/** The executor to run tasks for this endpoint and its layers */
	private ExecutorService executor;

	/** Indicates if the endpoint has been started */
	private boolean started;

	/** The list of endpoint observers (has nothing to do with CoAP observe relations) */
	private List<EndpointObserver> observers = new CopyOnWriteArrayList<>();

	/** The list of interceptors */
	private List<MessageInterceptor> interceptors = new CopyOnWriteArrayList<>();

	/** The list of Notification listener (use for CoAP observer relations) */
	private List<NotificationListener> notificationListeners = new CopyOnWriteArrayList<>();

	/**
	 * Creates a new <em>coap</em> endpoint using default configuration.
	 * <p>
	 * The endpoint will bind to all network interfaces and listen on an ephemeral port.
	 */
	@Deprecated
	public CoapEndpoint() {
		this(0);
	}

	/**
	 * Creates a new <em>coap</em> endpoint using default configuration.
	 * <p>
	 * The endpoint will bind to all network interfaces.
	 *
	 * @param port The port to listen on.
	 */
	@Deprecated
	public CoapEndpoint(final int port) {
		this(new InetSocketAddress(port));
	}

	/**
	 * Creates a new <em>coap</em> endpoint using default configuration.
	 *
	 * @param address The IP address and port to bind to.
	 */
	@Deprecated
	public CoapEndpoint(final InetSocketAddress address) {
		this(address, NetworkConfig.getStandard());
	}

	/**
	 * Creates a new <em>coap</em> endpoint for a configuration.
	 * <p>
	 * The endpoint will bind to all network interfaces and listen on an ephemeral port.
	 * 
	 * @param config The configuration values to use.
	 */
	@Deprecated
	public CoapEndpoint(final NetworkConfig config) {
		this(new InetSocketAddress(0), config);
	}

	/**
	 * Creates a new <em>coap</em> endpoint for a port and configuration.
	 * <p>
	 * The endpoint will bind to all network interfaces and listen on an ephemeral port.
	 *
	 * @param port The port to listen on.
	 * @param config The configuration values to use.
	 */
	@Deprecated
	public CoapEndpoint(final int port, final NetworkConfig config) {
		this(new InetSocketAddress(port), config);
	}

	/**
	 * Creates a new <em>coap</em> endpoint for a configuration.
	 *
	 * @param address The IP address and port to bind to.
	 * @param config The configuration values to use.
	 */
	@Deprecated
	public CoapEndpoint(final InetSocketAddress address, final NetworkConfig config) {
		this(new UDPConnector(address), true, config, null, null, null, null, null);
	}

	/**
	 * Creates a new <em>coap</em> endpoint for a configuration and message exchange store.
	 *
	 * @param address The IP address and port to bind to.
	 * @param config The configuration values to use.
	 * @param exchangeStore The store to use for keeping track of message exchanges.
	 */
	@Deprecated
	public CoapEndpoint(final InetSocketAddress address, final NetworkConfig config,
			final MessageExchangeStore exchangeStore) {
		this(new UDPConnector(address), true, config, null, null, exchangeStore, null, null);
	}

	/**
	 * Creates a new endpoint for a connector and configuration.
	 * <p>
	 * The endpoint will support the connector's implemented scheme and will bind to
	 * the IP address and port the connector is configured for.
	 * 
	 * @param connector The connector to use.
	 * @param config The configuration values to use.
	 */
	@Deprecated
	public CoapEndpoint(final Connector connector, final NetworkConfig config) {
		this(connector, false, config, null, null, null, null, null);
	}

	/**
	 * Creates a new <em>coap</em> endpoint for a configuration and observation store.
	 * 
	 * @param address The IP address and port to bind to.
	 * @param config The configuration values to use.
	 * @param store The store to use for keeping track of observations initiated by this
	 *              endpoint.
	 */
	@Deprecated
	public CoapEndpoint(final InetSocketAddress address, final NetworkConfig config, final ObservationStore store) {
		this(new UDPConnector(address), true, config, null, store, null, null, null);
	}

	/**
	 * Creates a new endpoint for a connector, configuration, message exchange and observation store.
	 * <p>
	 * The endpoint will support the connector's implemented scheme and will bind to
	 * the IP address and port the connector is configured for.
	 *
	 * @param connector The connector to use.
	 * @param config The configuration values to use.
	 * @param store The store to use for keeping track of observations initiated by this
	 *              endpoint.
	 * @param exchangeStore The store to use for keeping track of message exchanges.
	 */
	@Deprecated
	public CoapEndpoint(Connector connector, NetworkConfig config, ObservationStore store,
			MessageExchangeStore exchangeStore) {
		this(connector, false, config, null, store, exchangeStore, null, null);
	}

	/**
	 * Creates a new endpoint for a connector, configuration, message exchange
	 * and observation store.
	 * <p>
	 * Intended to be called either by the {@link CoapEndpointBuilder} or a
	 * subclass constructor. The endpoint will support the connector's
	 * implemented scheme and will bind to the IP address and port the connector
	 * is configured for.
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
	 * @param coapStackFactory coap-stack-factory factory to create coap-stack
	 * @throws IllegalArgumentException if applyConfiguration is {@code true},
	 *             but the connector is not a {@link UDPConnector}
	 */
	protected CoapEndpoint(Connector connector, boolean applyConfiguration, NetworkConfig config,
			TokenGenerator tokenGenerator, ObservationStore store, MessageExchangeStore exchangeStore,
			EndpointContextMatcher endpointContextMatcher, CoapStackFactory coapStackFactory) {
		this.config = config;
		this.connector = connector;
		this.connector.setRawDataReceiver(new InboxImpl());
		this.scheme = CoAP.getSchemeForProtocol(connector.getProtocol());

		// when remove the deprecated constructors,
		// this checks and defaults maybe also removed
		if (tokenGenerator == null) {
			tokenGenerator = new RandomTokenGenerator(config);
		}
		if (coapStackFactory == null) {
			coapStackFactory = getDefaultCoapStackFactory();
		}
		MessageExchangeStore localExchangeStore = (null != exchangeStore) ? exchangeStore
				: new InMemoryMessageExchangeStore(config, tokenGenerator);
		ObservationStore observationStore = (null != store) ? store : new InMemoryObservationStore(config);
		if (null == endpointContextMatcher) {
			endpointContextMatcher = EndpointContextMatcherFactory.create(connector, config);
		}

		// keep for subclasses
		if (applyConfiguration) {
			if (connector instanceof UDPConnector) {
				UDPConnector udpConnector = (UDPConnector) connector;
				udpConnector.setReceiverThreadCount(config.getInt(NetworkConfig.Keys.NETWORK_STAGE_RECEIVER_THREAD_COUNT));
				udpConnector.setSenderThreadCount(config.getInt(NetworkConfig.Keys.NETWORK_STAGE_SENDER_THREAD_COUNT));

				udpConnector.setReceiveBufferSize(config.getInt(NetworkConfig.Keys.UDP_CONNECTOR_RECEIVE_BUFFER));
				udpConnector.setSendBufferSize(config.getInt(NetworkConfig.Keys.UDP_CONNECTOR_SEND_BUFFER));
				udpConnector.setReceiverPacketSize(config.getInt(NetworkConfig.Keys.UDP_CONNECTOR_DATAGRAM_SIZE));
			} else {
				throw new IllegalArgumentException("Connector must be a UDPConnector to use apply configuration!");
			}
		}

		final Executor exchangeExecutionHandler = new Executor() {

			@Override
			public void execute(Runnable command) {
				final Executor exchangeExecutor = executor;
				if (exchangeExecutor == null) {
					LOGGER.error("Executor not ready for exchanges!",
							new Throwable("exchange execution failed!"));
				} else {
					exchangeExecutor.execute(command);
				}
			}
		};

		this.connector.setEndpointContextMatcher(endpointContextMatcher);
		LOGGER.info("{} uses {}", getClass().getSimpleName(), endpointContextMatcher.getName());

		this.coapstack = coapStackFactory.createCoapStack(connector.getProtocol(), config, new OutboxImpl());

		if (CoAP.isTcpProtocol(connector.getProtocol())) {
			this.matcher = new TcpMatcher(config, new NotificationDispatcher(), tokenGenerator, observationStore,
					localExchangeStore, exchangeExecutionHandler, endpointContextMatcher);
			this.serializer = new TcpDataSerializer();
			this.parser = new TcpDataParser();
		} else {
			this.matcher = new UdpMatcher(config, new NotificationDispatcher(), tokenGenerator, observationStore,
					localExchangeStore, exchangeExecutionHandler, endpointContextMatcher);
			this.serializer = new UdpDataSerializer();
			this.parser = new UdpDataParser();
		}
	}

	@Override
	public synchronized void start() throws IOException {
		if (started) {
			LOGGER.debug("Endpoint at {} is already started", getUri());
			return;
		}

		if (!this.coapstack.hasDeliverer()) {
			setMessageDeliverer(new ClientMessageDeliverer());
		}

		if (this.executor == null) {
			LOGGER.info("Endpoint [{}] requires an executor to start, using default single-threaded daemon executor", getUri());

			// in production environments the executor should be set to a multi threaded version
			// in order to utilize all cores of the processor
			setExecutor(ExecutorsUtil.newSingleThreadScheduledExecutor(
					new DaemonThreadFactory("CoapEndpoint-" + connector + '#'))); //$NON-NLS-1$
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
					executor.shutdown();
				}
			});
		}

		try {
			LOGGER.debug("Starting endpoint at {}", getUri());

			started = true;
			matcher.start();
			connector.start();
			for (EndpointObserver obs : observers) {
				obs.started(this);
			}
			LOGGER.info("Started endpoint at {}", getUri());
		} catch (IOException e) {
			// free partially acquired resources
			stop();
			throw e;
		}
	}

	@Override
	public synchronized void stop() {
		if (!started) {
			LOGGER.info("Endpoint at {} is already stopped", getUri());
		} else {
			LOGGER.info("Stopping endpoint at {}", getUri());
			started = false;
			connector.stop();
			matcher.stop();
			for (EndpointObserver obs : observers) {
				obs.stopped(this);
			}
		}
	}

	@Override
	public synchronized void destroy() {
		LOGGER.info("Destroying endpoint at {}", getUri());
		if (started) {
			stop();
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
	public synchronized boolean isStarted() {
		return started;
	}

	@Override
	public synchronized void setExecutor(final ScheduledExecutorService executor) {
		if (this.executor != executor) {
			if (started) {
				throw new IllegalStateException("endpoint already started!");
			}
			this.executor = executor;
			this.coapstack.setExecutor(executor);
		}
	}

	@Override
	public void addNotificationListener(final NotificationListener lis) {
		notificationListeners.add(lis);
	}

	@Override
	public void removeNotificationListener(final NotificationListener lis) {
		notificationListeners.remove(lis);
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
	public void sendRequest(final Request request) {
		if (!started) {
			request.cancel();
			return;
		}
		// create context, if not already set
		request.prepareDestinationContext();
		final Exchange exchange = new Exchange(request, Origin.LOCAL, executor);
		exchange.execute(new Runnable() {

			@Override
			public void run() {
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
		if (exchange.checkOwner()) {
			// send response while processing exchange.
			coapstack.sendResponse(exchange, response);
		} else {
			exchange.execute(new Runnable() {
				@Override
				public void run() {
					if (exchange.getRequest().getOptions().hasObserve()) {
						// observe- or cancel-observe-requests may have multiple responses
						// when observes are finished, the last response has no longer an
						// observe option. Therefore check the request for it.
						exchange.retransmitResponse();
					}
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
		URI uri = null;
		try {
			InetSocketAddress socketAddress = getAddress();
			String scheme = CoAP.getSchemeForProtocol(connector.getProtocol());
			String host = socketAddress.getAddress().getHostAddress();
			try {
				uri = new URI(scheme, null, host, socketAddress.getPort(), null, null, null);
			} catch (URISyntaxException e) {
				try {
					// workaround for openjdk bug JDK-8199396.
					// some characters are not supported for the ipv6 scope.
					host = host.replaceAll("[-._~]", "");
					uri = new URI(scheme, null, host, socketAddress.getPort(), null, null, null);
				} catch (URISyntaxException e2) {
					// warn with the original violation
					LOGGER.warn("URI", e);
				}
			}
		} catch (IllegalArgumentException e) {
			LOGGER.warn("URI", e);
		}
		return uri;
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

			for (MessageInterceptor messageInterceptor : interceptors) {
				messageInterceptor.sendRequest(request);
			}

			request.setReadyToSend();
			if (!started) {
				request.cancel();
			}
			// Request may have been canceled already, e.g. by one of the interceptors
			// or client code
			if (request.isCanceled()) {

				// make sure we do necessary house keeping, e.g. removing the exchange from
				// ExchangeStore to avoid memory leak
				// The Exchange may already have been completed implicitly by client code
				// invoking Request.cancel().
				// However, that might have happened BEFORE the exchange got registered with the
				// ExchangeStore. So, to make sure that we do not leak memory we complete the
				// Exchange again here, triggering the "housekeeping" functionality in the Matcher
				exchange.executeComplete();

			} else {
				RawData message = serializer.serializeRequest(request, new ExchangeCallback(exchange, request));
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
			for (MessageInterceptor interceptor : interceptors) {
				interceptor.sendResponse(response);
			}
			response.setReadyToSend();

			if (!started) {
				response.cancel();
			}

			// MessageInterceptor might have canceled
			if (response.isCanceled()) {
				if (null != exchange) {
					exchange.executeComplete();
				}
			} else {
				connector.send(serializer.serializeResponse(response, new ExchangeCallback(exchange, response)));
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
			for (MessageInterceptor interceptor : interceptors) {
				interceptor.sendEmptyMessage(message);
			}
			message.setReadyToSend();

			if (!started) {
				message.cancel();
			}

			// MessageInterceptor might have canceled
			if (message.isCanceled()) {
				if (null != exchange) {
					exchange.executeComplete();
				}
			} else if (exchange != null) {
				connector.send(serializer.serializeEmptyMessage(message, new ExchangeCallback(exchange, message)));
			} else {
				connector.send(serializer.serializeEmptyMessage(message, new SendingCallback(message)));
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
					LOGGER.debug("silently ignoring non-CoAP message from {}", raw.getEndpointContext());
				}

			} catch (CoAPMessageFormatException e) {

				if (e.isConfirmable() && e.hasMid()) {
					// reject erroneous reliably transmitted message as mandated by CoAP spec
					// https://tools.ietf.org/html/rfc7252#section-4.2
					reject(raw, e);
					LOGGER.debug("rejected malformed message from [{}], reason: {}",
							raw.getEndpointContext(), e.getMessage());
				} else {
					// ignore erroneous messages that are not transmitted reliably
					LOGGER.debug("discarding malformed message from [{}]", raw.getEndpointContext());
				}
			} catch (MessageFormatException e) {

				// ignore erroneous messages that are not transmitted reliably
				LOGGER.debug("discarding malformed message from [{}]", raw.getEndpointContext());
			}
		}

		private void reject(final RawData raw, final CoAPMessageFormatException cause) {

			// Generate RST
			EmptyMessage rst = new EmptyMessage(Type.RST);
			rst.setMID(cause.getMid());
			rst.setDestinationContext(raw.getEndpointContext());

			coapstack.sendEmptyMessage(null, rst);
		}

		private void reject(final Message message) {
			EmptyMessage rst = EmptyMessage.newRST(message);
			coapstack.sendEmptyMessage(null, rst);
		}

		private void receiveRequest(final Request request) {

			// set request attributes from raw data
			request.setScheme(scheme);

			if (!started) {
				LOGGER.debug("not running, drop request {}", request);
				return;
			}

			/* 
			 * Logging here causes significant performance loss.
			 * If necessary, add an interceptor that logs the messages,
			 * e.g., the MessageTracer.
			 */
			for (MessageInterceptor interceptor : interceptors) {
				interceptor.receiveRequest(request);
			}

			// MessageInterceptor might have canceled
			if (!request.isCanceled()) {
				final Exchange exchange = matcher.receiveRequest(request);
				if (exchange != null) {
					exchange.execute(new Runnable() {

						@Override
						public void run() {
							exchange.setEndpoint(CoapEndpoint.this);
							coapstack.receiveRequest(exchange, request);
						}
					});
				}
			}
		}

		private void receiveResponse(final Response response) {

			/* 
			 * Logging here causes significant performance loss.
			 * If necessary, add an interceptor that logs the messages,
			 * e.g., the MessageTracer.
			 */
			for (MessageInterceptor interceptor : interceptors) {
				interceptor.receiveResponse(response);
			}

			// MessageInterceptor might have canceled
			if (!response.isCanceled()) {
				final Exchange exchange = matcher.receiveResponse(response);
				if (exchange != null) {
					exchange.execute(new Runnable() {

						@Override
						public void run() {
							// entered serial execution.
							// recheck, if the response still match the exchange
							// and the exchange is not changed in the meantime
							if (exchange.checkCurrentResponse(response)) {
								exchange.setEndpoint(CoapEndpoint.this);
								response.setRTT(exchange.calculateRTT());
								coapstack.receiveResponse(exchange, response);
							} else if (!response.isDuplicate() && response.getType() != Type.ACK) {
								LOGGER.debug("rejecting not longer matchable response from {}",
										response.getSourceContext());
								// reject(response);
							} else {
								LOGGER.debug("not longer matched response {}", response);
							}
						}
					});
				} else if (response.getType() != Type.ACK && response.hasMID()) {
					// reject only messages with MID, ignore for TCP
					LOGGER.debug("rejecting unmatchable response from {}", response.getSourceContext());
					reject(response);
				}
			}
		}

		private void receiveEmptyMessage(final EmptyMessage message) {

			/* 
			 * Logging here causes significant performance loss.
			 * If necessary, add an interceptor that logs the messages,
			 * e.g., the MessageTracer.
			 */
			for (MessageInterceptor interceptor : interceptors) {
				interceptor.receiveEmptyMessage(message);
			}

			// MessageInterceptor might have canceled
			if (!message.isCanceled()) {
				// CoAP Ping
				if ((message.getType() == Type.CON || message.getType() == Type.NON) && message.hasMID()) {
					LOGGER.debug("responding to ping from {}", message.getSourceContext());
					reject(message);
				} else {
					final Exchange exchange = matcher.receiveEmptyMessage(message);
					if (exchange != null) {
						exchange.execute(new Runnable() {

							@Override
							public void run() {
								// entered serial execution.
								// recheck, it the empty message still match the exchange
								// and the exchange is not changed in the meantime
								if (exchange.checkMID(message.getMID())) {
									exchange.setEndpoint(CoapEndpoint.this);
									coapstack.receiveEmptyMessage(exchange, message);
								}
							}
						});
					}
				}
			}
		}
	}

	/**
	 * Base message callback implementation. Forwards callbacks to
	 * {@link Message}
	 */
	private class SendingCallback implements MessageCallback {

		/**
		 * Related send message.
		 */
		private final Message message;

		/**
		 * Creates a new message callback.
		 * 
		 * @param message related send message
		 * @throws NullPointerException if message is {@code null}
		 */
		public SendingCallback(final Message message) {
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
		public void onContextEstablished(EndpointContext context) {

		}

		@Override
		public void onSent() {
			message.setSent(true);
		}

		@Override
		public void onError(Throwable error) {
			message.setSendError(error);
		}
	}

	/**
	 * Message callback for exchanges. Additional calls
	 * {@link Exchange#setEndpointContext(EndpointContext)}.
	 */
	private class ExchangeCallback extends SendingCallback {

		/**
		 * Exchange of send message.
		 */
		private final Exchange exchange;

		/**
		 * Create a new instance.
		 * 
		 * @param exchange related exchange
		 * @param message related message
		 * @throws NullPointerException if exchange or request is {@code null}
		 */
		public ExchangeCallback(final Exchange exchange, final Message message) {
			super(message);
			if (null == exchange) {
				throw new NullPointerException("exchange must not be null");
			}
			this.exchange = exchange;
		}

		@Override
		public void onContextEstablished(EndpointContext context) {
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
						LOGGER.error("exception in protocol stage thread: {}", t.getMessage(), t);
					}
				}
			});
		} catch (RejectedExecutionException e) {
			LOGGER.debug("{} execute:", this, e);
		}
	}

	/**
	 * Builder to create CoapEndpoints.
	 */
	public static class CoapEndpointBuilder {

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
		 * Create new builder.
		 */
		public CoapEndpointBuilder() {
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
		public CoapEndpointBuilder setNetworkConfig(NetworkConfig config) {
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
		 * Provides a fluent API to chain setters.
		 * 
		 * @param port port number for socket. A port number of {@code 0} will
		 *            let the system pick up an ephemeral port
		 * @return this
		 * @throws IllegalStateException, if {@link #bindAddress} is already
		 *             defined
		 * @see #bindAddress
		 * @see #connector
		 */
		public CoapEndpointBuilder setPort(int port) {
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
		 * Provides a fluent API to chain setters.
		 * 
		 * @param address local address to bin to
		 * @return this
		 * @throws IllegalStateException, if {@link #bindAddress} is already
		 *             defined
		 * @see #bindAddress
		 * @see #connector
		 */
		public CoapEndpointBuilder setInetSocketAddress(InetSocketAddress address) {
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
		 * @throws IllegalStateException, if {@link #bindAddress} is already
		 *             defined
		 * @see #bindAddress
		 * @see #connector
		 */
		public CoapEndpointBuilder setConnector(Connector connector) {
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
		 * @throws IllegalStateException, if {@link #bindAddress} is already
		 *             defined
		 * @throws IllegalArgumentException if applyConfiguration is
		 *             {@code true}, but the connector is not a
		 *             {@link UDPConnector}
		 * @see #bindAddress
		 * @see #connector
		 */
		public CoapEndpointBuilder setConnectorWithAutoConfiguration(UDPConnector connector) {
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
		public CoapEndpointBuilder setObservationStore(ObservationStore store) {
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
		public CoapEndpointBuilder setMessageExchangeStore(MessageExchangeStore exchangeStore) {
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
		public CoapEndpointBuilder setEndpointContextMatcher(EndpointContextMatcher endpointContextMatcher) {
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
		public CoapEndpointBuilder setTokenGenerator(TokenGenerator tokenGenerator) {
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
		public CoapEndpointBuilder setCoapStackFactory(CoapStackFactory coapStackFactory) {
			this.coapStackFactory = coapStackFactory;
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
			if (exchangeStore == null) {
				exchangeStore = new InMemoryMessageExchangeStore(config, tokenGenerator);
			}
			if (endpointContextMatcher == null) {
				endpointContextMatcher = EndpointContextMatcherFactory.create(connector, config);
			}
			if (coapStackFactory == null) {
				coapStackFactory = getDefaultCoapStackFactory();
			}
			return new CoapEndpoint(connector, applyConfiguration, config, tokenGenerator, observationStore,
					exchangeStore, endpointContextMatcher, coapStackFactory);
		}
	}

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
			defaultCoapStackFactory = new CoapStackFactory() {

				public CoapStack createCoapStack(String protocol, NetworkConfig config, Outbox outbox) {
					if (CoAP.isTcpProtocol(protocol)) {
						return new CoapTcpStack(config, outbox);
					} else {
						return new CoapUdpStack(config, outbox);
					}
				}
			};

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
