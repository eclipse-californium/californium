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
 *    Kai Hudalla - logging
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use Logger's message formatting instead of
 *                                                    explicit String concatenation
 *    Achim Kraus (Bosch Software Innovations GmbH) - use onResponse of CoapObserveRelation
 *                                                    to order notifies and responses.
 *    Achim Kraus (Bosch Software Innovations GmbH) - use new introduced failed()
 *                                                    instead of onReject() and
 *                                                    onTimeout().
 *    Achim Kraus (Bosch Software Innovations GmbH) - use effective endpoint for ping()
 *    Achim Kraus (Bosch Software Innovations GmbH) - destroy endpoint on shutdown
 *    Achim Kraus (Bosch Software Innovations GmbH) - apply source code formatter
 *    Achim Kraus (Bosch Software Innovations GmbH) - cleanup executor, endpoint
 *                                                    usage and javadoc. Forward
 *                                                    send error encapsulated as
 *                                                    RuntimeException.
 *                                                    (don't destroy endpoint on shutdown)
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - get default timeout from configuration
 *                                                    of effective endpoint
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 *    Achim Kraus (Bosch Software Innovations GmbH) - use endpoint context for
 *                                                    further requests
 *    Achim Kraus (Bosch Software Innovations GmbH) - use executors util
 *    Achim Kraus (Bosch Software Innovations GmbH) - reset endpoint context on setURI(). 
 *                                                    Ignore endpoint context of multicast
 *                                                    responses.
 ******************************************************************************/
package org.eclipse.californium.core;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.californium.elements.exception.ConnectorException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.LinkFormat;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.MessageObserver;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.observe.NotificationListener;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NamedThreadFactory;

/**
 * The Class CoapClient.
 */
public class CoapClient {

	/** The logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(CoapClient.class);

	/** The timeout. 
	 * 
	 * Request/Response timeout in milliseconds.
	 * If {@code null}, use EXCHANGE_LIFETIME of effective endpoint 
	 */
	private Long timeout;

	/** The destination URI */
	private String uri;

	/**
	 * Destination endpoint context.
	 * 
	 * If available, used as default for outgoing messages.
	 */
	private final AtomicReference<EndpointContext> destinationContext = new AtomicReference<EndpointContext>();

	/** The type used for requests (CON is default) */
	private Type type = Type.CON;

	private int blockwise = 0;

	/** The client-specific executor service. */
	private ExecutorService executor;

	/** Scheduled executor intended to be used for rare executing timers (e.g. cleanup tasks). */
	private volatile ScheduledThreadPoolExecutor secondaryExecutor;

	/**
	 * Indicate, it the client-specific executor service is detached, or
	 * shutdown with this client.
	 */
	private volatile boolean detachExecutor;

	/** The endpoint. */
	private Endpoint endpoint;

	/**
	 * Constructs a new CoapClient that has no destination URI yet.
	 */
	public CoapClient() {
		this("");
	}

	/**
	 * Constructs a new CoapClient that sends requests to the specified URI.
	 *
	 * @param uri the uri
	 */
	public CoapClient(String uri) {
		this.uri = uri;
	}

	/**
	 * Constructs a new CoapClient that sends request to the specified URI.
	 * 
	 * @param uri the uri
	 */
	public CoapClient(URI uri) {
		this(uri.toString());
	}

	/**
	 * Constructs a new CoapClient with the specified scheme, host, port and
	 * path as URI.
	 *
	 * @param scheme the scheme
	 * @param host the host
	 * @param port the port
	 * @param path the path
	 */
	public CoapClient(String scheme, String host, int port, String... path) {
		StringBuilder builder = new StringBuilder().append(scheme).append("://").append(host).append(":").append(port);
		for (String element : path) {
			builder.append("/").append(element);
		}
		this.uri = builder.toString();
	}

	/**
	 * Gets the maximum amount of time that synchronous method calls will block
	 * and wait.
	 * <p>
	 * If this property is {@code null}, the value is from configuration property
	 * {@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#EXCHANGE_LIFETIME}
	 * of the effective endpoint.
	 * 
	 * @return The timeout in milliseconds, or {@code null}.
	 */
	public Long getTimeout() {
		return timeout;
	}

	/**
	 * Sets the maximum amount of time that synchronous method calls will block
	 * and wait. Setting this property to 0 will result in methods waiting
	 * infinitely.
	 * <p>
	 * If this property is {@code null}, the value is from configuration
	 * property
	 * {@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#EXCHANGE_LIFETIME}
	 * of the effective endpoint.
	 * <p>
	 * Under normal circumstances this property should be set to at least the
	 * <em>EXCHANGE_LIFETIME</em> (the default) in order to account for
	 * potential retransmissions of request and response messages.
	 * <p>
	 * When running over DTLS and the client is behind a NAT firewall, requests
	 * may frequently fail (run into timeout) due to the fact that the client
	 * has been assigned a new IP address or port by the firewall and the peer
	 * can no longer associate this client's address with the original DTLS
	 * session. In such cases it might be worthwhile to set the value of this
	 * property to a smaller number so that the timeout is detected sooner and a
	 * new session can be negotiated. You may also consider to use the automatic
	 * session resumption to pass such a NAT firewall, see
	 * DtlsConnectorConfig.autoResumptionTimeoutMillis.
	 * 
	 * @param timeout The timeout in milliseconds. {@code null}, if
	 *            EXCHANGE_LIFETIME of effective endpoint should be used.
	 * @return This CoAP client for command chaining.
	 */
	public CoapClient setTimeout(Long timeout) {
		this.timeout = timeout;
		return this;
	}

	/**
	 * Gets the destination URI of this client.
	 *
	 * @return the uri
	 */
	public String getURI() {
		return uri;
	}

	/**
	 * Sets the destination URI of this client.
	 *
	 * Reset {@link #destinationContext} also.
	 * 
	 * @param uri the uri
	 * @return the CoAP client
	 */
	public CoapClient setURI(String uri) {
		this.destinationContext.set(null);
		this.uri = uri;
		return this;
	}

	/**
	 * Set destination endpoint context.
	 * 
	 * Provides a fluent API to chain setters.
	 * 
	 * @param peerContext destination endpoint context
	 * @return this CoapClient
	 */
	public CoapClient setDestinationContext(EndpointContext peerContext) {
		this.destinationContext.set(peerContext);
		return this;
	}

	/**
	 * Get destination endpoint context.
	 * 
	 * @return destination endpoint context. Maybe {@code null}, if not
	 *         available.
	 * @since 2.3
	 */
	public EndpointContext getDestinationContext() {
		return this.destinationContext.get();
	}

	/**
	 * Sets a single-threaded executor to this client.
	 * 
	 * All handlers will be invoked by this executor. Note that the client
	 * executor uses a user thread (not a daemon thread) that needs to be
	 * stopped to exit the program by calling {@link #shutdown()}.
	 *
	 * @return the CoAP client
	 * @throws IllegalStateException if executor is already set or used.
	 */
	public CoapClient useExecutor() {
		boolean failed = true;
		ExecutorService executor = ExecutorsUtil.newFixedThreadPool(1, new NamedThreadFactory("CoapClient(main)#")); //$NON-NLS-1$
		ScheduledThreadPoolExecutor secondaryExecutor = new ScheduledThreadPoolExecutor(1, new NamedThreadFactory("CoapClient(secondary)#"));
		synchronized (this) {
			if (this.executor == null && this.secondaryExecutor == null) {
				this.executor = executor;
				this.secondaryExecutor = secondaryExecutor;
				this.detachExecutor = false;
				failed = false;
			}
		}
		if (failed) {
			executor.shutdownNow();
			secondaryExecutor.shutdown();
			throw new IllegalStateException("Executor already set or used!");
		}

		// activates the executor so that this user thread starts
		// deterministically
		executor.execute(new Runnable() {

			public void run() {
				LOGGER.info("using a SingleThreadExecutor for the CoapClient");
			};
		});
		return this;
	}

	/**
	 * Sets the executor services for this client.
	 * 
	 * All handlers will be invoked by the main executor. The executors will shutdown
	 * on {@link #shutdown()}, if not detached.
	 * 
	 * @param executor the main executor service
	 * @param secondaryExecutor intended to be used for rare executing timers (e.g. cleanup tasks).
	 * @param detach {@code true}, if the executor is not shutdown on
	 *            {@link #shutdown()}, {@code false}, otherwise.
	 * @return the CoAP client
	 * @throws IllegalStateException if executor is already set or used.
	 * @throws NullPointerException if provided executors are null
	 */
	public CoapClient setExecutors(ExecutorService executor, ScheduledThreadPoolExecutor secondaryExecutor, boolean detach) {
		if (executor == null || secondaryExecutor == null) {
			throw new NullPointerException("Executors must not be null!");
		}
		boolean failed = true;
		synchronized (this) {
			if (this.executor == null && this.secondaryExecutor == null) {
				this.executor = executor;
				this.secondaryExecutor = secondaryExecutor;
				this.detachExecutor = detach;
				failed = false;
			}
		}
		if (failed) {
			throw new IllegalStateException("Executor already set or used!");
		}
		return this;
	}

	private synchronized ScheduledThreadPoolExecutor getSecondaryExecutor() {
		// Warning there is maybe a performance issue here, see : 
		// - https://en.wikipedia.org/wiki/Double-checked_locking#Usage_in_Java
		// - https://github.com/eclipse/californium/issues/1420
		if (secondaryExecutor == null) {
			secondaryExecutor = new ScheduledThreadPoolExecutor(1, new NamedThreadFactory("CoapClient(secondary)#"));
		}
		this.detachExecutor = false;

		return secondaryExecutor;
	}

	/**
	 * Gets the endpoint this client uses.
	 *
	 * @return the endpoint
	 */
	public synchronized Endpoint getEndpoint() {
		return endpoint;
	}

	/**
	 * Sets the endpoint this client is supposed to use.
	 * 
	 * The endpoint maybe shared among clients. Therefore {@link #shutdown()}
	 * doesn't close nor destroy it.
	 *
	 * @param endpoint the endpoint
	 * @return the CoAP client
	 */
	public CoapClient setEndpoint(Endpoint endpoint) {
		synchronized (this) {
			this.endpoint = endpoint;
		}
		if (!endpoint.isStarted()) {
			try {
				endpoint.start();
				LOGGER.info("started set client endpoint {}", endpoint.getAddress());
			} catch (IOException e) {
				LOGGER.error("could not set and start client endpoint", e);
			}

		}

		return this;
	}

	/**
	 * Let the client use Confirmable requests.
	 * 
	 * @return the CoAP client
	 */
	public CoapClient useCONs() {
		this.type = Type.CON;
		return this;
	}

	/**
	 * Let the client use Non-Confirmable requests.
	 * 
	 * @return the CoAP client
	 */
	public CoapClient useNONs() {
		this.type = Type.NON;
		return this;
	}

	/**
	 * Let the client use early negotiation for the blocksize (16, 32, 64, 128,
	 * 256, 512, or 1024). Other values will be matched to the closest logarithm
	 * dualis.
	 * 
	 * @param size the preferred block size
	 * @return the CoAP client
	 */
	public CoapClient useEarlyNegotiation(int size) {
		this.blockwise = size;
		return this;
	}

	/**
	 * Let the client use late negotiation for the block size (default).
	 * 
	 * @return the CoAP client
	 */
	public CoapClient useLateNegotiation() {
		this.blockwise = 0;
		return this;
	}

	/**
	 * Performs a CoAP ping using the default timeout for requests.
	 * 
	 * @return success of the ping
	 */
	public boolean ping() {
		return ping(this.timeout);
	}

	/**
	 * Performs a CoAP ping and gives up after the given number of milliseconds.
	 * 
	 * @param timeout the time to wait for a pong in ms
	 * @return success of the ping
	 */
	public boolean ping(long timeout) {
		return ping(new Long(timeout));
	}

	private boolean ping(Long timeout) {
		try {
			Request request = new Request(null, Type.CON);
			request.setToken(Token.EMPTY);
			assignClientUriIfEmpty(request);
			Endpoint outEndpoint = getEffectiveEndpoint(request);
			if (timeout == null) {
				timeout = outEndpoint.getConfig().getLong(NetworkConfig.Keys.EXCHANGE_LIFETIME);
			}
			send(request, outEndpoint).waitForResponse(timeout);
			return request.isRejected();
		} catch (InterruptedException e) {
			// waiting was interrupted, which is fine
		}
		return false;
	}

	public Set<WebLink> discover() throws ConnectorException, IOException {
		return discover(null);
	}

	public Set<WebLink> discover(String query) throws ConnectorException, IOException {
		Request discover = newGet();
		// set URI for scheme and authority, but then remove path and query
		assignClientUriIfEmpty(discover);
		discover.getOptions().clearUriPath().clearUriQuery().setUriPath("/.well-known/core");
		if (query != null) {
			discover.getOptions().setUriQuery(query);
		}
		CoapResponse links = synchronous(discover);

		// if no response, return null (e.g., timeout)
		if (links == null) {
			return null;
		}
		setDestinationContextFromResponse(links.advanced());

		// check if Link Format
		if (links.getOptions().getContentFormat() != MediaTypeRegistry.APPLICATION_LINK_FORMAT) {
			return Collections.emptySet();
		}
		// parse and return
		return LinkFormat.parse(links.getResponseText());
	}

	// Synchronous GET

	/**
	 * Sends a GET request and blocks until the response is available.
	 * 
	 * @return the CoAP response
	 * @throws ConnectorException if an issue specific to the connector occurred
	 * @throws IOException if any other issue (not specific to the connector) occurred
	 */
	public CoapResponse get() throws ConnectorException, IOException {
		Request request = newGet();
		assignClientUriIfEmpty(request);
		return synchronous(request);
	}

	/**
	 * Sends a GET request with the specified Accept option and blocks until the
	 * response is available.
	 * 
	 * @param accept the Accept option
	 * @return the CoAP response
	 * @throws ConnectorException if an issue specific to the connector occurred
	 * @throws IOException if any other issue (not specific to the connector) occurred
	 */
	public CoapResponse get(int accept) throws ConnectorException, IOException {
		Request request = newGet();
		request.getOptions().setAccept(accept);
		assignClientUriIfEmpty(request);
		return synchronous(request);
	}

	// Asynchronous GET

	/**
	 * Sends a GET request and invokes the specified handler when a response
	 * arrives.
	 *
	 * @param handler the Response handler
	 */
	public void get(CoapHandler handler) {
		Request request = newGet();
		assignClientUriIfEmpty(request);
		asynchronous(request, handler);
	}

	/**
	 * Sends aGET request with the specified Accept option and invokes the
	 * handler when a response arrives.
	 * 
	 * @param handler the Response handler
	 * @param accept the Accept option
	 */
	public void get(CoapHandler handler, int accept) {
		Request request = newGet();
		request.getOptions().setAccept(accept);
		assignClientUriIfEmpty(request);
		asynchronous(request, handler);
	}

	// Synchronous POST

	/**
	 * Sends a POST request with the specified payload and the specified content
	 * format option and blocks until the response is available.
	 * 
	 * @param payload the payload
	 * @param format the Content-Format
	 * @return the CoAP response
	 * @throws ConnectorException if an issue specific to the connector occurred
	 * @throws IOException if any other issue (not specific to the connector) occurred
	 */
	public CoapResponse post(String payload, int format) throws ConnectorException, IOException {
		Request request = newPost();
		request.setPayload(payload);
		request.getOptions().setContentFormat(format);
		assignClientUriIfEmpty(request);
		return synchronous(request);
	}

	/**
	 * Sends a POST request with the specified payload and the specified content
	 * format option and blocks until the response is available.
	 * 
	 * @param payload the payload
	 * @param format the Content-Format
	 * @return the CoAP response
	 * @throws ConnectorException if an issue specific to the connector occurred
	 * @throws IOException if any other issue (not specific to the connector) occurred
	 */
	public CoapResponse post(byte[] payload, int format) throws ConnectorException, IOException {
		Request request = newPost();
		request.setPayload(payload);
		request.getOptions().setContentFormat(format);
		assignClientUriIfEmpty(request);
		return synchronous(request);
	}

	/**
	 * Sends a POST request with the specified payload, the specified content
	 * format and the specified Accept option and blocks until the response is
	 * available.
	 * 
	 * @param payload the payload
	 * @param format the Content-Format
	 * @param accept the Accept option
	 * @return the CoAP response
	 * @throws ConnectorException if an issue specific to the connector occurred
	 * @throws IOException if any other issue (not specific to the connector) occurred
	 */
	public CoapResponse post(String payload, int format, int accept) throws ConnectorException, IOException {
		Request request = newPost();
		request.setPayload(payload);
		request.getOptions().setContentFormat(format);
		request.getOptions().setAccept(accept);
		assignClientUriIfEmpty(request);
		return synchronous(request);
	}

	/**
	 * Sends a POST request with the specified payload, the specified content
	 * format and the specified Accept option and blocks until the response is
	 * available.
	 * 
	 * @param payload the payload
	 * @param format the Content-Format
	 * @param accept the Accept option
	 * @return the CoAP response
	 * @throws ConnectorException if an issue specific to the connector occurred
	 * @throws IOException if any other issue (not specific to the connector) occurred
	 */
	public CoapResponse post(byte[] payload, int format, int accept) throws ConnectorException, IOException {
		Request request = newPost();
		request.setPayload(payload);
		request.getOptions().setContentFormat(format);
		request.getOptions().setAccept(accept);
		assignClientUriIfEmpty(request);
		return synchronous(request);
	}

	// Asynchronous POST

	/**
	 * Sends a POST request with the specified payload and the specified content
	 * format and invokes the specified handler when a response arrives.
	 * 
	 * @param handler the Response handler
	 * @param payload the payload
	 * @param format the Content-Format
	 */
	public void post(CoapHandler handler, String payload, int format) {
		Request request = newPost();
		request.setPayload(payload);
		request.getOptions().setContentFormat(format);
		assignClientUriIfEmpty(request);
		asynchronous(request, handler);
	}

	/**
	 * Sends a POST request with the specified payload and the specified content
	 * format and invokes the specified handler when a response arrives.
	 * 
	 * @param handler the Response handler
	 * @param payload the payload
	 * @param format the Content-Format
	 */
	public void post(CoapHandler handler, byte[] payload, int format) {
		Request request = newPost();
		request.setPayload(payload);
		request.getOptions().setContentFormat(format);
		assignClientUriIfEmpty(request);
		asynchronous(request, handler);
	}

	/**
	 * Sends a POST request with the specified payload, the specified content
	 * format and accept and invokes the specified handler when a response
	 * arrives.
	 * 
	 * @param handler the Response handler
	 * @param payload the payload
	 * @param format the Content-Format
	 * @param accept the Accept option
	 */
	public void post(CoapHandler handler, String payload, int format, int accept) {
		Request request = newPost();
		request.setPayload(payload);
		request.getOptions().setContentFormat(format);
		request.getOptions().setAccept(accept);
		assignClientUriIfEmpty(request);
		asynchronous(request, handler);
	}

	/**
	 * Sends a POST request with the specified payload, the specified content
	 * format and accept and invokes the specified handler when a response
	 * arrives.
	 * 
	 * @param handler the Response handler
	 * @param payload the payload
	 * @param format the Content-Format
	 * @param accept the Accept option
	 */
	public void post(CoapHandler handler, byte[] payload, int format, int accept) {
		Request request = newPost();
		request.setPayload(payload);
		request.getOptions().setContentFormat(format);
		request.getOptions().setAccept(accept);
		assignClientUriIfEmpty(request);
		asynchronous(request, handler);
	}

	// Synchronous PUT

	/**
	 * Sends a PUT request with payload and required Content-Format and blocks
	 * until the response is available.
	 *
	 * @param payload the payload
	 * @param format the Content-Format
	 * @return the CoAP response
	 * @throws ConnectorException if an issue specific to the connector occurred
	 * @throws IOException if any other issue (not specific to the connector) occurred
	 */
	public CoapResponse put(String payload, int format) throws ConnectorException, IOException {
		Request request = newPut();
		request.setPayload(payload);
		request.getOptions().setContentFormat(format);
		assignClientUriIfEmpty(request);
		return synchronous(request);
	}

	/**
	 * Sends a PUT request with payload and required Content-Format and blocks
	 * until the response is available.
	 *
	 * @param payload the payload
	 * @param format the Content-Format
	 * @return the CoAP response
	 * @throws ConnectorException if an issue specific to the connector occurred
	 * @throws IOException if any other issue (not specific to the connector) occurred
	 */
	public CoapResponse put(byte[] payload, int format) throws ConnectorException, IOException {
		Request request = newPut();
		request.setPayload(payload);
		request.getOptions().setContentFormat(format);
		assignClientUriIfEmpty(request);
		return synchronous(request);
	}

	/**
	 * Sends a PUT request with with the specified ETags in the If-Match option
	 * and blocks until the response is available.
	 * 
	 * @param payload the payload string
	 * @param format the Content-Format
	 * @param etags the ETags for the If-Match option
	 * @return the CoAP response
	 * @throws ConnectorException if an issue specific to the connector occurred
	 * @throws IOException if any other issue (not specific to the connector) occurred
	 */
	public CoapResponse putIfMatch(String payload, int format, byte[]... etags) throws ConnectorException, IOException {
		Request request = newPut();
		request.setPayload(payload);
		request.getOptions().setContentFormat(format);
		assignClientUriIfEmpty(request);
		ifMatch(request, etags);
		return synchronous(request);
	}

	/**
	 * Sends a PUT request with with the specified ETags in the If-Match option
	 * and blocks until the response is available.
	 * 
	 * @param payload the payload
	 * @param format the Content-Format
	 * @param etags the ETags for the If-Match option
	 * @return the CoAP response
	 * @throws ConnectorException if an issue specific to the connector occurred
	 * @throws IOException if any other issue (not specific to the connector) occurred
	 */
	public CoapResponse putIfMatch(byte[] payload, int format, byte[]... etags) throws ConnectorException, IOException {
		Request request = newPut();
		request.setPayload(payload);
		request.getOptions().setContentFormat(format);
		assignClientUriIfEmpty(request);
		ifMatch(request, etags);
		return synchronous(request);
	}

	/**
	 * Sends a PUT request with the If-None-Match option set and blocks until
	 * the response is available.
	 * 
	 * @param payload the payload string
	 * @param format the Content-Format
	 * @return the CoAP response
	 * @throws ConnectorException if an issue specific to the connector occurred
	 * @throws IOException if any other issue (not specific to the connector) occurred
	 */
	public CoapResponse putIfNoneMatch(String payload, int format) throws ConnectorException, IOException {
		Request request = newPut();
		request.setPayload(payload);
		request.getOptions().setContentFormat(format);
		request.getOptions().setIfNoneMatch(true);
		assignClientUriIfEmpty(request);
		return synchronous(request);
	}

	/**
	 * Sends a PUT request with the If-None-Match option set and blocks until
	 * the response is available.
	 * 
	 * @param payload the payload
	 * @param format the Content-Format
	 * @return the CoAP response
	 * @throws ConnectorException if an issue specific to the connector occurred
	 * @throws IOException if any other issue (not specific to the connector) occurred
	 */
	public CoapResponse putIfNoneMatch(byte[] payload, int format) throws ConnectorException, IOException {
		Request request = newPut();
		request.setPayload(payload);
		request.getOptions().setContentFormat(format);
		request.getOptions().setIfNoneMatch(true);
		assignClientUriIfEmpty(request);
		return synchronous(request);
	}

	// Asynchronous PUT

	/**
	 * Sends a PUT request with the specified payload and the specified content
	 * format and invokes the specified handler when a response arrives.
	 * 
	 * @param handler the Response handler
	 * @param payload the payload
	 * @param format the Content-Format
	 */
	public void put(CoapHandler handler, String payload, int format) {
		Request request = newPut();
		request.setPayload(payload);
		request.getOptions().setContentFormat(format);
		assignClientUriIfEmpty(request);
		asynchronous(request, handler);
	}

	/**
	 * Sends a PUT request with the specified payload and the specified content
	 * format and invokes the specified handler when a response arrives.
	 * 
	 * @param handler the Response handler
	 * @param payload the payload
	 * @param format the Content-Format
	 */
	public void put(CoapHandler handler, byte[] payload, int format) {
		Request request = newPut();
		request.setPayload(payload);
		request.getOptions().setContentFormat(format);
		assignClientUriIfEmpty(request);
		asynchronous(request, handler);
	}

	/**
	 * 
	 * @param handler the Response handler
	 * @param payload the payload
	 * @param format the Content-Format
	 * @param etags the ETags for the If-Match option
	 */
	public void putIfMatch(CoapHandler handler, String payload, int format, byte[]... etags) {
		Request request = newPut();
		request.setPayload(payload);
		request.getOptions().setContentFormat(format);
		assignClientUriIfEmpty(request);
		ifMatch(request, etags);
		asynchronous(request, handler);
	}

	/**
	 * 
	 * @param handler the Response handler
	 * @param payload the payload
	 * @param format the Content-Format
	 * @param etags the ETags for the If-Match option
	 */
	public void putIfMatch(CoapHandler handler, byte[] payload, int format, byte[]... etags) {
		Request request = newPut();
		request.setPayload(payload);
		request.getOptions().setContentFormat(format);
		assignClientUriIfEmpty(request);
		ifMatch(request, etags);
		asynchronous(request, handler);
	}

	/**
	 * 
	 * @param handler the Response handler
	 * @param payload the payload
	 * @param format the Content-Format
	 */
	public void putIfNoneMatch(CoapHandler handler, String payload, int format) {
		Request request = newPut();
		request.setPayload(payload);
		request.getOptions().setContentFormat(format);
		request.getOptions().setIfNoneMatch(true);
		assignClientUriIfEmpty(request);
		asynchronous(request, handler);
	}

	/**
	 * 
	 * @param handler the Response handler
	 * @param payload the payload
	 * @param format the Content-Format
	 */
	public void putIfNoneMatch(CoapHandler handler, byte[] payload, int format) {
		Request request = newPut();
		request.setPayload(payload);
		request.getOptions().setContentFormat(format);
		request.getOptions().setIfNoneMatch(true);
		assignClientUriIfEmpty(request);
		asynchronous(request, handler);
	}

	// Synchronous DELETE

	/**
	 * Sends a DELETE request and waits for the response.
	 *
	 * @return the CoAP response
	 * @throws ConnectorException if an issue specific to the connector occurred
	 * @throws IOException if any other issue (not specific to the connector) occurred
	 */
	public CoapResponse delete() throws ConnectorException, IOException {
		Request request = newDelete();
		assignClientUriIfEmpty(request);
		return synchronous(request);
	}

	/**
	 * Sends a DELETE request and invokes the specified handler when a response
	 * arrives.
	 *
	 * @param handler the response handler
	 */
	public void delete(CoapHandler handler) {
		Request request = newDelete();
		assignClientUriIfEmpty(request);
		asynchronous(request, handler);
	}

	// ETag validation

	public CoapResponse validate(byte[]... etags) throws ConnectorException, IOException {
		Request request = newGet();
		etags(request, etags);
		assignClientUriIfEmpty(request);
		return synchronous(request);
	}

	public void validate(CoapHandler handler, byte[]... etags) {
		Request request = newGet();
		etags(request, etags);
		assignClientUriIfEmpty(request);
		asynchronous(request, handler);
	}

	// Advanced requests

	/**
	 * Sends an advanced synchronous request that has to be configured by the
	 * developer.
	 * 
	 * @param request the custom request
	 * @return the CoAP response
	 * @throws ConnectorException if an issue specific to the connector occurred
	 * @throws IOException if any other issue (not specific to the connector) occurred
	 */
	public CoapResponse advanced(Request request) throws ConnectorException, IOException {
		assignClientUriIfEmpty(request);
		return synchronous(request);
	}

	/**
	 * Sends an advanced asynchronous request that has to be configured by the
	 * developer.
	 * 
	 * @param handler the response handler
	 * @param request the custom request
	 */
	public void advanced(CoapHandler handler, Request request) {
		assignClientUriIfEmpty(request);
		asynchronous(request, handler);
	}

	// Synchronous observer

	/**
	 * Sends an observe request and waits until it has been established
	 * whereupon the specified handler is invoked when a notification arrives.
	 *
	 * @param handler the Response handler
	 * @return the CoAP observe relation
	 * @throws ConnectorException if an issue specific to the connector occurred
	 * @throws IOException if any other issue (not specific to the connector) occurred
	 */
	public CoapObserveRelation observeAndWait(CoapHandler handler) throws ConnectorException, IOException {
		Request request = newGet();
		request.setObserve();
		return observeAndWait(request, handler);
	}

	/**
	 * Sends an observe request with the specified Accept option and waits until
	 * it has been established whereupon the specified handler is invoked when a
	 * notification arrives.
	 *
	 * @param handler the Response handler
	 * @param accept the Accept option
	 * @return the CoAP observe relation
	 * @throws ConnectorException if an issue specific to the connector occurred
	 * @throws IOException if any other issue (not specific to the connector) occurred
	 */
	public CoapObserveRelation observeAndWait(CoapHandler handler, int accept) throws ConnectorException, IOException {
		Request request = newGet();
		request.setObserve();
		request.getOptions().setAccept(accept);
		return observeAndWait(request, handler);
	}

	// Asynchronous observe

	/**
	 * Sends an observe request and invokes the specified handler each time a
	 * notification arrives.
	 *
	 * @param handler the Response handler
	 * @return the CoAP observe relation
	 */
	public CoapObserveRelation observe(CoapHandler handler) {
		Request request = newGet();
		request.setObserve();
		return observe(request, handler);
	}

	/**
	 * Sends an observe request with the specified Accept option and invokes the
	 * specified handler each time a notification arrives.
	 *
	 * @param handler the Response handler
	 * @param accept the Accept option
	 * @return the CoAP observe relation
	 */
	public CoapObserveRelation observe(CoapHandler handler, int accept) {
		Request request = newGet();
		request.setObserve();
		return observe(accept(request, accept), handler);
	}

	/**
	 * Shutdown the client-specific executor service, when not detached. Always
	 * needed unless you used detached executor.
	 */
	public void shutdown() {
		ExecutorService executor;
		ExecutorService secondaryExecutor;
		boolean shutdown;
		synchronized (this) {
			executor = this.executor;
			secondaryExecutor = this.secondaryExecutor;
			shutdown = !this.detachExecutor;
			this.executor = null;
			this.secondaryExecutor = null;
		}
		if (shutdown) {
			if (executor != null) {
				executor.shutdownNow();
			}
			if (secondaryExecutor != null) {
				secondaryExecutor.shutdownNow();
			}
		}
	}

	// Implementation

	/**
	 * Asynchronously sends the specified request and invokes the specified
	 * handler when a response arrives.
	 *
	 * @param request the request
	 * @param handler the Response handler
	 */
	private void asynchronous(Request request, CoapHandler handler) {
		request.addMessageObserver(new MessageObserverImpl(handler, request.isMulticast()));
		send(request);
	}

	/**
	 * Synchronously sends the specified request.
	 *
	 * @param request the request
	 * 
	 * @return the CoAP response
	 * @throws ConnectorException if an issue specific to the connector occurred
	 * @throws IOException if any other issue (not specific to the connector) occurred
	 */
	private CoapResponse synchronous(Request request) throws ConnectorException, IOException {
		return synchronous(request, getEffectiveEndpoint(request));
	}

	/**
	 * Synchronously sends the specified request over the specified endpoint.
	 *
	 * @param request the request
	 * @param outEndpoint the endpoint
	 * 
	 * @return the CoAP response
	 * @throws ConnectorException if an issue specific to the connector occurred
	 * @throws IOException if any other issue (not specific to the connector) occurred
	 */
	private CoapResponse synchronous(Request request, Endpoint outEndpoint) throws ConnectorException, IOException {
		try {
			Long timeout = getTimeout();
			if (timeout == null) {
				timeout = outEndpoint.getConfig().getLong(NetworkConfig.Keys.EXCHANGE_LIFETIME);
			}
			Response response = send(request, outEndpoint).waitForResponse(timeout);
			if (response == null) {
				// Cancel request so appropriate clean up can happen.
				request.cancel();
				Throwable sendError = request.getSendError();
				if (sendError != null) {
					if (sendError instanceof ConnectorException) {
						throw (ConnectorException) sendError;
					} else {
						throw new IOException(sendError);
					}
				}
				return null;
			} else {
				if (!request.isMulticast()) {
					setDestinationContextFromResponse(response);
				}
				return new CoapResponse(response);
			}
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
	}

	/*
	 * Sets the specified Accept option of the request.
	 *
	 * @param request the request
	 * @param accept the Accept option
	 * 
	 * @return the request
	 */
	private static Request accept(final Request request, final int accept) {
		request.getOptions().setAccept(accept);
		return request;
	}

	/*
	 * Adds the specified ETag options to the request.
	 * 
	 * @param request the request
	 * @param etags the list of ETags
	 * 
	 * @return the request
	 */
	private static Request etags(final Request request, final byte[]... etags) {
		for (byte[] etag : etags) {
			request.getOptions().addETag(etag);
		}
		return request;
	}

	/*
	 * Adds the specified ETags as If-Match options to the request.
	 * 
	 * @param request the request
	 * @param etags the ETags for the If-Match option
	 * 
	 * @return the request
	 */
	private static Request ifMatch(final Request request, final byte[]... etags) {
		for (byte[] etag : etags) {
			request.getOptions().addIfMatch(etag);
		}
		return request;
	}

	/**
	 * Sends the specified observe request and waits for the response whereupon
	 * the specified handler is invoked when a notification arrives.
	 *
	 * @param request the request
	 * 
	 * @param handler the Response handler
	 * 
	 * @return the CoAP observe relation
	 * @throws IllegalArgumentException if the observe option is not set in the
	 *             request
	 * @throws ConnectorException if an issue specific to the connector occurred
	 * @throws IOException if any other issue (not specific to the connector) occurred
	 */
	public CoapObserveRelation observeAndWait(Request request, CoapHandler handler) throws ConnectorException, IOException {

		if (request.getOptions().hasObserve()) {
			assignClientUriIfEmpty(request);
			Endpoint outEndpoint = getEffectiveEndpoint(request);
			CoapObserveRelation relation = new CoapObserveRelation(request, outEndpoint, getSecondaryExecutor());
			// add message observer to get the response.
			ObserveMessageObserverImpl messageObserver = new ObserveMessageObserverImpl(handler, request.isMulticast(), relation);
			request.addMessageObserver(messageObserver);
			// add notification listener to all notification
			NotificationListener notificationListener = new Adapter(messageObserver, relation);
			outEndpoint.addNotificationListener(notificationListener);
			// relation should remove this listener when the request is cancelled
			relation.setNotificationListener(notificationListener);
			CoapResponse response = synchronous(request, outEndpoint);
			if (response == null || !response.advanced().getOptions().hasObserve()) {
				relation.setCanceled(true);
			}
			return relation;
		} else {
			throw new IllegalArgumentException("please make sure that the request has observe option set.");
		}
	}

	/**
	 * Sends the specified observe request and invokes the specified handler
	 * each time a notification arrives.
	 *
	 * @param request the request
	 * 
	 * @param handler the Response handler
	 * 
	 * @return the CoAP observe relation
	 * @throws IllegalArgumentException if the observe option is not set in the
	 *             request
	 */
	public CoapObserveRelation observe(Request request, CoapHandler handler) {
		if (request.getOptions().hasObserve()) {
			assignClientUriIfEmpty(request);
			Endpoint outEndpoint = getEffectiveEndpoint(request);
			CoapObserveRelation relation = new CoapObserveRelation(request, outEndpoint, getSecondaryExecutor());
			// add message observer to get the response.
			ObserveMessageObserverImpl messageObserver = new ObserveMessageObserverImpl(handler, request.isMulticast(), relation);
			request.addMessageObserver(messageObserver);
			// add notification listener to all notification
			NotificationListener notificationListener = new Adapter(messageObserver, relation);
			outEndpoint.addNotificationListener(notificationListener);
			// relation should remove this listener when the request is cancelled
			relation.setNotificationListener(notificationListener);
			send(request, outEndpoint);
			return relation;
		} else {
			throw new IllegalArgumentException("please make sure that the request has observe option set.");
		}
	}

	/**
	 * Sends the specified request over the endpoint of the client if one is
	 * defined or over the default endpoint otherwise.
	 *
	 * @param request the request
	 * @return the request
	 */
	protected Request send(Request request) {
		return send(request, getEffectiveEndpoint(request));
	}

	/**
	 * Sends the specified request over the specified endpoint.
	 * 
	 * @param request the request
	 * @param outEndpoint the endpoint
	 * @return the request
	 */
	protected Request send(Request request, Endpoint outEndpoint) {
		if (blockwise != 0) {
			request.getOptions().setBlock2(new BlockOption(BlockOption.size2Szx(this.blockwise), false, 0));
		}

		outEndpoint.sendRequest(request);
		return request;
	}

	/**
	 * Returns the effective endpoint that the specified request is supposed to
	 * be sent over. If an endpoint has explicitly been set to this CoapClient,
	 * this endpoint will be used. If no endpoint has been set, the client will
	 * effectively use a default endpoint of the {@link EndpointManager}.
	 * 
	 * @param request the request to be sent
	 * @return the effective endpoint that the request is going o be sent over.
	 */
	protected Endpoint getEffectiveEndpoint(Request request) {
		Endpoint myEndpoint = getEndpoint();

		// custom endpoint
		if (myEndpoint != null) {
			return myEndpoint;
		}
		return EndpointManager.getEndpointManager().getDefaultEndpoint(request.getScheme());
	}

	protected void execute(Runnable job) {
		ExecutorService executor;
		synchronized (this) {
			executor = this.executor;
		}
		if (executor == null) {
			job.run();
		} else {
			try {
				// use thread from the client executer
				executor.execute(job);
			} catch (RejectedExecutionException ex) {
				if (!executor.isShutdown()) {
					LOGGER.warn("failed to execute job!");
				}
			}
		}
	}

	/*
	 * Create a GET request with a type specified in the client
	 *
	 * @return the request
	 */
	private Request newGet() {
		return applyRequestType(Request.newGet());
	}

	/*
	 * Create a POST request with a type specified in the client
	 *
	 * @return the request
	 */
	private Request newPost() {
		return applyRequestType(Request.newPost());
	}

	/*
	 * Create a PUT request with a type specified in the client
	 *
	 * @return the request
	 */
	private Request newPut() {
		return applyRequestType(Request.newPut());
	}

	/*
	 * Create a DELETE request with a type specified in the client
	 *
	 * @return the request
	 */
	private Request newDelete() {
		return applyRequestType(Request.newDelete());
	}

	/*
	 * Applies the CoapClient#type (managed by useNONs, useCONs) to the
	 * specified request.
	 *
	 *
	 * @param request the request
	 * 
	 * @return the same request with changed type
	 */
	private Request applyRequestType(Request request) {
		request.setType(this.type);
		return request;
	}

	/*
	 * Assigns a CoapClient#uri if request has no uri.
	 *
	 * @param request the request
	 */
	private Request assignClientUriIfEmpty(Request request) {
		EndpointContext context = destinationContext.get();
		if (context != null && request.getDestinationContext() == null) {
			request.setDestinationContext(context);
			request.setURI(uri);
		} else if (!request.hasURI() && !request.hasProxyURI()) {
			request.setURI(uri);
		}
		return request;
	}

	private void setDestinationContextFromResponse(Response response) {
		if (response != null) {
			// use source context for further request
			destinationContext.compareAndSet(null,  response.getSourceContext());
		}
	}

	/*
	 * Adapt MessageObserver for a given request in NotificationListener
	 */
	private class Adapter implements NotificationListener {

		private final MessageObserver observer;
		private final CoapObserveRelation relation;

		public Adapter(MessageObserver observer, CoapObserveRelation relation) {
			this.observer = observer;
			this.relation = relation;
		}

		@Override
		public void onNotification(Request request, Response response) {
			if (relation.matchRequest(request)) {
				observer.onResponse(response);
			}
		}
	}

	/**
	 * The MessageObserverImpl is called when a response arrives. It wraps the
	 * response into a CoapResponse and lets the executor invoke the handler's
	 * method.
	 */
	private class MessageObserverImpl extends MessageObserverAdapter {

		/** The handler. */
		protected final CoapHandler handler;

		private final boolean multicast;

		/**
		 * Constructs a new message observer that calls the specified handler
		 *
		 * @param handler the Response handler
		 * @param multicast {@code true} for multicast requests, {@code false},
		 *            otherwise.
		 */
		private MessageObserverImpl(CoapHandler handler, boolean multicast) {
			this.handler = handler;
			this.multicast = multicast;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * org.eclipse.californium.core.coap.MessageObserverAdapter#responded(
		 * org.eclipse.californium.core.coap.Response)
		 */
		@Override
		public void onResponse(final Response response) {
			if (!multicast) {
				setDestinationContextFromResponse(response);
			}
			succeeded(response != null ? new CoapResponse(response) : null);
		}

		/**
		 * Invoked when a response arrives (even if the response code is not
		 * successful, the response still was successfully transmitted).
		 *
		 * @param response the response
		 */
		protected void succeeded(final CoapResponse response) {
			execute(new Runnable() {

				public void run() {
					try {
						deliver(response);
					} catch (Throwable t) {
						LOGGER.warn("exception while handling response", t);
					}
				}
			});
		}

		/**
		 * Invokes the handler's method with the specified response. This method
		 * must be invoked by the client's executor if it defines one.
		 * 
		 * This is a separate method, so that other message observers can add
		 * synchronization code, e.g., for CoAP notification re-ordering.
		 *
		 * @param response the response
		 */
		protected void deliver(CoapResponse response) {
			handler.onLoad(response);
		}

		/**
		 * Invokes the handler's method failed() on the executor.
		 */
		@Override
		protected void failed() {
			execute(new Runnable() {

				public void run() {
					try {
						handler.onError();
					} catch (Throwable t) {
						LOGGER.warn("exception while handling failure", t);
					}
				}
			});
		}
	}

	/**
	 * The ObserveMessageObserverImpl is called whenever a notification of an
	 * observed resource arrives. It wraps the response into a CoapResponse and
	 * lets the executor invoke the handler's method.
	 */
	private class ObserveMessageObserverImpl extends MessageObserverImpl {

		/** The observer relation relation. */
		private final CoapObserveRelation relation;

		/**
		 * Constructs a new message observer with the specified handler and the
		 * specified relation.
		 *
		 * @param handler the Response handler
		 * @param relation the Observe relation
		 */
		public ObserveMessageObserverImpl(CoapHandler handler, boolean multicast, CoapObserveRelation relation) {
			super(handler, multicast);
			this.relation = relation;
		}

		/**
		 * Checks if the specified response truly is a new notification and if,
		 * invokes the handler's method or drops the notification otherwise.
		 * Ordering and delivery must be done synchronized here to deal with
		 * race conditions in the stack.
		 */
		@Override
		protected void deliver(CoapResponse response) {
			synchronized (relation) {
				if (relation.onResponse(response)) {
					handler.onLoad(response);
				} else {
					LOGGER.debug("dropping old notification: {}", response.advanced());
					return;
				}
			}
		}

		/**
		 * Marks the relation as canceled and invokes the the handler's failed()
		 * method.
		 */
		@Override
		protected void failed() {
			// When relation is canceled remove the notification listener
			relation.setCanceled(true);
			super.failed();
		}
	}

	/**
	 * The Builder can be used to build a CoapClient if the URI's pieces are
	 * available in separate strings. This is in particular useful to add
	 * multiple queries to the URI.
	 */
	public static class Builder {

		/** The scheme, host and port. */
		String scheme, host, port;

		/** The path and the query. */
		String[] path, query;

		/**
		 * Instantiates a new builder.
		 *
		 * @param host the host
		 * @param port the port
		 */
		public Builder(String host, int port) {
			this.host = host;
			this.port = Integer.toString(port);
		}

		/**
		 * Sets the specified scheme.
		 *
		 * @param scheme the scheme
		 * @return the builder
		 */
		public Builder scheme(String scheme) {
			this.scheme = scheme;
			return this;
		}

		/**
		 * Sets the specified host.
		 *
		 * @param host the host
		 * @return the builder
		 */
		public Builder host(String host) {
			this.host = host;
			return this;
		}

		/**
		 * Sets the specified port.
		 *
		 * @param port the port
		 * @return the builder
		 */
		public Builder port(String port) {
			this.port = port;
			return this;
		}

		/**
		 * Sets the specified port.
		 *
		 * @param port the port
		 * @return the builder
		 */
		public Builder port(int port) {
			this.port = Integer.toString(port);
			return this;
		}

		/**
		 * Sets the specified resource path.
		 *
		 * @param path the path
		 * @return the builder
		 */
		public Builder path(String... path) {
			this.path = path;
			return this;
		}

		/**
		 * Sets the specified query.
		 *
		 * @param query the query
		 * @return the builder
		 */
		public Builder query(String... query) {
			this.query = query;
			return this;
		}

		/**
		 * Creates the CoapClient
		 *
		 * @return the client
		 */
		public CoapClient create() {
			StringBuilder builder = new StringBuilder();
			if (scheme != null) {
				builder.append(scheme).append("://");
			}
			builder.append(host).append(":").append(port);
			for (String element : path) {
				builder.append("/").append(element);
			}
			if (query.length > 0) {
				builder.append("?");
			}
			for (int i = 0; i < query.length; i++) {
				builder.append(query[i]);
				if (i < query.length - 1) {
					builder.append("&");
				}
			}
			return new CoapClient(builder.toString());
		}
	}
}
