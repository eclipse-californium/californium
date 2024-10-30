/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.proxy2.http.server;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.hc.core5.function.Supplier;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.EndpointDetails;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.Message;
import org.apache.hc.core5.http.URIScheme;
import org.apache.hc.core5.http.impl.bootstrap.AsyncServerBootstrap;
import org.apache.hc.core5.http.impl.bootstrap.HttpAsyncServer;
import org.apache.hc.core5.http.impl.routing.RequestRouter;
import org.apache.hc.core5.http.nio.AsyncServerExchangeHandler;
import org.apache.hc.core5.http.nio.AsyncServerRequestHandler;
import org.apache.hc.core5.http.nio.support.AsyncResponseBuilder;
import org.apache.hc.core5.http.nio.support.BasicServerExchangeHandler;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.http.protocol.HttpCoreContext;
import org.apache.hc.core5.http.protocol.HttpProcessor;
import org.apache.hc.core5.http.protocol.HttpProcessorBuilder;
import org.apache.hc.core5.http.protocol.ResponseConnControl;
import org.apache.hc.core5.http.protocol.ResponseContent;
import org.apache.hc.core5.http.protocol.ResponseDate;
import org.apache.hc.core5.http.protocol.ResponseServer;
import org.apache.hc.core5.http.protocol.UriPatternType;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.net.URIAuthority;
import org.apache.hc.core5.reactor.IOReactorConfig;
import org.apache.hc.core5.reactor.ListenerEndpoint;
import org.apache.hc.core5.util.Args;
import org.apache.hc.core5.util.TimeValue;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.proxy2.config.Proxy2Config;
import org.eclipse.californium.proxy2.http.ContentTypedEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.net.HttpHeaders;

/**
 * Create simple http server.
 */
public class HttpServer {

	private static final Logger LOGGER = LoggerFactory.getLogger(HttpServer.class);

	public static final URIAuthority WILDCARD_AUTHORITY = new URIAuthority("*");
	public static final URIAuthority LOCAL_AUTHORITY = RequestRouter.LOCAL_AUTHORITY;

	private final InetSocketAddress httpInterface;
	private final AsyncServerBootstrap bootstrap;
	private final RequestRouter.Builder<Supplier<AsyncServerExchangeHandler>> requestRouterBuilder;
	private final Set<String> virtualHosts = new HashSet<>();
	private HttpAsyncServer server;

	/**
	 * Create http server.
	 * 
	 * @param config configuration
	 * @param httpPort port ot be used.
	 * @since 3.0 (changed parameter to Configuration)
	 */
	public HttpServer(Configuration config, int httpPort) {
		this(config, new InetSocketAddress(httpPort));
	}

	/**
	 * Create http server.
	 * 
	 * @param config configuration
	 * @param httpInterface interface to be used.
	 * @throws NullPointerException if interface is {@code null}
	 * @since 3.0 (changed parameter to Configuration)
	 */
	public HttpServer(Configuration config, InetSocketAddress httpInterface) {
		if (httpInterface == null) {
			throw new NullPointerException("http interface must not be null!");
		}
		this.httpInterface = httpInterface;
		// Create HTTP protocol processing chain
		// Use standard server-side protocol interceptors
		HttpProcessor httpProcessor = HttpProcessorBuilder.create().add(new ResponseDate()).add(new ResponseServer())
				.add(new ResponseContent()).add(new ResponseConnControl()).build();
		// create request route for generic proxy support.
		requestRouterBuilder = RequestRouter
				.<Supplier<AsyncServerExchangeHandler>> builder(UriPatternType.URI_PATTERN_IN_ORDER);
		// configuring IOReactor
		int threads = config.get(Proxy2Config.HTTP_WORKER_THREADS);
		int socketTimeout = config.getTimeAsInt(Proxy2Config.HTTP_SERVER_SOCKET_TIMEOUT, TimeUnit.MILLISECONDS);
		int socketBufferSize = config.get(Proxy2Config.HTTP_SERVER_SOCKET_BUFFER_SIZE);
		IOReactorConfig ioReactorConfig = IOReactorConfig.custom().setRcvBufSize(socketBufferSize)
				.setSoTimeout(socketTimeout, TimeUnit.MILLISECONDS).setTcpNoDelay(true)
				.setSoLinger(0, TimeUnit.MILLISECONDS).setIoThreadCount(threads).build();
		bootstrap = AsyncServerBootstrap.bootstrap().setIOReactorConfig(ioReactorConfig)
				.setHttpProcessor(httpProcessor);
	}

	/**
	 * Register proxy request handler.
	 * 
	 * The proxy handler is used for all requests, which contains a
	 * {@code absoluteURI}, which is not related to one of the used virtual
	 * handlers.
	 * 
	 * @param <T> request presentation
	 * @param uriPattern URI pattern to register
	 * @param requestHandler request handler to register
	 * @throws NullPointerException if request handler is {@code null}
	 * @throws IllegalStateException if server was already started
	 * @see #register(String, String, AsyncServerRequestHandler)
	 * @see <a href="https://tools.ietf.org/html/rfc2616#section-5.1.2" target=
	 *      "_blank"> RFC2616, HTTP/1.1 - 5.1.2 Request-URI</a>
	 * @since 3.0
	 */
	public <T> void registerProxy(final String uriPattern, final AsyncServerRequestHandler<T> requestHandler) {
		if (server != null) {
			throw new IllegalStateException("http server already started!");
		}
		Args.notBlank(uriPattern, "URI pattern");
		Args.notNull(requestHandler, "Request handler");
		requestRouterBuilder.addRoute(WILDCARD_AUTHORITY, uriPattern,
				() -> new BasicServerExchangeHandler<>(requestHandler));
	}

	/**
	 * Register request handler.
	 * 
	 * @param <T> request presentation
	 * @param uriPattern URI pattern to register
	 * @param requestHandler request handler to register
	 * @throws NullPointerException if one of the arguments is {@code null}
	 * @throws IllegalStateException if server was already started
	 * @since 3.0
	 */
	public <T> void register(final String uriPattern, final AsyncServerRequestHandler<T> requestHandler) {
		if (server != null) {
			throw new IllegalStateException("http server already started!");
		}
		Args.notBlank(uriPattern, "URI pattern");
		Args.notNull(requestHandler, "Request handler");
		requestRouterBuilder.addRoute(LOCAL_AUTHORITY, uriPattern,
				() -> new BasicServerExchangeHandler<>(requestHandler));
	}

	/**
	 * Registers a request handler for URIs matching the given host and pattern.
	 * 
	 * @param <T> request presentation
	 * @param hostname the host name
	 * @param uriPattern URI pattern to register
	 * @param requestHandler request handler to register
	 * @throws NullPointerException if one of the arguments is {@code null}
	 * @throws IllegalStateException if server was already started
	 * @since 4.0 (was registerVirtual)
	 */
	public <T> void register(final String hostname, final String uriPattern,
			final AsyncServerRequestHandler<T> requestHandler) {
		if (server != null) {
			throw new IllegalStateException("http server already started!");
		}
		Args.notNull(virtualHosts, "hostname");
		Args.notBlank(uriPattern, "URI pattern");
		Args.notNull(requestHandler, "Request handler");
		virtualHosts.add(hostname);
		requestRouterBuilder.addRoute(new URIAuthority(hostname), uriPattern,
				() -> new BasicServerExchangeHandler<>(requestHandler));
	}

	/**
	 * Get address of http network interface.
	 * 
	 * @return address of http network interface.
	 * @since 3.0
	 */
	public InetSocketAddress getInterface() {
		return httpInterface;
	}

	/**
	 * Start http server.
	 */
	public void start() {
		requestRouterBuilder.resolveAuthority((scheme, authority) -> {
			if (authority == null) {
				LOGGER.debug("Default authority to local");
				return LOCAL_AUTHORITY;
			} else if (!virtualHosts.contains(authority.getHostName())) {
				LOGGER.debug("Translate {} to *", authority);
				return WILDCARD_AUTHORITY;
			} else {
				LOGGER.debug("Accept {}", authority);
				return authority;
			}
		});

		bootstrap.setRequestRouter(requestRouterBuilder.build());
		server = bootstrap.create();
		LOGGER.info("HttpServer listening on {} started.", StringUtil.toLog(httpInterface));
		Runtime.getRuntime().addShutdownHook(new Thread() {

			@Override
			public void run() {
				LOGGER.info("HTTP server shutting down");
				HttpServer.this.stop();
			}
		});

		server.start();
		final Future<ListenerEndpoint> future = server.listen(httpInterface, URIScheme.HTTP);
		try {
			final ListenerEndpoint listenerEndpoint = future.get();
			LOGGER.info("Listening on {}", listenerEndpoint.getAddress());
		} catch (InterruptedException ex) {
			LOGGER.info("interrupted", ex);
		} catch (ExecutionException ex) {
			LOGGER.error("unexpected error:", ex);
		}
	}

	/**
	 * Stop http server.
	 */
	public void stop() {
		if (server != null) {
			server.close(CloseMode.GRACEFUL);
			System.out.println("shutdown ...");
			try {
				server.awaitShutdown(TimeValue.MAX_VALUE);
			} catch (InterruptedException e) {
			}
		}
		LOGGER.info("HttpServer on {} stopped.", StringUtil.toLog(httpInterface));
	}

	/**
	 * Set simple resource.
	 * 
	 * Apply {@link String#format(String, Object...)} to the message using the
	 * {@code httpPort} and {@code requestCounter} as parameter.
	 * 
	 * @param resource resource path
	 * @param message message template for response
	 * @param requestCounter counter for requests.
	 */
	public void setSimpleResource(String resource, String message, AtomicLong requestCounter) {
		String name = StringUtil.toDisplayString(httpInterface);
		RequestCounterHandler requestHandler = new RequestCounterHandler(message, name, requestCounter);
		register(resource, requestHandler);
	}

	/**
	 * Handler for simple requests.
	 */
	private static class RequestCounterHandler extends ByteBufferAsyncServerRequestHandler {

		private final String message;
		private final String name;
		private final AtomicLong requestCounter;

		private RequestCounterHandler(String message, String name, AtomicLong requestCounter) {
			this.message = message;
			this.name = name;
			this.requestCounter = requestCounter == null ? new AtomicLong() : requestCounter;
		}

		@Override
		public void handle(final Message<HttpRequest, ContentTypedEntity> message,
				final ResponseTrigger responseTrigger, final HttpContext context) throws HttpException, IOException {

			final HttpCoreContext coreContext = HttpCoreContext.cast(context);
			final EndpointDetails endpoint = coreContext.getEndpointDetails();
			long counter = requestCounter.incrementAndGet();
			String payload = String.format(this.message, name, counter);
			int hc = payload.hashCode();
			responseTrigger.submitResponse(
					AsyncResponseBuilder.create(HttpStatus.SC_OK).addHeader(HttpHeaders.ETAG, Integer.toHexString(hc))
							.setEntity(payload, ContentType.TEXT_PLAIN.withCharset(UTF_8)).build(),
					context);
			LOGGER.debug("{}, {} request handled!", endpoint, counter);
		}

	}
}
