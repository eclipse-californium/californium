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
package org.eclipse.californium.proxy2;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.HttpStatus;
import org.apache.http.client.protocol.RequestAcceptEncoding;
import org.apache.http.client.protocol.ResponseContentEncoding;
import org.apache.http.config.ConnectionConfig;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.DefaultConnectionReuseStrategy;
import org.apache.http.impl.DefaultHttpResponseFactory;
import org.apache.http.impl.nio.DefaultHttpServerIODispatch;
import org.apache.http.impl.nio.DefaultNHttpServerConnection;
import org.apache.http.impl.nio.DefaultNHttpServerConnectionFactory;
import org.apache.http.impl.nio.reactor.DefaultListeningIOReactor;
import org.apache.http.impl.nio.reactor.IOReactorConfig;
import org.apache.http.nio.NHttpConnectionFactory;
import org.apache.http.nio.protocol.BasicAsyncRequestHandler;
import org.apache.http.nio.protocol.HttpAsyncService;
import org.apache.http.nio.protocol.UriHttpAsyncRequestHandlerMapper;
import org.apache.http.nio.reactor.IOEventDispatch;
import org.apache.http.nio.reactor.ListeningIOReactor;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpProcessor;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.protocol.ImmutableHttpProcessor;
import org.apache.http.protocol.ResponseConnControl;
import org.apache.http.protocol.ResponseContent;
import org.apache.http.protocol.ResponseDate;
import org.apache.http.protocol.ResponseServer;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Create simple http server.
 */
public class HttpServer {

	/**
	 * The default thread group for Californium threads.
	 */
	public static final ThreadGroup HTTP_THREAD_GROUP = new ThreadGroup("Http"); //$NON-NLS-1$

	static {
		// reset daemon, may be set by parent group!
		HTTP_THREAD_GROUP.setDaemon(false);
	}

	private static final Logger LOGGER = LoggerFactory.getLogger(HttpServer.class);

	private final UriHttpAsyncRequestHandlerMapper registry;
	private final IOEventDispatch ioEventDispatch;
	private final IOReactorConfig ioReactorConfig;
	private final InetSocketAddress httpInterface;
	private ThreadFactory threadFactory = new DaemonThreadFactory("Http#", HTTP_THREAD_GROUP);
	private ListeningIOReactor ioReactor;

	/**
	 * Create http server.
	 * 
	 * @param config network configuration
	 * @param httpPort port ot be used.
	 */
	public HttpServer(NetworkConfig config, int httpPort) {
		this(config, new InetSocketAddress(httpPort));
	}

	/**
	 * Create http server.
	 * 
	 * @param config network configuration
	 * @param httpInterface interface to be used.
	 * @throws NullPointerException if interface is {@code null}
	 * @since 2.4
	 */
	public HttpServer(NetworkConfig config, InetSocketAddress httpInterface) {
		if (httpInterface == null) {
			throw new NullPointerException("http interface must not be null!");
		}
		this.httpInterface = httpInterface;
		// Create HTTP protocol processing chain
		// Use standard server-side protocol interceptors
		HttpRequestInterceptor[] requestInterceptors = new HttpRequestInterceptor[] { new RequestAcceptEncoding() };
		HttpResponseInterceptor[] responseInterceptors = new HttpResponseInterceptor[] { new ResponseContentEncoding(),
				new ResponseDate(), new ResponseServer(), new ResponseContent(), new ResponseConnControl() };
		HttpProcessor httpProcessor = new ImmutableHttpProcessor(requestInterceptors, responseInterceptors);

		// Create request handler registry
		registry = new UriHttpAsyncRequestHandlerMapper();

		// Create server-side HTTP protocol handler
		HttpAsyncService protocolHandler = new HttpAsyncService(httpProcessor, new DefaultConnectionReuseStrategy(),
				new DefaultHttpResponseFactory(), registry, null);

		// Create HTTP connection factory
		NHttpConnectionFactory<DefaultNHttpServerConnection> connFactory = new DefaultNHttpServerConnectionFactory(
				ConnectionConfig.DEFAULT);

		// Create server-side I/O event dispatch
		ioEventDispatch = new DefaultHttpServerIODispatch<HttpAsyncService>(protocolHandler, connFactory);

		// configuring IOReactor
		int socketTimeout = config.getInt(NetworkConfig.Keys.HTTP_SERVER_SOCKET_TIMEOUT);
		int socketBufferSize = config.getInt(NetworkConfig.Keys.HTTP_SERVER_SOCKET_BUFFER_SIZE);
		ioReactorConfig = IOReactorConfig.custom().setRcvBufSize(socketBufferSize).setSoTimeout(socketTimeout)
				.setTcpNoDelay(true).setSoLinger(0).build();
	}

	UriHttpAsyncRequestHandlerMapper getRequestHandlerMapper() {
		return registry;
	}

	/**
	 * Start http server.
	 * 
	 * @throws IOException in case if a non-recoverable I/O error.
	 */
	public void start() throws IOException {
		ioReactor = new DefaultListeningIOReactor(ioReactorConfig, threadFactory);
		// Listen of the given port
		ioReactor.listen(httpInterface);
		// create the listener thread
		Thread listener = new Thread("Http-Listener") {

			@Override
			public void run() {
				// Starts the reactor and initiates the dispatch of I/O
				// event notifications to the given IOEventDispatch.
				try {
					ioReactor.execute(ioEventDispatch);
				} catch (IOException e) {
					LOGGER.error("I/O Exception in HttpServer", e);
				}
			}
		};
		listener.setDaemon(false);
		listener.start();
		LOGGER.info("HttpServer listening on {} started.", StringUtil.toDisplayString(httpInterface));
	}

	/**
	 * Start http server.
	 */
	public void stop() {
		try {
			ioReactor.shutdown(1000);
			System.out.println("shutdown ...");
		} catch (IOException e) {
			LOGGER.error("shutdown failed!", e);
		}
		LOGGER.info("HttpServer on {} stopped.", StringUtil.toDisplayString(httpInterface));
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
		registry.register(resource,
				new BasicAsyncRequestHandler(new RequestCounterHandler(message, name, requestCounter)));
	}

	/**
	 * The Class BaseRequestHandler handles simples requests that do not need
	 * the proxying.
	 */
	private static class RequestCounterHandler implements HttpRequestHandler {

		private final String message;
		private final String name;
		private final AtomicLong requestCounter;

		private RequestCounterHandler(String message, String name, AtomicLong requestCounter) {
			this.message = message;
			this.name =  name;
			this.requestCounter = requestCounter == null ? new AtomicLong() : requestCounter;
		}

		@Override
		public void handle(HttpRequest httpRequest, HttpResponse httpResponse, HttpContext httpContext)
				throws HttpException, IOException {
			long counter = requestCounter.incrementAndGet();
			String payload = String.format(message, name, counter);
			httpResponse.setStatusCode(HttpStatus.SC_OK);
			httpResponse.setEntity(new StringEntity(payload));
			LOGGER.debug("{} request handled!", counter);
		}
	}
}
