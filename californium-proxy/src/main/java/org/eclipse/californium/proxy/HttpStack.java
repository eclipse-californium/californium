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
 *    Francesco Corazza - HTTP cross-proxy
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.proxy;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Exchanger;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.HttpStatus;
import org.apache.http.client.protocol.RequestAcceptEncoding;
import org.apache.http.client.protocol.ResponseContentEncoding;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.DefaultConnectionReuseStrategy;
import org.apache.http.impl.nio.DefaultHttpServerIODispatch;
import org.apache.http.impl.nio.DefaultNHttpServerConnection;
import org.apache.http.impl.nio.DefaultNHttpServerConnectionFactory;
import org.apache.http.impl.nio.reactor.DefaultListeningIOReactor;
import org.apache.http.nio.NHttpConnectionFactory;
import org.apache.http.nio.protocol.BasicAsyncRequestConsumer;
import org.apache.http.nio.protocol.BasicAsyncRequestHandler;
import org.apache.http.nio.protocol.HttpAsyncExchange;
import org.apache.http.nio.protocol.HttpAsyncRequestConsumer;
import org.apache.http.nio.protocol.HttpAsyncRequestHandler;
import org.apache.http.nio.protocol.HttpAsyncRequestHandlerRegistry;
import org.apache.http.nio.protocol.HttpAsyncService;
import org.apache.http.nio.reactor.IOEventDispatch;
import org.apache.http.nio.reactor.ListeningIOReactor;
import org.apache.http.params.CoreConnectionPNames;
import org.apache.http.params.CoreProtocolPNames;
import org.apache.http.params.HttpParams;
import org.apache.http.params.SyncBasicHttpParams;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpProcessor;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.protocol.ImmutableHttpProcessor;
import org.apache.http.protocol.ResponseConnControl;
import org.apache.http.protocol.ResponseContent;
import org.apache.http.protocol.ResponseDate;
import org.apache.http.protocol.ResponseServer;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.config.NetworkConfig;


/**
 * Class encapsulating the logic of a http server. The class create a receiver
 * thread that it is always blocked on the listen primitive. For each connection
 * this thread creates a new thread that handles the client/server dialog.
 */
public class HttpStack {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(HttpStack.class.getCanonicalName());
	
	private static final Response Response_NULL = new Response(null); // instead of Response.NULL // TODO
	
	private static final int SOCKET_TIMEOUT = NetworkConfig.getStandard().getInt(
			NetworkConfig.Keys.HTTP_SERVER_SOCKET_TIMEOUT);
	private static final int SOCKET_BUFFER_SIZE = NetworkConfig.getStandard().getInt(
			NetworkConfig.Keys.HTTP_SERVER_SOCKET_BUFFER_SIZE);
	private static final int GATEWAY_TIMEOUT = SOCKET_TIMEOUT * 3 / 4;
	private static final String SERVER_NAME = "Californium Http Proxy";
	
	/**
	 * Resource associated with the proxying behavior. If a client requests
	 * resource indicated by
	 * http://proxy-address/PROXY_RESOURCE_NAME/coap-server, the proxying
	 * handler will forward the request desired coap server.
	 */
	private static final String PROXY_RESOURCE_NAME = "proxy";

	/**
	 * The resource associated with the local resources behavior. If a client
	 * requests resource indicated by
	 * http://proxy-address/LOCAL_RESOURCE_NAME/coap-resource, the proxying
	 * handler will forward the request to the local resource requested.
	 */
	public static final String LOCAL_RESOURCE_NAME = "local";

	private final ConcurrentHashMap<Request, Exchanger<Response>> exchangeMap = new ConcurrentHashMap<Request, Exchanger<Response>>();

	private RequestHandler requestHandler;
	
	/**
	 * Instantiates a new http stack on the requested port. It creates an http
	 * listener thread on the port.
	 * 
	 * @param httpPort
	 *            the http port
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public HttpStack(int httpPort) throws IOException {
		new HttpServer(httpPort);
	}

	/**
	 * Checks if a thread is waiting for the arrive of a specific response.
	 * 
	 * @param request
	 *            the request
	 * @return true, if is waiting
	 */
	public boolean isWaitingRequest(Request request) {

		// DEBUG
		// System.out.println(request.hashCode());
		// request.prettyPrint();
		//
		// System.out.println(responseMap.get(request) != null);
		// System.out.println(semaphoreMap.get(request) != null);
		//
		// for (Request r : responseMap.keySet()) {
		// System.out.println(r.hashCode());
		// r.prettyPrint();
		// }
		//
		// for (Request r : semaphoreMap.keySet()) {
		// System.out.println(r.hashCode());
		// r.prettyPrint();
		// }

		// check the presence of the key in both maps
		// TODO check how much is this operation heavy
		// return responseMap.containsKey(request) &&
		// semaphoreMap.containsKey(request);

		return exchangeMap.containsKey(request);
	}

	private class HttpServer {

		public HttpServer(int httpPort) {
			// HTTP parameters for the server
			HttpParams params = new SyncBasicHttpParams();
			params.setIntParameter(CoreConnectionPNames.SO_TIMEOUT, SOCKET_TIMEOUT).setIntParameter(CoreConnectionPNames.SOCKET_BUFFER_SIZE, SOCKET_BUFFER_SIZE).setBooleanParameter(CoreConnectionPNames.TCP_NODELAY, true).setParameter(CoreProtocolPNames.ORIGIN_SERVER, SERVER_NAME);

			// Create HTTP protocol processing chain
			// Use standard server-side protocol interceptors
			HttpRequestInterceptor[] requestInterceptors = new HttpRequestInterceptor[] { new RequestAcceptEncoding() };
			HttpResponseInterceptor[] responseInterceptors = new HttpResponseInterceptor[] { new ResponseContentEncoding(), new ResponseDate(), new ResponseServer(), new ResponseContent(), new ResponseConnControl() };
			HttpProcessor httpProcessor = new ImmutableHttpProcessor(requestInterceptors, responseInterceptors);

			// Create request handler registry
			HttpAsyncRequestHandlerRegistry registry = new HttpAsyncRequestHandlerRegistry();

			// register the handler that will reply to the proxy requests
			registry.register("/" + PROXY_RESOURCE_NAME + "/*", new ProxyAsyncRequestHandler(PROXY_RESOURCE_NAME, true));
			// register the handler for the frontend
			registry.register("/" + LOCAL_RESOURCE_NAME + "/*", new ProxyAsyncRequestHandler(LOCAL_RESOURCE_NAME, false));
			// register the default handler for root URIs
			// wrapping a common request handler with an async request handler
			registry.register("*", new BasicAsyncRequestHandler(new BaseRequestHandler()));

			// Create server-side HTTP protocol handler
			HttpAsyncService protocolHandler = new HttpAsyncService(httpProcessor, new DefaultConnectionReuseStrategy(), registry, params);

			// Create HTTP connection factory
			NHttpConnectionFactory<DefaultNHttpServerConnection> connFactory = new DefaultNHttpServerConnectionFactory(params);

			// Create server-side I/O event dispatch
			final IOEventDispatch ioEventDispatch = new DefaultHttpServerIODispatch(protocolHandler, connFactory);

			final ListeningIOReactor ioReactor;
			try {
				// Create server-side I/O reactor
				ioReactor = new DefaultListeningIOReactor();
				// Listen of the given port
				LOGGER.info("HttpStack listening on port {}", httpPort);
				ioReactor.listen(new InetSocketAddress(httpPort));

				// create the listener thread
				Thread listener = new Thread("HttpStack listener") {

					@Override
					public void run() {
						// Starts the reactor and initiates the dispatch of I/O
						// event notifications to the given IOEventDispatch.
						try {
							LOGGER.info("Submitted http listening to thread 'HttpStack listener'");

							ioReactor.execute(ioEventDispatch);
						} catch (IOException e) {
							LOGGER.error("I/O Exception in HttpStack", e);
						}

						LOGGER.info("Shutdown HttpStack");
					}
				};

				listener.setDaemon(false);
				listener.start();
				LOGGER.info("HttpStack started");
			} catch (IOException e) {
				LOGGER.error("I/O error", e);
			}
		}

		/**
		 * The Class BaseRequestHandler handles simples requests that do not
		 * need the proxying.
		 */
		private class BaseRequestHandler implements HttpRequestHandler {

			/*
			 * (non-Javadoc)
			 * @see
			 * org.apache.http.protocol.HttpRequestHandler#handle(org.apache
			 * .http .HttpRequest, org.apache.http.HttpResponse,
			 * org.apache.http.protocol.HttpContext)
			 */
			@Override
			public void handle(HttpRequest httpRequest, HttpResponse httpResponse, HttpContext httpContext) throws HttpException, IOException {
				httpResponse.setStatusCode(HttpStatus.SC_OK);
				httpResponse.setEntity(new StringEntity("Californium Proxy server"));

//				if (Bench_Help.DO_LOG) 
					LOGGER.debug("Root request handled");
			}
		}

		/**
		 * Class associated with the http service to translate the http requests
		 * in coap requests and to produce the http responses. Even if the class
		 * accepts a string indicating the name of the proxy resource, it is
		 * still thread-safe because the local resource is set in the
		 * constructor and then only read by the methods.
		 */
		private class ProxyAsyncRequestHandler implements
				HttpAsyncRequestHandler<HttpRequest> {

			private final String localResource;
			private final boolean proxyingEnabled;

			/**
			 * Instantiates a new proxy request handler.
			 * 
			 * @param localResource
			 *            the local resource
			 * @param proxyingEnabled
			 */
			public ProxyAsyncRequestHandler(String localResource, boolean proxyingEnabled) {
				super();

				this.localResource = localResource;
				this.proxyingEnabled = proxyingEnabled;
			}

			/*
			 * (non-Javadoc)
			 * @see
			 * org.apache.http.nio.protocol.HttpAsyncRequestHandler#handle(java.
			 * lang.Object, org.apache.http.nio.protocol.HttpAsyncExchange,
			 * org.apache.http.protocol.HttpContext)
			 */
			@Override
			public void handle(HttpRequest httpRequest, HttpAsyncExchange httpExchange, HttpContext httpContext) throws HttpException, IOException {
//				if (Bench_Help.DO_LOG) 
					LOGGER.debug("Incoming http request: {}", httpRequest.getRequestLine());

				final HttpRequestContext httpRequestContext = new HttpRequestContext(httpExchange, httpRequest);
				try {
					// translate the request in a valid coap request
					Request coapRequest = new HttpTranslator().getCoapRequest(httpRequest, localResource, proxyingEnabled);
//					if (Bench_Help.DO_LOG) 
						LOGGER.info("Received HTTP request and translate to {}", coapRequest);

					// handle the requset
					requestHandler.handleRequest(coapRequest, httpRequestContext);
				} catch (InvalidMethodException e) {
					LOGGER.warn("Method not implemented", e);
					httpRequestContext.sendSimpleHttpResponse(HttpTranslator.STATUS_WRONG_METHOD);
				} catch (InvalidFieldException e) {
					LOGGER.warn("Request malformed", e);
					httpRequestContext.sendSimpleHttpResponse(HttpTranslator.STATUS_URI_MALFORMED);
				} catch (TranslationException e) {
					LOGGER.warn("Failed to translate the http request in a valid coap request", e);
					httpRequestContext.sendSimpleHttpResponse(HttpTranslator.STATUS_TRANSLATION_ERROR);
				}
			}

			/*
			 * (non-Javadoc)
			 * @see
			 * org.apache.http.nio.protocol.HttpAsyncRequestHandler#processRequest
			 * (org.apache.http.HttpRequest,
			 * org.apache.http.protocol.HttpContext)
			 */
			@Override
			public HttpAsyncRequestConsumer<HttpRequest> processRequest(HttpRequest httpRequest, HttpContext httpContext) throws HttpException, IOException {
				// Buffer request content in memory for simplicity
				return new BasicAsyncRequestConsumer();
			}
		}

	}

	public void doReceiveMessage(Request request, HttpRequestContext context) {
		requestHandler.handleRequest(request, context);
	}

	public RequestHandler getRequestHandler() {
		return requestHandler;
	}

	public void setRequestHandler(RequestHandler requestHandler) {
		this.requestHandler = requestHandler;
	}

}
