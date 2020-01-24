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
 *    Francesco Corazza - HTTP cross-proxy
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.proxy;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Exchanger;

import org.apache.http.HttpException;
import org.apache.http.HttpInetConnection;
import org.apache.http.HttpRequest;
import org.apache.http.nio.protocol.BasicAsyncRequestConsumer;
import org.apache.http.nio.protocol.HttpAsyncExchange;
import org.apache.http.nio.protocol.HttpAsyncRequestConsumer;
import org.apache.http.nio.protocol.HttpAsyncRequestHandler;
import org.apache.http.nio.protocol.UriHttpAsyncRequestHandlerMapper;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpCoreContext;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class encapsulating the logic of a http server. The class create a receiver
 * thread that it is always blocked on the listen primitive. For each connection
 * this thread creates a new thread that handles the client/server dialog.
 * 
 * <a href="https://tools.ietf.org/html/rfc8075">RFC8075 - HTTP2CoAP</a>
 */
public class HttpStack {

	private static final Logger LOGGER = LoggerFactory.getLogger(HttpStack.class);

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
	private final HttpServer server;

	private RequestHandler requestHandler;

	/**
	 * Instantiates a new http stack on the requested port. It creates an http
	 * listener thread on the port and the proxy handler.
	 * 
	 * @param httpPort the http port
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public HttpStack(int httpPort) throws IOException {
		this(NetworkConfig.getStandard(), httpPort);
	}

	/**
	 * Instantiates a new http stack on the requested port. It creates an http
	 * listener thread on the port and the handlers as provided.
	 * 
	 * @param config configuration with HTTP_SERVER_SOCKET_TIMEOUT and
	 *            HTTP_SERVER_SOCKET_BUFFER_SIZE.
	 * @param httpPort the http port
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public HttpStack(NetworkConfig config, int httpPort) throws IOException {
		server = new HttpServer(config, httpPort);
		// register the default handler for root URIs
		// wrapping a common request handler with an async request handler
		server.setSimpleResource("*", SERVER_NAME + " on port " + httpPort + ".", null);
	}

	/**
	 * Register "local" request handler.
	 *
	 * Handles requests for
	 * "http:/<proxy-host>:<proxy-port>/local/<local-coap-path>".
	 * 
	 */
	void registerLocalRequestHandler() {
		UriHttpAsyncRequestHandlerMapper registry = server.getRequestHandlerMapper();
		// register the handler for local coap resources
		registry.register("/" + LOCAL_RESOURCE_NAME + "/*", new ProxyAsyncRequestHandler(LOCAL_RESOURCE_NAME, false));
	}

	/**
	 * Register "porxy" request handlers.
	 *
	 * Handles proxy requests for
	 * "http:/<proxy-host>:<proxy-port>/proxy/<destination-uri>".
	 */
	void registerProxyRequestHandler() {
		UriHttpAsyncRequestHandlerMapper registry = server.getRequestHandlerMapper();
		// register the handler for proxy coap resources
		registry.register("/" + PROXY_RESOURCE_NAME + "/*", new ProxyAsyncRequestHandler(PROXY_RESOURCE_NAME, true));
		registry.register("http*", new ProxyAsyncRequestHandler(PROXY_RESOURCE_NAME, true));
	}

	/**
	 * Register http-proxy request handlers.
	 * 
	 * Enables to catch calls, if this http server is configures as http-proxy
	 * for the client. In that case, the http-request contains the URI
	 * (including destination host).
	 * 
	 * Handles proxy requests for
	 * "http:/<destination>:<port>/<destination-uri>/<destination-scheme>:".
	 */
	void registerHttpProxyRequestHandler() {
		UriHttpAsyncRequestHandlerMapper registry = server.getRequestHandlerMapper();
		// register the handler for proxy coap resources
		registry.register("http*", new ProxyAsyncRequestHandler(PROXY_RESOURCE_NAME, true));
	}

	/**
	 * Start http server.
	 * 
	 * @throws IOException in case if a non-recoverable I/O error.
	 */
	public void start() throws IOException {
		server.start();
	}

	/**
	 * Stop http server.
	 */
	public void stop() {
		server.stop();
	}

	/**
	 * Checks if a thread is waiting for the arrive of a specific response.
	 * 
	 * @param request the request
	 * @return true, if is waiting
	 * @deprectaed not used
	 */
	@Deprecated
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

	public void doReceiveMessage(Request request, HttpRequestContext context) {
		requestHandler.handleRequest(request, context);
	}

	public RequestHandler getRequestHandler() {
		return requestHandler;
	}

	public void setRequestHandler(RequestHandler requestHandler) {
		this.requestHandler = requestHandler;
	}

	/**
	 * Class associated with the http service to translate the http requests in
	 * coap requests and to produce the http responses. Even if the class
	 * accepts a string indicating the name of the proxy resource, it is still
	 * thread-safe because the local resource is set in the constructor and then
	 * only read by the methods.
	 */
	private class ProxyAsyncRequestHandler implements HttpAsyncRequestHandler<HttpRequest> {

		private final String resourceName;
		private final boolean proxyingEnabled;

		/**
		 * Instantiates a new proxy request handler.
		 * 
		 * @param resourceName the http resource name
		 * @param proxyingEnabled
		 */
		public ProxyAsyncRequestHandler(String resourceName, boolean proxyingEnabled) {
			this.resourceName = resourceName;
			this.proxyingEnabled = proxyingEnabled;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * org.apache.http.nio.protocol.HttpAsyncRequestHandler#handle(java.
		 * lang.Object, org.apache.http.nio.protocol.HttpAsyncExchange,
		 * org.apache.http.protocol.HttpContext)
		 */
		@Override
		public void handle(HttpRequest httpRequest, HttpAsyncExchange httpExchange, HttpContext httpContext)
				throws HttpException, IOException {

			HttpInetConnection connection = (HttpInetConnection) httpContext
					.getAttribute(HttpCoreContext.HTTP_CONNECTION);
			InetSocketAddress endpoint = new InetSocketAddress(connection.getLocalAddress(),connection.getLocalPort());
			InetSocketAddress source = new InetSocketAddress(connection.getRemoteAddress(), connection.getRemotePort());

			LOGGER.debug("handler {}, proxy {}", resourceName, proxyingEnabled);
			LOGGER.debug("Incoming http request: on {} from {}{}   {}", endpoint, source, StringUtil.lineSeparator(),
					httpRequest.getRequestLine());

			final HttpRequestContext httpRequestContext = new HttpRequestContext(httpExchange);
			try {
				// translate the request in a valid coap request
				Request coapRequest = new HttpTranslator().getCoapRequest(httpRequest, resourceName, proxyingEnabled);
				// if (Bench_Help.DO_LOG)
				LOGGER.info("Received HTTP request and translate to {}", coapRequest);
				coapRequest.setSourceContext(new AddressEndpointContext(source));
				coapRequest.setDestinationContext(new AddressEndpointContext(endpoint));
				// handle the requset
				doReceiveMessage(coapRequest, httpRequestContext);
			} catch (InvalidMethodException e) {
				LOGGER.warn("Method not implemented", e);
				httpRequestContext.sendSimpleHttpResponse(HttpTranslator.STATUS_WRONG_METHOD, e.getMessage());
			} catch (InvalidFieldException e) {
				LOGGER.warn("Request malformed", e);
				httpRequestContext.sendSimpleHttpResponse(HttpTranslator.STATUS_URI_MALFORMED, e.getMessage());
			} catch (TranslationException e) {
				LOGGER.warn("Failed to translate the http request in a valid coap request", e);
				httpRequestContext.sendSimpleHttpResponse(HttpTranslator.STATUS_TRANSLATION_ERROR, e.getMessage());
			} catch (Throwable e) {
				LOGGER.error("Unexpected error", e);
				httpRequestContext.sendSimpleHttpResponse(HttpTranslator.STATUS_INTERNAL_SERVER_ERROR, e.getMessage());
			}
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * org.apache.http.nio.protocol.HttpAsyncRequestHandler#processRequest
		 * (org.apache.http.HttpRequest, org.apache.http.protocol.HttpContext)
		 */
		@Override
		public HttpAsyncRequestConsumer<HttpRequest> processRequest(HttpRequest httpRequest, HttpContext httpContext)
				throws HttpException, IOException {
			// Buffer request content in memory for simplicity
			return new BasicAsyncRequestConsumer();
		}
	}
}
