/*******************************************************************************
 * Copyright (c) 2020 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - derived from org.eclipse.californium.proxy
 ******************************************************************************/

package org.eclipse.californium.proxy2;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.util.Locale;

import org.apache.http.HttpEntity;
import org.apache.http.HttpException;
import org.apache.http.HttpInetConnection;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.StatusLine;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.EnglishReasonPhraseCatalog;
import org.apache.http.message.BasicStatusLine;
import org.apache.http.nio.protocol.BasicAsyncRequestConsumer;
import org.apache.http.nio.protocol.HttpAsyncExchange;
import org.apache.http.nio.protocol.HttpAsyncRequestConsumer;
import org.apache.http.nio.protocol.HttpAsyncRequestHandler;
import org.apache.http.nio.protocol.UriHttpAsyncRequestHandlerMapper;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpCoreContext;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.MessageDeliverer;
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
	 * http://proxy-address/{@value #PROXY_RESOURCE_NAME}/coap-server, the
	 * proxying handler will forward the request to the desired coap server.
	 */
	private static final String PROXY_RESOURCE_NAME = "proxy";

	/**
	 * The resource associated with the local resources behavior. If a client
	 * requests resource indicated by
	 * http://proxy-address/{@value #LOCAL_RESOURCE_NAME}/coap-resource, the
	 * proxying handler will forward the request to the local resource
	 * requested.
	 */
	public static final String LOCAL_RESOURCE_NAME = "local";

	private final HttpServer server;

	private Http2CoapTranslator translator;
	private MessageDeliverer requestDeliverer;

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
		this(config, new InetSocketAddress(httpPort));
	}

	/**
	 * Instantiates a new http stack on the requested interface. It creates an
	 * http listener thread on the interface and the handlers as provided.
	 * 
	 * @param config configuration with HTTP_SERVER_SOCKET_TIMEOUT and
	 *            HTTP_SERVER_SOCKET_BUFFER_SIZE.
	 * @param httpInterface the http interface
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @since 2.4
	 */
	public HttpStack(NetworkConfig config, InetSocketAddress httpInterface) throws IOException {
		server = new HttpServer(config, httpInterface);
		// register the default handler for root URIs
		// wrapping a common request handler with an async request handler
		server.setSimpleResource("*", SERVER_NAME + " on %s.", null);
	}

	/**
	 * Set http translator for incoming http requests and outgoing http
	 * responses.
	 * 
	 * set in {@link HttpStack} on {@link #start()}.
	 * 
	 * @param translator http translator
	 */
	void setHttpTranslator(Http2CoapTranslator translator) {
		this.translator = translator;
	}

	/**
	 * Register "local" request handler.
	 *
	 * Handles requests for
	 * "http://<proxy-host>:<proxy-port>/local/<local-coap-path>".
	 */
	void registerLocalRequestHandler() {
		UriHttpAsyncRequestHandlerMapper registry = server.getRequestHandlerMapper();
		// register the handler for local coap resources
		registry.register("/" + LOCAL_RESOURCE_NAME + "/*", new ProxyAsyncRequestHandler(LOCAL_RESOURCE_NAME, false));
	}

	/**
	 * Register "proxy" request handlers.
	 *
	 * Handles proxy requests for
	 * "http://<proxy-host>:<proxy-port>/proxy/<destination-uri>".
	 */
	void registerProxyRequestHandler() {
		UriHttpAsyncRequestHandlerMapper registry = server.getRequestHandlerMapper();
		// register the handler for proxy coap resources
		ProxyAsyncRequestHandler handler = new ProxyAsyncRequestHandler(PROXY_RESOURCE_NAME, true);
		registry.register("/" + PROXY_RESOURCE_NAME + "/*", handler);
		registry.register("/" + PROXY_RESOURCE_NAME, handler);
		registry.register("http*", handler);
	}

	/**
	 * Register http-proxy request handlers.
	 * 
	 * Enables to catch calls, if this http server is configures as http-proxy
	 * for the client. In that case, the http-request contains the URI
	 * (including the destination host).
	 * 
	 * Handles proxy requests for
	 * "http://<destination>:<port>/<destination-uri>/<destination-scheme>:".
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
	 * Set message deliverer for http request.
	 * 
	 * @param requestDeliverer message deliverer for http request
	 */
	public void setRequestDeliverer(MessageDeliverer requestDeliverer) {
		this.requestDeliverer = requestDeliverer;
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
		public void handle(HttpRequest httpRequest, final HttpAsyncExchange httpExchange, HttpContext httpContext)
				throws HttpException, IOException {

			HttpInetConnection connection = (HttpInetConnection) httpContext
					.getAttribute(HttpCoreContext.HTTP_CONNECTION);
			InetSocketAddress endpoint = new InetSocketAddress(connection.getLocalAddress(), connection.getLocalPort());
			InetSocketAddress source = new InetSocketAddress(connection.getRemoteAddress(), connection.getRemotePort());

			LOGGER.debug("handler {}, proxy {}", resourceName, proxyingEnabled);
			LOGGER.debug("Incoming http request: on {} from {}{}   {}", endpoint, source, StringUtil.lineSeparator(),
					httpRequest.getRequestLine());

			try {
				// translate the request in a valid coap request
				final Request coapRequest = translator.getCoapRequest(httpRequest, resourceName, proxyingEnabled);
				// if (Bench_Help.DO_LOG)
				LOGGER.info("Received HTTP request and translate to {}", coapRequest);
				coapRequest.setSourceContext(new AddressEndpointContext(source));
				// use destination of incoming request to keep the receiving interface.
				coapRequest.setDestinationContext(new AddressEndpointContext(endpoint));
				// handle the request
				Exchange exchange = new Exchange(coapRequest, Origin.REMOTE, null) {

					@Override
					public void sendAccept() {
						// has no meaning for HTTP: do nothing
					}

					@Override
					public void sendReject() {
						sendSimpleHttpResponse(httpExchange, HttpTranslator.STATUS_NOT_FOUND, null);
					}

					@Override
					public void sendResponse(Response response) {
						coapRequest.setResponse(response);
						sendHttpResponse(httpExchange, response);
						LOGGER.debug("HTTP returned {}", response);
					}
				};
				requestDeliverer.deliverRequest(exchange);
			} catch (InvalidMethodException e) {
				LOGGER.warn("Method not implemented", e);
				sendSimpleHttpResponse(httpExchange, HttpTranslator.STATUS_WRONG_METHOD, e.getMessage());
			} catch (InvalidFieldException e) {
				LOGGER.warn("Request malformed", e);
				sendSimpleHttpResponse(httpExchange, HttpTranslator.STATUS_URI_MALFORMED, e.getMessage());
			} catch (TranslationException e) {
				LOGGER.warn("Failed to translate the http request in a valid coap request", e);
				sendSimpleHttpResponse(httpExchange, HttpTranslator.STATUS_TRANSLATION_ERROR, e.getMessage());
			} catch (Throwable e) {
				LOGGER.error("Unexpected error", e);
				sendSimpleHttpResponse(httpExchange, HttpTranslator.STATUS_INTERNAL_SERVER_ERROR, e.getMessage());
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

	/**
	 * Sedn http response.
	 * 
	 * @param httpExchange http exchange
	 * @param coapResponse coap response
	 */
	private void sendHttpResponse(HttpAsyncExchange httpExchange, Response coapResponse) {
		LOGGER.debug("Incoming response: {}", coapResponse);

		// get the sample http response
		HttpResponse httpResponse = httpExchange.getResponse();

		try {
			// translate the coap response in an http response
			translator.getHttpResponse(httpExchange.getRequest(), coapResponse, httpResponse);

			LOGGER.debug("Outgoing http response: {}", httpResponse.getStatusLine());
			// send the response
			httpExchange.submitResponse();
		} catch (TranslationException e) {
			LOGGER.warn("Failed to translate coap response to http response: {}", e.getMessage());
			sendSimpleHttpResponse(httpExchange, HttpTranslator.STATUS_TRANSLATION_ERROR, null);
		} catch (Throwable e) {
			LOGGER.warn("Failed to translate coap response to http response: {}", e.getMessage(), e);
			sendSimpleHttpResponse(httpExchange, HttpTranslator.STATUS_TRANSLATION_ERROR, null);
		}
	}

	/**
	 * Send simple http response.
	 *
	 * @param httpExchange the http exchange
	 * @param httpCode the http code
	 * @param message additional message, maybe {@code null}
	 */
	private static void sendSimpleHttpResponse(HttpAsyncExchange httpExchange, int httpCode, String message) {
		// get the empty response from the exchange
		HttpResponse httpResponse = httpExchange.getResponse();

		// create and set the status line
		String reason = EnglishReasonPhraseCatalog.INSTANCE.getReason(httpCode, Locale.ENGLISH);
		StatusLine statusLine = new BasicStatusLine(HttpVersion.HTTP_1_1, httpCode, reason);
		httpResponse.setStatusLine(statusLine);

		try {
			StringBuilder payload = new StringBuilder();
			payload.append(httpCode).append(": ").append(reason);
			if (message != null) {
				payload.append("\r\n\r\n").append(message);
			}
			HttpEntity entity = new StringEntity(payload.toString());
			httpResponse.setEntity(entity);
		} catch (UnsupportedEncodingException e) {
		}

		// send the error response
		httpExchange.submitResponse();
	}

}
