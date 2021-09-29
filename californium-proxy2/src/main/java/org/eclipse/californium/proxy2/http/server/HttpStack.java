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

package org.eclipse.californium.proxy2.http.server;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Locale;
import java.util.concurrent.Executor;

import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.EndpointDetails;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.Message;
import org.apache.hc.core5.http.impl.EnglishReasonPhraseCatalog;
import org.apache.hc.core5.http.message.RequestLine;
import org.apache.hc.core5.http.nio.AsyncServerRequestHandler.ResponseTrigger;
import org.apache.hc.core5.http.nio.support.AsyncResponseBuilder;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.http.protocol.HttpCoreContext;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.proxy2.InvalidFieldException;
import org.eclipse.californium.proxy2.InvalidMethodException;
import org.eclipse.californium.proxy2.TranslationException;
import org.eclipse.californium.proxy2.config.Proxy2Config;
import org.eclipse.californium.proxy2.http.ContentTypedEntity;
import org.eclipse.californium.proxy2.http.CrossProtocolTranslator;
import org.eclipse.californium.proxy2.http.Http2CoapTranslator;
import org.eclipse.californium.proxy2.http.ProxyResponseProducer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class encapsulating the logic of a http server. The class create a receiver
 * thread that it is always blocked on the listen primitive. For each connection
 * this thread creates a new thread that handles the client/server dialog.
 * 
 * <a href="https://tools.ietf.org/html/rfc8075" target="_blank">RFC8075 - HTTP2CoAP</a>
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
	private final Executor executor;
	private final MessageDeliverer requestDeliverer;
	private final Http2CoapTranslator translator;

	/**
	 * Instantiates a new http stack on the requested interface. It creates an
	 * http listener thread on the interface and the handlers as provided.
	 * 
	 * @param config configuration with
	 *            {@link Proxy2Config#HTTP_SERVER_SOCKET_TIMEOUT}, and
	 *            {@link Proxy2Config#HTTP_SERVER_SOCKET_BUFFER_SIZE}.
	 * @param executor the executor to process the coap-exchanges
	 * @param httpInterface the http interface
	 * @param translator http translator
	 * @param requestDeliverer message deliverer for http request
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @since 3.0 (changed parameter to Configuration)
	 */
	public HttpStack(Configuration config, Executor executor, InetSocketAddress httpInterface, Http2CoapTranslator translator, MessageDeliverer requestDeliverer) throws IOException {
		server = new HttpServer(config, httpInterface);
		this.executor = executor;
		this.translator = translator;
		this.requestDeliverer = requestDeliverer;
	}

	/**
	 * Register default handler for proxy http-server itself.
	 * 
	 * Usually only called, if http-request is no proxy-request.
	 * 
	 * @since 3.0
	 */
	void registerDefaultHandler() {
		// register the default handler for root URIs
		// wrapping a common request handler with an async request handler
		server.setSimpleResource("*", SERVER_NAME + " on %s.", null);
	}

	/**
	 * Register "local" request handler.
	 *
	 * Handles requests for
	 * {@code "http://<proxy-host>:<proxy-port>/local/<local-coap-path>"}.
	 */
	void registerLocalRequestHandler() {
		String name = "/" + LOCAL_RESOURCE_NAME;
		// register the handler for local coap resources
		server.register(name + "/*", new ProxyAsyncRequestHandler(name, false));
	}

	/**
	 * Register "proxy" request handlers.
	 *
	 * Handles proxy requests for
	 * "{@code http://<proxy-host>:<proxy-port>/proxy/<destination-uri>"}.
	 */
	void registerProxyRequestHandler() {
		String name = "/" + PROXY_RESOURCE_NAME;
		// register the handler for proxy coap resources
		ProxyAsyncRequestHandler handler = new ProxyAsyncRequestHandler(name, true);
		server.register(name + "/*", handler);
		server.register(name, handler);
	}

	/**
	 * Register http-proxy request handlers.
	 * 
	 * Enables to catch calls, if this http server is configures as http-proxy
	 * for the client. In that case, the http-request contains the URI
	 * (including the destination host).
	 * 
	 * Handles proxy requests for
	 * {@code "http://<destination>:<port>/<destination-uri>/<destination-scheme>:"}.
	 */
	void registerHttpProxyRequestHandler() {
		String name = "/" + PROXY_RESOURCE_NAME;
		// register the handler for proxy coap resources
		server.registerProxy(new ProxyAsyncRequestHandler(name, true));
	}

	/**
	 * Get address of http network interface.
	 * 
	 * @return address of http network interface.
	 * @since 3.0
	 */
	public InetSocketAddress getInterface() {
		return server.getInterface();
	}

	/**
	 * Starts the http server.
	 */
	public void start() {
		server.start();
	}

	/**
	 * Stop http server.
	 */
	public void stop() {
		server.stop();
	}

	/**
	 * Class associated with the http service to translate the http requests in
	 * coap requests and to produce the http responses. Even if the class
	 * accepts a string indicating the name of the proxy resource, it is still
	 * thread-safe because the local resource is set in the constructor and then
	 * only read by the methods.
	 */
	private class ProxyAsyncRequestHandler extends ByteBufferAsyncServerRequestHandler {

		private final String resourceName;
		private final boolean proxyingEnabled;

		/**
		 * Instantiates a new proxy request handler.
		 * 
		 * @param resourceName the http resource name
		 * @param proxyingEnabled {@code true}, enable proxy, {@code false}, otherwise.
		 */
		public ProxyAsyncRequestHandler(String resourceName, boolean proxyingEnabled) {
			this.resourceName = resourceName;
			this.proxyingEnabled = proxyingEnabled;
		}

		@Override
		public void handle(final Message<HttpRequest, ContentTypedEntity> message,
				final ResponseTrigger responseTrigger, final HttpContext context) throws HttpException, IOException {

			final HttpCoreContext coreContext = HttpCoreContext.adapt(context);
			final EndpointDetails connection = coreContext.getEndpointDetails();
			final HttpRequest request = message.getHead();
			InetSocketAddress endpoint = (InetSocketAddress) connection.getLocalAddress();
			InetSocketAddress source = (InetSocketAddress) connection.getRemoteAddress();

			LOGGER.debug("handler {}, proxy {}", resourceName, proxyingEnabled);
			LOGGER.debug("Incoming http request: on {} from {}{}   {}", endpoint, source, StringUtil.lineSeparator(),
					new RequestLine(request));

			try {
				// translate the request in a valid coap request
				final Request coapRequest = translator.getCoapRequest(message, resourceName, proxyingEnabled);
				// if (Bench_Help.DO_LOG)
				LOGGER.info("Received HTTP request and translate to {}", coapRequest);
				coapRequest.setSourceContext(new AddressEndpointContext(source));
				// keep the receiving interface.
				coapRequest.setLocalAddress(endpoint, false);
				// handle the request
				final Exchange exchange = new Exchange(coapRequest, source, Origin.REMOTE, executor) {

					@Override
					public void sendAccept() {
						// has no meaning for HTTP: do nothing
					}

					@Override
					public void sendReject() {
						sendSimpleHttpResponse(CrossProtocolTranslator.STATUS_NOT_FOUND, null, responseTrigger,
								context);
					}

					@Override
					public void sendResponse(Response response) {
						coapRequest.setResponse(response);
						sendHttpResponse(request, response, responseTrigger, context);
						LOGGER.debug("HTTP returned {}", response);
					}
				};
				exchange.execute(new Runnable() {

					@Override
					public void run() {
						requestDeliverer.deliverRequest(exchange);
					}
				});
			} catch (InvalidMethodException e) {
				LOGGER.warn("Method not implemented", e);
				sendSimpleHttpResponse(CrossProtocolTranslator.STATUS_WRONG_METHOD, e.getMessage(), responseTrigger,
						context);
			} catch (InvalidFieldException e) {
				LOGGER.warn("Request malformed", e);
				sendSimpleHttpResponse(CrossProtocolTranslator.STATUS_URI_MALFORMED, e.getMessage(), responseTrigger,
						context);
			} catch (TranslationException e) {
				LOGGER.warn("Failed to translate the http request in a valid coap request", e);
				sendSimpleHttpResponse(CrossProtocolTranslator.STATUS_TRANSLATION_ERROR, e.getMessage(),
						responseTrigger, context);
			} catch (Throwable e) {
				LOGGER.error("Unexpected error", e);
				sendSimpleHttpResponse(CrossProtocolTranslator.STATUS_INTERNAL_SERVER_ERROR, e.getMessage(),
						responseTrigger, context);
			}
		}
	}

	/**
	 * Send http response.
	 * 
	 * @param request related http request
	 * @param coapResponse coap response
	 * @param responseTrigger http response trigger
	 * @param context http context
	 */
	private void sendHttpResponse(HttpRequest request, Response coapResponse, ResponseTrigger responseTrigger,
			HttpContext context) {
		LOGGER.debug("Incoming response: {}", coapResponse);

		try {
			// translate the coap response in an http response
			ProxyResponseProducer httpResponse = translator.getHttpResponse(request, coapResponse);

			LOGGER.debug("Outgoing http response: {}", httpResponse.getStatusLine());
			// send the response
			responseTrigger.submitResponse(httpResponse, context);
		} catch (TranslationException e) {
			LOGGER.warn("Failed to translate coap response to http response: {}", e.getMessage());
			sendSimpleHttpResponse(CrossProtocolTranslator.STATUS_TRANSLATION_ERROR, null, responseTrigger, context);
		} catch (Throwable e) {
			LOGGER.warn("Failed to translate coap response to http response: {}", e.getMessage(), e);
			sendSimpleHttpResponse(CrossProtocolTranslator.STATUS_TRANSLATION_ERROR, null, responseTrigger, context);
		}
	}

	/**
	 * Send simple http response.
	 *
	 * @param httpCode the http code
	 * @param message additional message, may be {@code null}
	 * @param responseTrigger http response trigger
	 * @param context http context
	 */
	private static void sendSimpleHttpResponse(int httpCode, String message, ResponseTrigger responseTrigger,
			HttpContext context) {
		// create diagnose message
		String reason = EnglishReasonPhraseCatalog.INSTANCE.getReason(httpCode, Locale.ENGLISH);
		StringBuilder payload = new StringBuilder();
		payload.append(httpCode).append(": ").append(reason);
		if (message != null) {
			payload.append("\r\n\r\n").append(message);
		}

		try {
			responseTrigger.submitResponse(
					AsyncResponseBuilder.create(httpCode).setEntity(payload.toString(), ContentType.TEXT_PLAIN).build(),
					context);
		} catch (HttpException e) {
			LOGGER.warn("Failed to send response: {}", e.getMessage(), e);
		} catch (IOException e) {
			LOGGER.warn("Failed to send response: {}", e.getMessage(), e);
		}
	}

}
