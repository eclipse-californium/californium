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
import java.util.concurrent.Executor;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.proxy2.config.Proxy2Config;
import org.eclipse.californium.proxy2.http.Http2CoapTranslator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The class represent the container of the resources and the layers used by the
 * proxy. A URI of an HTTP request might look like this:
 * http://localhost:8080/proxy/coap://localhost:5683/example
 */
public class ProxyHttpServer {

	private final static Logger LOGGER = LoggerFactory.getLogger(ProxyHttpServer.class);

	private final HttpStack httpStack;
	private final MessageDeliverer proxyCoapDeliverer;
	private final MessageDeliverer localCoapDeliverer;

	/**
	 * Instantiates a new proxy http server endpoint.
	 * 
	 * @param config configuration
	 * @param executor the executor to process the coap-exchanges
	 * @param bind the http interface
	 * @param translator the http translator
	 * @param proxyCoapDeliverer the proxy-coap-deliverer. May be {@code null},
	 *            if a local-coap-deliverer is provided
	 * @param localCoapDeliverer the local-coap-deliverer. May be {@code null},
	 *            if a proxy-coap-deliverer is provided
	 * @throws IOException the socket exception
	 * @since 3.0
	 */
	private ProxyHttpServer(Configuration config, Executor executor, InetSocketAddress bind,
			Http2CoapTranslator translator, MessageDeliverer proxyCoapDeliverer, MessageDeliverer localCoapDeliverer)
			throws IOException {
		this.proxyCoapDeliverer = proxyCoapDeliverer;
		this.localCoapDeliverer = localCoapDeliverer;
		this.httpStack = new HttpStack(config, executor, bind, translator, new MessageDeliverer() {

			@Override
			public void deliverRequest(Exchange exchange) {
				handleRequest(exchange);
			}

			@Override
			public void deliverResponse(Exchange exchange, Response response) {
			}
		});
		if (proxyCoapDeliverer != null) {
			httpStack.registerProxyRequestHandler();
			httpStack.registerHttpProxyRequestHandler();
		}
		if (localCoapDeliverer != null) {
			httpStack.registerLocalRequestHandler();
		}
		httpStack.registerDefaultHandler();
	}

	/**
	 * Get address of http network interface.
	 * 
	 * @return address of http network interface.
	 * @since 3.0
	 */
	public InetSocketAddress getInterface() {
		return httpStack.getInterface();
	}

	/**
	 * Start http server.
	 */
	public void start() {
		httpStack.start();
	}

	/**
	 * Stop http server.
	 */
	public void stop() {
		httpStack.stop();
	}

	/**
	 * Handles incoming coap requests.
	 * 
	 * @param exchange coap exchange
	 */
	public void handleRequest(final Exchange exchange) {
		final Request request = exchange.getRequest();
		LOGGER.info("ProxyEndpoint handles request {}", request);
		if (request.getOptions().hasProxyUri()) {
			// handle the request as usual
			if (proxyCoapDeliverer != null) {
				proxyCoapDeliverer.deliverRequest(exchange);
			} else {
				exchange.sendResponse(new Response(ResponseCode.PROXY_NOT_SUPPORTED));
			}
		} else {
			if (localCoapDeliverer != null) {
				localCoapDeliverer.deliverRequest(exchange);
			} else {
				exchange.sendResponse(new Response(ResponseCode.PROXY_NOT_SUPPORTED));
			}
		}
	}

	/**
	 * Create builder for proxy http-server.
	 * 
	 * @return builder
	 * @since 3.0
	 */
	public static Builder buider() {
		return new Builder();
	}

	/**
	 * Builder for proxy http-server.
	 * 
	 * @since 3.0
	 */
	public static class Builder {

		/**
		 * Configuration to use.
		 */
		private Configuration config;
		/**
		 * Local address to bind.
		 */
		private InetSocketAddress bindAddress;
		/**
		 * Executor for coap-exchanges.
		 */
		private Executor executor;
		/**
		 * Proxy coap-message deliverer.
		 */
		private MessageDeliverer proxyCoapDeliverer;
		/**
		 * Local coap-message deliverer.
		 */
		private MessageDeliverer localCoapDeliverer;
		/**
		 * Http translator.
		 */
		private Http2CoapTranslator translator;

		/**
		 * Set Configuration to use.
		 * 
		 * Default is {@link Configuration#getStandard()}.
		 * 
		 * Provides a fluent API to chain setters.
		 * 
		 * @param config configuration to use
		 * @return this builder to chain setters
		 */
		public Builder setConfiguration(Configuration config) {
			this.config = config;
			return this;
		}

		/**
		 * Set http port for server.
		 * 
		 * Default is {@link Proxy2Config#HTTP_PORT}.
		 * 
		 * Provides a fluent API to chain setters.
		 * 
		 * @param port port for http server
		 * @return this builder to chain setters
		 * @throws IllegalStateException if bind address is already provided
		 */
		public Builder setPort(int port) {
			if (this.bindAddress != null) {
				throw new IllegalStateException("bind address already defined!");
			}
			this.bindAddress = new InetSocketAddress(port);
			return this;
		}

		/**
		 * Set local http interface for server.
		 * 
		 * Default is any-interface at {@link Proxy2Config#HTTP_PORT}.
		 * 
		 * Provides a fluent API to chain setters.
		 * 
		 * @param address local interface for http server
		 * @return this builder to chain setters
		 * @throws IllegalStateException if bind address is already provided
		 */
		public Builder setInetSocketAddress(InetSocketAddress address) {
			if (this.bindAddress != null) {
				throw new IllegalStateException("bind address already defined!");
			}
			this.bindAddress = address;
			return this;
		}

		/**
		 * Set executor for coap-exchanges.
		 * 
		 * The Executor is mandatory.
		 * 
		 * Provides a fluent API to chain setters.
		 * 
		 * @param executor executor for coap-exchanges
		 * @return this builder to chain setters
		 */
		public Builder setExecutor(Executor executor) {
			this.executor = executor;
			return this;
		}

		/**
		 * Set http translator for incoming http requests and outgoing http
		 * responses.
		 * 
		 * Forwarded to {@link HttpStack}.
		 * 
		 * Provides a fluent API to chain setters.
		 * 
		 * @param translator http translator
		 * @return this builder to chain setters
		 */
		public Builder setHttpTranslator(Http2CoapTranslator translator) {
			this.translator = translator;
			return this;
		}

		/**
		 * Set deliverer for forward proxy.
		 * 
		 * Registers {@link HttpStack#registerProxyRequestHandler()} and
		 * {@link HttpStack#registerHttpProxyRequestHandler()}.
		 * 
		 * Provides a fluent API to chain setters.
		 * 
		 * @param deliverer message deliverer for proxy-requests
		 * @return this builder to chain setters
		 */
		public Builder setProxyCoapDeliverer(MessageDeliverer deliverer) {
			this.proxyCoapDeliverer = deliverer;
			return this;
		}

		/**
		 * Set deliverer for local coap resources.
		 * 
		 * Registers {@link HttpStack#registerLocalRequestHandler()}.
		 * 
		 * Provides a fluent API to chain setters.
		 * 
		 * @param deliverer message deliverer for local coap resources
		 * @return this builder to chain setters
		 */
		public Builder setLocalCoapDeliverer(MessageDeliverer deliverer) {
			this.localCoapDeliverer = deliverer;
			return this;
		}

		/**
		 * Build a proxy http server.
		 * 
		 * @return created proxy http server
		 * @throws IOException the socket exception
		 * @throws IllegalStateException if the executor or a coap-deliverer is
		 *             missing
		 */
		public ProxyHttpServer build() throws IOException {
			if (executor == null) {
				throw new IllegalStateException("Executor missing!");
			}
			if (proxyCoapDeliverer == null && localCoapDeliverer == null) {
				throw new IllegalStateException("At least one coap-deliver must be provided!");
			}
			if (config == null) {
				config = Configuration.getStandard();
			}
			if (bindAddress == null) {
				bindAddress = new InetSocketAddress(config.get(Proxy2Config.HTTP_PORT));
			}
			if (translator == null) {
				translator = new Http2CoapTranslator();
			}
			return new ProxyHttpServer(config, executor, bindAddress, translator, proxyCoapDeliverer,
					localCoapDeliverer);
		}
	}
}
