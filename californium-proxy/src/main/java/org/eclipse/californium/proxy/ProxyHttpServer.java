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

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.proxy.resources.ProxyCacheResource;
import org.eclipse.californium.proxy.resources.StatsResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The class represent the container of the resources and the layers used by the
 * proxy. A URI of an HTTP request might look like this:
 * http://localhost:8080/proxy/coap://localhost:5683/example
 */
public class ProxyHttpServer {

	private final static Logger LOGGER = LoggerFactory.getLogger(ProxyHttpServer.class);

	private final ProxyCacheResource cacheResource = new ProxyCacheResource(true);
	private final StatsResource statsResource = new StatsResource(cacheResource);

	private ProxyCoapResolver proxyCoapResolver;
	private MessageDeliverer proxyCoapDeliverer;
	private MessageDeliverer localCoapDeliverer;
	private boolean handlerRegistered;
	private HttpStack httpStack;

	/**
	 * Create http server to access local coap resources.
	 * 
	 * @deprecated use {@link #setLocalCoapDeliverer(MessageDeliverer)} with
	 *             {@link CoapServer#getMessageDeliverer()} instead.
	 */
	@Deprecated
	public ProxyHttpServer(CoapServer server) throws IOException {
		this(new HttpStack(server.getConfig().getInt(NetworkConfig.Keys.HTTP_PORT)));
		setLocalCoapDeliverer(server.getMessageDeliverer());
	}

	/**
	 * Instantiates a new proxy endpoint.
	 * 
	 * @param httpPort the http port
	 * @throws IOException the socket exception
	 */
	public ProxyHttpServer(int httpPort) throws IOException {
		this(new HttpStack(httpPort));
	}

	/**
	 * Instantiates a new proxy endpoint.
	 * 
	 * @param config network configuration
	 * @param httpPort the http port
	 * @throws IOException the socket exception
	 */
	public ProxyHttpServer(NetworkConfig config, int httpPort) throws IOException {
		this(new HttpStack(config, httpPort));
	}

	private ProxyHttpServer(HttpStack stack) {
		this.httpStack = stack;
		this.httpStack.setRequestHandler(new RequestHandler() {

			public void handleRequest(Request request, HttpRequestContext context) {
				ProxyHttpServer.this.handleRequest(request, context);
			}
		});
	}

	/**
	 * Start http server.
	 * 
	 * @throws IOException in case if a non-recoverable I/O error.
	 */
	public void start() throws IOException {
		if (!handlerRegistered) {
			if (proxyCoapDeliverer != null || proxyCoapResolver != null) {
				httpStack.registerProxyRequestHandler();
				httpStack.registerHttpProxyRequestHandler();
			}
			if (localCoapDeliverer != null || proxyCoapResolver != null) {
				httpStack.registerLocalRequestHandler();
			}
			handlerRegistered = true;
		}
		httpStack.start();
	}

	/**
	 * Stop http server.
	 */
	public void stop() {
		httpStack.stop();
	}

	public void handleRequest(final Request request, final HttpRequestContext context) {

		LOGGER.info("ProxyEndpoint handles request {}", request);

		Exchange exchange = new Exchange(request, Origin.REMOTE, null) {

			@Override
			public void sendAccept() {
				// has no meaning for HTTP: do nothing
			}

			@Override
			public void sendReject() {
				context.handleRequestForwarding(null);
			}

			@Override
			public void sendResponse(Response response) {
				// Redirect the response to the HttpStack instead of a normal
				// CoAP endpoint.
				// TODO: When we change endpoint to be an interface, we can
				// redirect the responses a little more elegantly.
				request.setResponse(response);
				responseProduced(request, response);
				context.handleRequestForwarding(response);
				LOGGER.debug("HTTP returned {}", response);
			}
		};

		Response response = null;
		// ignore the request if it is reset or acknowledge
		// check if the proxy-uri is defined
		if (request.getOptions().hasProxyUri()) {
			// get the response from the cache
			response = cacheResource.getResponse(request);

			LOGGER.debug("Cache returned {}", response);

			// update statistics
			statsResource.updateStatistics(request, response != null);
		}

		// check if the response is present in the cache
		if (response != null) {
			// link the retrieved response with the request to set the
			// parameters request-specific (i.e., token, id, etc)
			exchange.sendResponse(response);
			return;
		} else {

			if (request.getOptions().hasProxyUri()) {
				// handle the request as usual
				if (proxyCoapDeliverer != null) {
					proxyCoapDeliverer.deliverRequest(exchange);
				} else if (proxyCoapResolver != null) {
					proxyCoapResolver.forwardRequest(exchange);
				} else {
					exchange.sendResponse(new Response(ResponseCode.PROXY_NOT_SUPPORTED));
				}
			} else {
				if (localCoapDeliverer != null) {
					localCoapDeliverer.deliverRequest(exchange);
				} else if (proxyCoapResolver != null) {
					proxyCoapResolver.forwardRequest(exchange);
				} else {
					exchange.sendResponse(new Response(ResponseCode.PROXY_NOT_SUPPORTED));
				}
			}

			/*
			 * Martin: Originally, the request was delivered to the
			 * ProxyCoAP2Coap which was at the path proxy/coapClient or to
			 * proxy/httpClient This approach replaces this implicit fuzzy
			 * connection with an explicit and dynamically changeable one.
			 */
		}
	}

	public Resource getStatistics() {
		return statsResource;
	}

	/**
	 * Set deliverer for forward proxy.
	 * 
	 * Register {@link HttpStack#registerProxyRequestHandler()} and
	 * {@link HttpStack#registerHttpProxyRequestHandler()} on {@link #start()}.
	 * 
	 * @param deliverer mesage deliverer for proxy-requests
	 */
	public void setProxyCoapDeliverer(MessageDeliverer deliverer) {
		this.proxyCoapDeliverer = deliverer;
	}

	/**
	 * Set deliverer for local coap resources.
	 * 
	 * Register {@link HttpStack#registerLocalRequestHandler()} on
	 * {@link #start()}.
	 * 
	 * @param deliverer mesage deliverer for local coap resources
	 */
	public void setLocalCoapDeliverer(MessageDeliverer deliverer) {
		this.localCoapDeliverer = deliverer;
	}

	protected void responseProduced(Request request, Response response) {
		// check if the proxy-uri is defined
		if (request.getOptions().hasProxyUri()) {
			LOGGER.info("Cache response");
			// insert the response in the cache
			cacheResource.cacheResponse(request, response);
		} else {
			LOGGER.info("Do not cache response");
		}
	}

	/**
	 * @deprecated use {@link MessageDeliverer} instead. This getter will be
	 *             removed without replacement!
	 */
	@Deprecated
	public ProxyCoapResolver getProxyCoapResolver() {
		return proxyCoapResolver;
	}

	/**
	 * @deprecated use {@link #setProxyCoapDeliverer(MessageDeliverer)} or
	 *             {@link #setLocalCoapDeliverer(MessageDeliverer)} instead.
	 */
	@Deprecated
	public void setProxyCoapResolver(ProxyCoapResolver proxyCoapResolver) {
		this.proxyCoapResolver = proxyCoapResolver;
	}
}
