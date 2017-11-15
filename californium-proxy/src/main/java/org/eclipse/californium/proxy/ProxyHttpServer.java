/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.proxy;

import java.io.IOException;
import java.net.SocketException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.proxy.resources.ForwardingResource;
import org.eclipse.californium.proxy.resources.ProxyCacheResource;
import org.eclipse.californium.proxy.resources.StatsResource;


/**
 * The class represent the container of the resources and the layers used by the
 * proxy. A URI of an HTTP request might look like this:
 * http://localhost:8080/proxy/coap://localhost:5683/example
 */
public class ProxyHttpServer {

	private final static Logger LOGGER = Logger.getLogger(ProxyHttpServer.class.getCanonicalName());

	private final ProxyCacheResource cacheResource = new ProxyCacheResource(true);
	private final StatsResource statsResource = new StatsResource(cacheResource);
	
	private HttpStack httpStack;

	private ForwardingResource coap2coap;

	/**
	 * Instantiates a new proxy endpoint from the default ports.
	 * 
	 * @throws SocketException
	 *             the socket exception
	 */
	public ProxyHttpServer(ForwardingResource coap) throws IOException {
		this(coap, NetworkConfig.getStandard().getInt(NetworkConfig.Keys.HTTP_PORT));
	}

	/**
	 * Instantiates a new proxy endpoint.
	 * 
	 * @param httpPort
	 *            the http port
	 * @throws IOException
	 *             the socket exception
	 */
	public ProxyHttpServer(ForwardingResource coap, int httpPort) throws IOException {
	
		this.httpStack = new HttpStack(httpPort);
		this.httpStack.setRequestHandler(new RequestHandler() {
			public void handleRequest(Request request) {
				ProxyHttpServer.this.handleRequest(request);
			}
		});
		this.coap2coap = coap;
	}

	public void handleRequest(final Request request) {
		
		Exchange exchange = new Exchange(request, Origin.REMOTE) {

			@Override
			public void sendAccept() {
				// has no meaning for HTTP: do nothing
			}
			@Override
			public void sendReject() {
				// TODO: close the HTTP connection to signal rejection
			}
			@Override
			public void sendResponse(Response response) {
				// Redirect the response to the HttpStack instead of a normal
				// CoAP endpoint.
				// TODO: When we change endpoint to be an interface, we can
				// redirect the responses a little more elegantly.
				try {
					request.setResponse(response);
					responseProduced(request, response);
					httpStack.doSendResponse(request, response);
					LOGGER.info("HTTP returned " + response);
				} catch (Exception e) {
					LOGGER.log(Level.WARNING, "Exception while responding to Http request", e);
				}
			}
		};
		exchange.setRequest(request);
		
		Response response = null;
		// ignore the request if it is reset or acknowledge
		// check if the proxy-uri is defined
		if (request.getType() != Type.RST && request.getType() != Type.ACK 
				&& request.getOptions().hasProxyUri()) {
			// get the response from the cache
			response = cacheResource.getResponse(request);

				LOGGER.info("Cache returned "+response);

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
			// HttpTranslator set Proxy-Uri from HTTP URI template
			// handle the request as usual
			coap2coap.handleRequest(exchange);
		}
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
}
