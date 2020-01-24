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
package org.eclipse.californium.proxy.resources;

import java.net.InetSocketAddress;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.proxy.Coap2CoapTranslator;
import org.eclipse.californium.proxy.EndpointPool;
import org.eclipse.californium.proxy.TranslationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resource that forwards a coap request with the proxy-uri option set to the
 * desired coap server.
 */
public class Proxy2CoapClientResource extends CoapResource {

	private static final Logger LOGGER = LoggerFactory.getLogger(Proxy2CoapClientResource.class);

	/**
	 * Destroy endpoint pools.
	 */
	private boolean destroyPool;
	/**
	 * Accept CON request before forwarding it.
	 */
	private boolean accept;
	/**
	 * Maps scheme to endpoint pool.
	 */
	private Map<String, EndpointPool> mapSchemeToPool = new HashMap<>();
	/**
	 * Coap2Coap translator.
	 */
	private Coap2CoapTranslator translator;

	public Proxy2CoapClientResource() {
		this("coapClient", true, new Coap2CoapTranslator(), new EndpointPool());
		destroyPool = true;
	}

	public Proxy2CoapClientResource(String name) {
		this(name, true, new Coap2CoapTranslator(), new EndpointPool());
		destroyPool = true;
	}

	/**
	 * Create proxy resource.
	 * 
	 * @param name name of the resource
	 * @param accept accept CON request befor forwarding the request
	 * @param translator translater for coap2coap messages. {@code null} to sue
	 *            default implementation {@link Coap2CoapTranslator}.
	 * @param pools list of endpoint pools for outgoing requests
	 */
	public Proxy2CoapClientResource(String name, boolean accept, Coap2CoapTranslator translator, EndpointPool... pools) {
		// set the resource hidden
		super(name, true);
		getAttributes().setTitle("Forward the requests to a CoAP server.");
		this.accept = accept;
		this.translator = translator;
		for (EndpointPool pool : pools) {
			this.mapSchemeToPool.put(pool.getScheme(), pool);
		}
	}

	public void destroy() {
		if (destroyPool) {
			for (EndpointPool pool : mapSchemeToPool.values()) {
				pool.destroy();
			}
		}
	}

	@Override
	public void handleRequest(final Exchange exchange) {
		Request incomingRequest = exchange.getRequest();
		LOGGER.debug("ProxyCoapClientResource forwards {}", incomingRequest);

		EndpointPool pool = null;
		Endpoint outgoingEndpoint = null;

		try {
			// create the new request from the original
			InetSocketAddress exposedInterface = translator.getExposedInterface(incomingRequest);
			URI destination = translator.getDestinationURI(incomingRequest, exposedInterface);
			Request outgoingRequest = translator.getRequest(destination, incomingRequest);
			pool = mapSchemeToPool.get(outgoingRequest.getScheme());
			outgoingEndpoint = pool.getEndpoint();

			// prepare to process the outcome
			outgoingRequest.addMessageObserver(new ProxyMessageObserver(pool, translator, exchange, outgoingEndpoint));

			// execute the request
			if (outgoingRequest.getDestinationContext() == null) {
				exchange.sendResponse(new Response(ResponseCode.INTERNAL_SERVER_ERROR));
				pool.release(outgoingEndpoint);
				throw new NullPointerException("Destination is null");
			}
			LOGGER.debug("Sending proxied CoAP request to {}", outgoingRequest.getDestinationContext());
			if (accept) {
				exchange.sendAccept();
			}
			outgoingEndpoint.sendRequest(outgoingRequest);
		} catch (TranslationException e) {
			LOGGER.debug("Proxy-uri option malformed: {}", e.getMessage());
			exchange.sendResponse(new Response(Coap2CoapTranslator.STATUS_FIELD_MALFORMED));
		} catch (Exception e) {
			LOGGER.warn("Failed to execute request: {}", e.getMessage(), e);
			exchange.sendResponse(new Response(ResponseCode.INTERNAL_SERVER_ERROR));
			if (pool != null) {
				pool.release(outgoingEndpoint);
			}
		}
	}

	private static class ProxyMessageObserver extends MessageObserverAdapter {

		private final EndpointPool pool;
		private final Coap2CoapTranslator translator;
		private final Exchange incomingExchange;
		private final Endpoint outgoingEndpoint;

		private ProxyMessageObserver(EndpointPool pool, Coap2CoapTranslator translator, Exchange incomingExchange,
				Endpoint outgoingEndpoint) {
			this.pool = pool;
			this.translator = translator;
			this.incomingExchange = incomingExchange;
			this.outgoingEndpoint = outgoingEndpoint;
		}

		@Override
		public void onResponse(Response incomingResponse) {
			LOGGER.debug("ProxyCoapClientResource received {}", incomingResponse);
			incomingExchange.sendResponse(translator.getResponse(incomingResponse));
			pool.release(outgoingEndpoint);
		}

		@Override
		public void onReject() {
			fail(ResponseCode.SERVICE_UNAVAILABLE);
			LOGGER.debug("Request rejected");
		}

		@Override
		public void onTimeout() {
			fail(ResponseCode.GATEWAY_TIMEOUT);
			LOGGER.debug("Request timed out.");
		}

		@Override
		public void onCancel() {
			fail(ResponseCode.SERVICE_UNAVAILABLE);
			LOGGER.debug("Request canceled");
		}

		@Override
		public void onSendError(Throwable e) {
			fail(ResponseCode.SERVICE_UNAVAILABLE);
			LOGGER.warn("Send error", e);
		}

		private void fail(ResponseCode response) {
			incomingExchange.sendResponse(new Response(response));
			pool.release(outgoingEndpoint);
		}
	}
}
