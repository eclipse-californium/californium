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

import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.compat.CompletableFuture;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.proxy.CoapTranslator;
import org.eclipse.californium.proxy.EndpointPool;
import org.eclipse.californium.proxy.TranslationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Resource that forwards a coap request with the proxy-uri option set to the
 * desired coap server.
 */
public class ProxyCoapClientResource extends ForwardingResource {

	private static final Logger LOGGER = LoggerFactory.getLogger(ProxyCoapClientResource.class);

	private EndpointPool pool;
	private ScheduledExecutorService mainExecutor;
	private ScheduledExecutorService secondaryExecutor;

	public ProxyCoapClientResource() {
		this(NetworkConfig.getStandard(), "coapClient", null, null);
	}

	public ProxyCoapClientResource(String name) {
		this(NetworkConfig.getStandard(), name, null, null);
	}

	/**
	 * Create proxy resource.
	 * 
	 * @param config network configuration to be used.
	 * @param name name of the resource
	 * @param mainExecutor main executor for outgoing endpoints. {@code null} to
	 *            create a main executor based on values of the network config.
	 * @param secondaryExecutor secondary executor for outgoing endpoints.
	 *            {@code null} to create a secondary executor based on values of
	 *            the network config.
	 */
	public ProxyCoapClientResource(NetworkConfig config, String name, ScheduledExecutorService mainExecutor,
			ScheduledExecutorService secondaryExecutor) {
		// set the resource hidden
		super(name, true);
		getAttributes().setTitle("Forward the requests to a CoAP server.");
		int peers = config.getInt(NetworkConfig.Keys.MAX_ACTIVE_PEERS);
		if (peers > 2000) {
			peers = 2000;
		}
		if (mainExecutor == null) {
			int threads = config.getInt(NetworkConfig.Keys.PROTOCOL_STAGE_THREAD_COUNT);
			this.mainExecutor = ExecutorsUtil.newScheduledThreadPool(threads, new DaemonThreadFactory("Proxy#"));
			this.secondaryExecutor = ExecutorsUtil.newDefaultSecondaryScheduler("ProxyTimer#");
			mainExecutor = this.mainExecutor;
			secondaryExecutor = this.secondaryExecutor;
		}
		pool = new EndpointPool(peers, peers / 4, mainExecutor, secondaryExecutor);
	}

	public void destroy() {
		pool.destroy();
		if (mainExecutor != null) {
			ExecutorsUtil.shutdownExecutorGracefully(1000, mainExecutor);
			ExecutorsUtil.shutdownExecutorGracefully(1000, secondaryExecutor);
			mainExecutor = null;
			secondaryExecutor = null;
		}
	}

	@Override
	public void handleRequest(final Exchange exchange) {
		Request incomingRequest = exchange.getRequest();
		LOGGER.debug("ProxyCoapClientResource forwards {}", incomingRequest);

		// check the invariant: the request must have the proxy-uri set
		if (!incomingRequest.getOptions().hasProxyUri()) {
			LOGGER.debug("Proxy-uri option not set.");
			exchange.sendResponse(new Response(ResponseCode.BAD_OPTION));
			return;
		}

		// remove the fake uri-path
		// FIXME: HACK // TODO: why? still necessary in new Cf?
		incomingRequest.getOptions().clearUriPath();

		Endpoint endpoint = null;

		try {
			endpoint = pool.getEndpoint();
			// create the new request from the original
			Request outgoingRequest = CoapTranslator.getRequest(incomingRequest);

			// prepare to process the outcome
			outgoingRequest.addMessageObserver(new ProxyMessageObserver(pool, exchange, endpoint));

			// execute the request
			if (outgoingRequest.getDestinationContext() == null) {
				exchange.sendResponse(new Response(ResponseCode.INTERNAL_SERVER_ERROR));
				pool.release(endpoint);
				throw new NullPointerException("Destination is null");
			}
			LOGGER.debug("Sending proxied CoAP request.");
			endpoint.sendRequest(outgoingRequest);
		} catch (TranslationException e) {
			LOGGER.debug("Proxy-uri option malformed: {}", e.getMessage());
			exchange.sendResponse(new Response(CoapTranslator.STATUS_FIELD_MALFORMED));
			pool.release(endpoint);
		} catch (Exception e) {
			LOGGER.warn("Failed to execute request: {}", e.getMessage());
			exchange.sendResponse(new Response(ResponseCode.INTERNAL_SERVER_ERROR));
			pool.release(endpoint);
		}
	}

	@Deprecated
	@Override
	public CompletableFuture<Response> forwardRequest(final Request incomingRequest) {
		final CompletableFuture<Response> future = new CompletableFuture<>();
		Exchange exchange = new Exchange(incomingRequest, Origin.REMOTE, null) {

			@Override
			public void sendAccept() {
				// has no meaning for HTTP: do nothing
			}
			@Override
			public void sendReject() {
				future.complete(new Response(ResponseCode.SERVICE_UNAVAILABLE));
			}
			@Override
			public void sendResponse(Response response) {
				future.complete(response);
			}
		};
		handleRequest(exchange);
		return future;
	}

	private static class ProxyMessageObserver extends MessageObserverAdapter {

		private final EndpointPool pool;
		private final Exchange incomingExchange;
		private final Endpoint outgoingEndpoint;

		private ProxyMessageObserver(EndpointPool pool, Exchange incomingExchange, Endpoint outgoingEndpoint) {
			this.pool = pool;
			this.incomingExchange = incomingExchange;
			this.outgoingEndpoint = outgoingEndpoint;
		}

		@Override
		public void onResponse(Response incomingResponse) {
			LOGGER.debug("ProxyCoapClientResource received {}", incomingResponse);
			incomingExchange.sendResponse(CoapTranslator.getResponse(incomingResponse));
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

		@Override
		public void onContextEstablished(EndpointContext endpointContext) {
		}

		private void fail(ResponseCode response) {
			incomingExchange.sendResponse(new Response(response));
			pool.release(outgoingEndpoint);
		}
	}
}
