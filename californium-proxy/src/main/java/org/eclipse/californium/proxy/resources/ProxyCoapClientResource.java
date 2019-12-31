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
		LOGGER.debug("ProxyCoapClientResource forwards {}", exchange.getRequest());

		try {
			final Endpoint endpoint = pool.getEndpoint();
			// create the new request from the original
			Request outgoingRequest = CoapTranslator.getRequest(incomingRequest);
			// receive the response
			outgoingRequest.addMessageObserver(new MessageObserverAdapter() {

				@Override
				public void onResponse(Response incomingResponse) {
					LOGGER.debug("ProxyCoapClientResource received {}", incomingResponse);
					exchange.sendResponse(CoapTranslator.getResponse(incomingResponse));
					pool.release(endpoint);
				}

				@Override
				public void onReject() {
					LOGGER.warn("Request rejected");
					fail(ResponseCode.SERVICE_UNAVAILABLE);
				}

				@Override
				public void onTimeout() {
					LOGGER.warn("Request timed out.");
					fail(ResponseCode.GATEWAY_TIMEOUT);
				}

				@Override
				public void onCancel() {
					LOGGER.warn("Request canceled");
					fail(ResponseCode.SERVICE_UNAVAILABLE);
				}

				@Override
				public void onSendError(Throwable e) {
					LOGGER.warn("Send error", e);
					fail(ResponseCode.SERVICE_UNAVAILABLE);
				}

				@Override
				public void onContextEstablished(EndpointContext endpointContext) {
				}

				private void fail(ResponseCode response) {
					exchange.sendResponse(new Response(response));
					pool.release(endpoint);
				}
			});

			// execute the request
			if (outgoingRequest.getDestinationContext() == null) {
				throw new NullPointerException("DestinationContext is null");
			}
			LOGGER.debug("Sending proxied CoAP request.");
			endpoint.sendRequest(outgoingRequest);
		} catch (TranslationException e) {
			LOGGER.warn("Proxy-uri option malformed: {}", e.getMessage());
			exchange.sendResponse(new Response(CoapTranslator.STATUS_FIELD_MALFORMED));
		} catch (Exception e) {
			LOGGER.warn("Failed to execute request: {}", e.getMessage());
			exchange.sendResponse(new Response(ResponseCode.INTERNAL_SERVER_ERROR));
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
}
