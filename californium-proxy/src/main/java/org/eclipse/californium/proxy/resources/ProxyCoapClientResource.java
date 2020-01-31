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

import org.eclipse.californium.compat.CompletableFuture;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.proxy.CoapTranslator;
import org.eclipse.californium.proxy.EndPointManagerPool;
import org.eclipse.californium.proxy.TranslationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Resource that forwards a coap request with the proxy-uri option set to the
 * desired coap server.
 */
public class ProxyCoapClientResource extends ForwardingResource {

	private static final Logger LOGGER = LoggerFactory.getLogger(ProxyCoapClientResource.class);

	public ProxyCoapClientResource() {
		this("coapClient");
	} 
	
	public ProxyCoapClientResource(String name) {
		// set the resource hidden
		super(name, true);
		getAttributes().setTitle("Forward the requests to a CoAP server.");
	}

	@Override
	public CompletableFuture<Response> forwardRequest(Request incomingRequest) {
		final CompletableFuture<Response> future = new CompletableFuture<>();

		LOGGER.info("ProxyCoapClientResource forwards {}", incomingRequest);

		// check the invariant: the request must have the proxy-uri set
		if (!incomingRequest.getOptions().hasProxyUri()) {
			LOGGER.warn("Proxy-uri option not set.");
			future.complete(new Response(ResponseCode.BAD_OPTION));
			return future;
		}

		// remove the fake uri-path
		// FIXME: HACK // TODO: why? still necessary in new Cf?
		incomingRequest.getOptions().clearUriPath();

		final EndpointManager endpointManager = EndPointManagerPool.getManager();

		// create a new request to forward to the requested coap server
		Request outgoingRequest = null;
		try {
			// create the new request from the original
			outgoingRequest = CoapTranslator.getRequest(incomingRequest);

			// receive the response
			outgoingRequest.addMessageObserver(new MessageObserverAdapter() {

				@Override
				public void onResponse(Response incomingResponse) {
					LOGGER.debug("ProxyCoapClientResource received {}", incomingResponse);
					future.complete(CoapTranslator.getResponse(incomingResponse));
					EndPointManagerPool.putClient(endpointManager);
				}

				@Override
				public void onReject() {
					LOGGER.warn("Request rejected");
					future.complete(new Response(ResponseCode.SERVICE_UNAVAILABLE));
					EndPointManagerPool.putClient(endpointManager);
				}

				@Override
				public void onTimeout() {
					LOGGER.warn("Request timed out.");
					future.complete(new Response(ResponseCode.GATEWAY_TIMEOUT));
					EndPointManagerPool.putClient(endpointManager);
				}

				@Override
				public void onCancel() {
					LOGGER.warn("Request canceled");
					future.complete(new Response(ResponseCode.SERVICE_UNAVAILABLE));
					EndPointManagerPool.putClient(endpointManager);
				}

				@Override
				public void onSendError(Throwable e) {
					future.complete(new Response(ResponseCode.SERVICE_UNAVAILABLE));
					LOGGER.warn("Send error", e);
					EndPointManagerPool.putClient(endpointManager);
				}

				@Override
				public void onContextEstablished(EndpointContext endpointContext) {
				}
			});

			// execute the request
			LOGGER.debug("Sending proxied CoAP request.");

			if (outgoingRequest.getDestination() == null) {
				throw new NullPointerException("Destination is null");
			}
			if (outgoingRequest.getDestinationPort() == 0) {
				throw new NullPointerException("Destination port is 0");
			}

			endpointManager.getDefaultEndpoint().sendRequest(outgoingRequest);
		} catch (TranslationException e) {
			LOGGER.warn("Proxy-uri option malformed: {}", e.getMessage());
			future.complete(new Response(CoapTranslator.STATUS_FIELD_MALFORMED));
			return future;
		} catch (Exception e) {
			LOGGER.warn("Failed to execute request: {}", e.getMessage());
			future.complete(new Response(ResponseCode.INTERNAL_SERVER_ERROR));
			return future;
		}

		return future;
	}
}
