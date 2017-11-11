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
package org.eclipse.californium.proxy.resources;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MessageObserver;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.proxy.CoapTranslator;
import org.eclipse.californium.proxy.TranslationException;

import java.util.concurrent.CompletableFuture;
import java.util.logging.Level;


/**
 * Resource that forwards a coap request with the proxy-uri option set to the
 * desired coap server.
 */
public class ProxyCoapClientResource extends ForwardingResource {
	
	private long timeout;
	
	public ProxyCoapClientResource() {
		this(100000); // 100 s
	} 
	
	public ProxyCoapClientResource(long timeout) {
		super("coap2coap");
		this.timeout = timeout;
	}

	@Override
	public CompletableFuture<Response> forwardRequest(Request incomingRequest) {
		final CompletableFuture<Response> future = new CompletableFuture<>();

		LOGGER.log(Level.INFO, "ProxyCoapClientResource forwards {0}", incomingRequest);

		// check the invariant: the request must have the proxy-uri set
		if (!incomingRequest.getOptions().hasProxyUri()) {
			LOGGER.warning("Proxy-uri option not set.");
			future.complete(new Response(ResponseCode.BAD_OPTION));
			return future;
		}

		// create a new request to forward to the requested coap server
		Request outgoingRequest = null;
		try {
			// create the new request from the original
			outgoingRequest = CoapTranslator.getRequest(incomingRequest);

			// receive the response
			outgoingRequest.addMessageObserver(new MessageObserver() {
				@Override
				public void onRetransmission() {
				}

				@Override
				public void onResponse(Response incomingResponse) {
					LOGGER.log(Level.INFO, "ProxyCoapClientResource received {0}", incomingResponse);
					future.complete(CoapTranslator.getResponse(incomingResponse));
				}

				@Override
				public void onAcknowledgement() {
				}

				@Override
				public void onReject() {
					LOGGER.warning("Request rejected");
					future.complete(new Response(ResponseCode.SERVICE_UNAVAILABLE));
				}

				@Override
				public void onTimeout() {
					LOGGER.warning("Request timed out.");
					future.complete(new Response(ResponseCode.GATEWAY_TIMEOUT));
				}

				@Override
				public void onCancel() {
					LOGGER.warning("Request canceled");
					future.complete(new Response(ResponseCode.SERVICE_UNAVAILABLE));
				}
			});

			// execute the request
			LOGGER.finer("Sending proxied CoAP request.");
			outgoingRequest.send();

		} catch (TranslationException e) {
			LOGGER.log(Level.WARNING, "Proxy-uri option malformed: {0}", e.getMessage());
			future.complete(new Response(CoapTranslator.STATUS_FIELD_MALFORMED));
			return future;
		} catch (Exception e) {
			LOGGER.log(Level.WARNING, "Failed to execute request: {0}", e.getMessage());
			future.complete(new Response(ResponseCode.INTERNAL_SERVER_ERROR));
			return future;
		}

		return future;
	}
}
