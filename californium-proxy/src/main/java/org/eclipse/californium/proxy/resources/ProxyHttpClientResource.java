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

import java.net.URI;

import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.concurrent.FutureCallback;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.protocol.*;
import org.eclipse.californium.compat.CompletableFuture;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.proxy.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class ProxyHttpClientResource. This class extends ForwardingResource to
 * forward CoAP requests to HTTP target Server and translated CoAP responses
 * back to Coap Client.
 *
 */
public class ProxyHttpClientResource extends ForwardingResource {

	private static final Logger LOGGER = LoggerFactory.getLogger(ProxyHttpClientResource.class);

	/**
	 * DefaultHttpClient is thread safe. It is recommended that the same
	 * instance of this class is reused for multiple request executions.
	 */
	private static final CloseableHttpAsyncClient asyncClient = HttpClientFactory.createClient();

	/**
	 * Constructs a ProxyHttpClientResource with default resource name.
	 */
	public ProxyHttpClientResource() {
		this("httpClient");
	}

	/**
	 * Constructs a ProxyHttpClientResource with the specified resource name.
	 */
	public ProxyHttpClientResource(String name) {
		super(name, true);
		getAttributes().setTitle("Forward the requests to a HTTP client.");
	}

	@Override
	public void handleRequest(final Exchange exchange) {
		final Request incomingRequest = exchange.getRequest();
		URI uri;
		try {
			uri = UriTranslator.getDestinationURI(incomingRequest);
		} catch (TranslationException ex) {
			exchange.sendResponse(new Response(CoapTranslator.STATUS_FIELD_MALFORMED));
			return;
		}

		// get the requested host, if the port is not specified, the constructor
		// sets it to -1
		HttpHost httpHost = new HttpHost(uri.getHost(), uri.getPort(), uri.getScheme());

		HttpRequest httpRequest = null;
		try {
			// get the mapping to http for the incoming coap request
			httpRequest = new HttpTranslator().getHttpRequest(uri, incomingRequest);
			LOGGER.debug("Outgoing http request: {}", httpRequest.getRequestLine());
		} catch (InvalidFieldException e) {
			LOGGER.warn("Problems during the http/coap translation: {}", e.getMessage());
			exchange.sendResponse(new Response(CoapTranslator.STATUS_FIELD_MALFORMED));
			return;
		} catch (TranslationException e) {
			LOGGER.warn("Problems during the http/coap translation: {}", e.getMessage());
			exchange.sendResponse(new Response(CoapTranslator.STATUS_TRANSLATION_ERROR));
			return;
		}

		asyncClient.execute(httpHost, httpRequest, new BasicHttpContext(), new FutureCallback<HttpResponse>() {
			@Override
			public void completed(HttpResponse result) {
				long timestamp = ClockUtil.nanoRealtime();
				LOGGER.debug("Incoming http response: {}", result.getStatusLine());
				// the entity of the response, if non repeatable, could be
				// consumed only one time, so do not debug it!
				// System.out.println(EntityUtils.toString(httpResponse.getEntity()));

				// translate the received http response in a coap response
				try {
					Response coapResponse = new HttpTranslator().getCoapResponse(result, incomingRequest);
					coapResponse.setNanoTimestamp(timestamp);

					exchange.sendResponse(coapResponse);
				} catch (InvalidFieldException e) {
					LOGGER.warn("Problems during the http/coap translation: {}", e.getMessage());
					exchange.sendResponse(new Response(CoapTranslator.STATUS_FIELD_MALFORMED));
				} catch (TranslationException e) {
					LOGGER.warn("Problems during the http/coap translation: {}", e.getMessage());
					exchange.sendResponse(new Response(CoapTranslator.STATUS_TRANSLATION_ERROR));
				}
			}

			@Override
			public void failed(Exception ex) {
				LOGGER.warn("Failed to get the http response: {}", ex.getMessage());
				exchange.sendResponse(new Response(ResponseCode.INTERNAL_SERVER_ERROR));
			}

			@Override
			public void cancelled() {
				LOGGER.warn("Request canceled");
				exchange.sendResponse(new Response(ResponseCode.SERVICE_UNAVAILABLE));
			}
		});
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
