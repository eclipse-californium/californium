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

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.concurrent.CompletableFuture;

import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.concurrent.FutureCallback;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.protocol.*;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.proxy.*;

public class ProxyHttpClientResource extends ForwardingResource {
	
	/**
	 * DefaultHttpClient is thread safe. It is recommended that the same
	 * instance of this class is reused for multiple request executions.
	 */
	private static final CloseableHttpAsyncClient asyncClient = HttpClientPool.createClient();

	public ProxyHttpClientResource() {
		this(100000);
	}

	public ProxyHttpClientResource(long timeout) {
		super("httpClient");
	}

	@Override
	public CompletableFuture<Response> forwardRequest(Request request) {
		final CompletableFuture<Response> future = new CompletableFuture<>();
		final Request incomingCoapRequest = request;
		
		// check the invariant: the request must have the proxy-uri set
		if (!incomingCoapRequest.getOptions().hasProxyUri()) {
			LOGGER.warning("Proxy-uri option not set.");
			future.complete(new Response(ResponseCode.BAD_OPTION));
			return future;
		}

		// get the proxy-uri set in the incoming coap request
		URI proxyUri;
		try {
			String proxyUriString = URLDecoder.decode(incomingCoapRequest.getOptions().getProxyUri(), "UTF-8");
			proxyUri = new URI(proxyUriString);
		} catch (UnsupportedEncodingException e) {
			LOGGER.warning("Proxy-uri option malformed: " + e.getMessage());
			future.complete(new Response(CoapTranslator.STATUS_FIELD_MALFORMED));
			return future;
		} catch (URISyntaxException e) {
			LOGGER.warning("Proxy-uri option malformed: " + e.getMessage());
			future.complete(new Response(CoapTranslator.STATUS_FIELD_MALFORMED));
			return future;
		}

		// get the requested host, if the port is not specified, the constructor
		// sets it to -1
		HttpHost httpHost = new HttpHost(proxyUri.getHost(), proxyUri.getPort(), proxyUri.getScheme());

		HttpRequest httpRequest = null;
		try {
			// get the mapping to http for the incoming coap request
			httpRequest = HttpTranslator.getHttpRequest(incomingCoapRequest);
			LOGGER.finer("Outgoing http request: " + httpRequest.getRequestLine());
		} catch (InvalidFieldException e) {
			LOGGER.warning("Problems during the http/coap translation: " + e.getMessage());
			future.complete(new Response(CoapTranslator.STATUS_FIELD_MALFORMED));
			return future;
		} catch (TranslationException e) {
			LOGGER.warning("Problems during the http/coap translation: " + e.getMessage());
			future.complete(new Response(CoapTranslator.STATUS_TRANSLATION_ERROR));
			return future;
		}

		asyncClient.execute(httpHost, httpRequest, new BasicHttpContext(), new FutureCallback<HttpResponse>() {
			@Override
			public void completed(HttpResponse result) {
				long timestamp = System.nanoTime();
				LOGGER.info("Incoming http response: " + result.getStatusLine());
				// the entity of the response, if non repeatable, could be
				// consumed only one time, so do not debug it!
				// System.out.println(EntityUtils.toString(httpResponse.getEntity()));

				// translate the received http response in a coap response
				try {
					Response coapResponse = HttpTranslator.getCoapResponse(result, incomingCoapRequest);
					coapResponse.setTimestamp(timestamp);

					future.complete(coapResponse);
				} catch (InvalidFieldException e) {
					LOGGER.warning("Problems during the http/coap translation: " + e.getMessage());
					future.complete(new Response(CoapTranslator.STATUS_FIELD_MALFORMED));
				} catch (TranslationException e) {
					LOGGER.warning("Problems during the http/coap translation: " + e.getMessage());
					future.complete(new Response(CoapTranslator.STATUS_TRANSLATION_ERROR));
				}
			}

			@Override
			public void failed(Exception ex) {
				LOGGER.warning("Failed to get the http response: " + ex.getMessage());
				future.complete(new Response(ResponseCode.INTERNAL_SERVER_ERROR));
			}

			@Override
			public void cancelled() {
				LOGGER.warning("Request canceled");
				future.complete(new Response(ResponseCode.SERVICE_UNAVAILABLE));
			}
		});

		return future;
	}
}
