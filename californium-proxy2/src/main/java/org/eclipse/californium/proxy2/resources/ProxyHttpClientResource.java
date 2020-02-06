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

package org.eclipse.californium.proxy2.resources;

import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.concurrent.FutureCallback;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.protocol.BasicHttpContext;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.proxy2.Coap2CoapTranslator;
import org.eclipse.californium.proxy2.Coap2HttpTranslator;
import org.eclipse.californium.proxy2.HttpClientFactory;
import org.eclipse.californium.proxy2.InvalidFieldException;
import org.eclipse.californium.proxy2.TranslationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resource that forwards a coap request with the proxy-uri, proxy-scheme,
 * URI-host, or URI-port option set to the desired http server.
 */
public class ProxyHttpClientResource extends ProxyCoapResource {

	private static final Logger LOGGER = LoggerFactory.getLogger(ProxyHttpClientResource.class);

	private final Coap2HttpTranslator translator;

	private final Set<String> schemes = new HashSet<String>();

	/**
	 * DefaultHttpClient is thread safe. It is recommended that the same
	 * instance of this class is reused for multiple request executions.
	 */
	private static final CloseableHttpAsyncClient asyncClient = HttpClientFactory.createClient();

	public ProxyHttpClientResource(String name, boolean visible, boolean accept, Coap2HttpTranslator translator,
			String... schemes) {
		// set the resource hidden
		super(name, visible, accept);
		getAttributes().setTitle("Forward the requests to a HTTP client.");
		this.translator = translator;
		if (schemes == null || schemes.length == 0) {
			this.schemes.add("http");
		} else {
			for (String scheme : schemes) {
				this.schemes.add(scheme);
			}
		}
	}

	@Override
	public void handleRequest(final Exchange exchange) {
		final Request incomingCoapRequest = exchange.getRequest();

		URI uri;
		try {
			InetSocketAddress exposedInterface = translator.getExposedInterface(incomingCoapRequest);
			uri = translator.getDestinationURI(incomingCoapRequest, exposedInterface);
		} catch (TranslationException ex) {
			LOGGER.debug("URI error.", ex);
			exchange.sendResponse(new Response(Coap2CoapTranslator.STATUS_FIELD_MALFORMED));
			return;
		}

		// get the requested host, if the port is not specified, the constructor
		// sets it to -1
		HttpHost httpHost = new HttpHost(uri.getHost(), uri.getPort(), uri.getScheme());

		HttpRequest httpRequest = null;
		try {
			// get the mapping to http for the incoming coap request
			httpRequest = translator.getHttpRequest(uri, incomingCoapRequest);
			LOGGER.debug("Outgoing http request: {}", httpRequest.getRequestLine());
		} catch (InvalidFieldException e) {
			LOGGER.debug("Problems during the http/coap translation: {}", e.getMessage());
			exchange.sendResponse(new Response(Coap2CoapTranslator.STATUS_FIELD_MALFORMED));
			return;
		} catch (TranslationException e) {
			LOGGER.debug("Problems during the http/coap translation: {}", e.getMessage());
			exchange.sendResponse(new Response(Coap2CoapTranslator.STATUS_TRANSLATION_ERROR));
			return;
		}

		if (accept) {
			exchange.sendAccept();
		}

		asyncClient.execute(httpHost, httpRequest, new BasicHttpContext(), new FutureCallback<HttpResponse>() {

			@Override
			public void completed(HttpResponse result) {
				try {
					long timestamp = ClockUtil.nanoRealtime();
					LOGGER.debug("Incoming http response: {}", result.getStatusLine());
					// the entity of the response, if non repeatable, could be
					// consumed only one time, so do not debug it!
					// System.out.println(EntityUtils.toString(httpResponse.getEntity()));

					// translate the received http response in a coap response
					Response coapResponse = translator.getCoapResponse(result, incomingCoapRequest);
					coapResponse.setNanoTimestamp(timestamp);

					exchange.sendResponse(coapResponse);
				} catch (InvalidFieldException e) {
					LOGGER.debug("Problems during the http/coap translation: {}", e.getMessage());
					exchange.sendResponse(new Response(Coap2CoapTranslator.STATUS_FIELD_MALFORMED));
				} catch (TranslationException e) {
					LOGGER.debug("Problems during the http/coap translation: {}", e.getMessage());
					exchange.sendResponse(new Response(Coap2CoapTranslator.STATUS_TRANSLATION_ERROR));
				} catch (Throwable e) {
					LOGGER.debug("Error during the http/coap translation: {}", e.getMessage(), e);
					exchange.sendResponse(new Response(Coap2CoapTranslator.STATUS_FIELD_MALFORMED));
				}
				LOGGER.debug("Incoming http response: {} processed!", result.getStatusLine());
			}

			@Override
			public void failed(Exception ex) {
				LOGGER.debug("Failed to get the http response: {}", ex.getMessage());
				if (ex instanceof SocketTimeoutException) {
					exchange.sendResponse(new Response(ResponseCode.GATEWAY_TIMEOUT));
				} else {
					exchange.sendResponse(new Response(ResponseCode.BAD_GATEWAY));
				}
			}

			@Override
			public void cancelled() {
				LOGGER.debug("Request canceled");
				exchange.sendResponse(new Response(ResponseCode.SERVICE_UNAVAILABLE));
			}
		});

	}

	@Override
	public Set<String> getDestinationSchemes() {
		return Collections.unmodifiableSet(schemes);
	}

}
