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

import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.core5.concurrent.FutureCallback;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.Message;
import org.apache.hc.core5.http.message.StatusLine;
import org.apache.hc.core5.http.nio.support.BasicResponseConsumer;
import org.apache.hc.core5.http.protocol.BasicHttpContext;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.proxy2.Coap2CoapTranslator;
import org.eclipse.californium.proxy2.CoapUriTranslator;
import org.eclipse.californium.proxy2.InvalidFieldException;
import org.eclipse.californium.proxy2.TranslationException;
import org.eclipse.californium.proxy2.http.Coap2HttpTranslator;
import org.eclipse.californium.proxy2.http.ContentTypedEntity;
import org.eclipse.californium.proxy2.http.ContentTypedEntityConsumer;
import org.eclipse.californium.proxy2.http.HttpClientFactory;
import org.eclipse.californium.proxy2.http.ProxyRequestProducer;
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

	/**
	 * Create proxy resource for outgoing http-requests.
	 * 
	 * @param name name of the resource
	 * @param visible visibility of the resource
	 * @param accept accept CON request before forwarding the request
	 * @param translator translator for coap2coap messages. {@code null} to use
	 *            default implementation {@link Coap2HttpTranslator}.
	 * @param schemes supported schemes. "http" or "https". If empty, "http" is
	 *            used.
	 */
	public ProxyHttpClientResource(String name, boolean visible, boolean accept, Coap2HttpTranslator translator,
			String... schemes) {
		// set the resource hidden
		super(name, visible, accept);
		getAttributes().setTitle("Forward the requests to a HTTP client.");
		this.translator = translator != null ? translator : new Coap2HttpTranslator();
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

		URI destination;
		try {
			InetSocketAddress exposedInterface = translator.getExposedInterface(incomingCoapRequest);
			destination = translator.getDestinationURI(incomingCoapRequest, exposedInterface);
		} catch (TranslationException ex) {
			LOGGER.debug("URI error.", ex);
			Response response = new Response(Coap2CoapTranslator.STATUS_FIELD_MALFORMED);
			response.setPayload(ex.getMessage());
			exchange.sendResponse(response);
			return;
		}

		final CacheKey cacheKey;
		final CacheResource cache = getCache();
		if (cache != null) {
			cacheKey = new CacheKey(incomingCoapRequest.getCode(), destination,
					incomingCoapRequest.getOptions().getAccept(), incomingCoapRequest.getPayload());
			Response response = cache.getResponse(cacheKey);
			StatsResource statsResource = getStatsResource();
			if (statsResource != null) {
				statsResource.updateStatistics(destination, response != null);
			}
			if (response != null) {
				LOGGER.info("Cache returned {}", response);
				exchange.sendResponse(response);
				return;
			}
		} else {
			cacheKey = null;
		}

		ProxyRequestProducer httpRequest = null;
		try {
			// get the mapping to http for the incoming coap request
			httpRequest = translator.getHttpRequest(destination, incomingCoapRequest);
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

		asyncClient.execute(httpRequest,
				new BasicResponseConsumer<ContentTypedEntity>(new ContentTypedEntityConsumer()), new BasicHttpContext(),
				new FutureCallback<Message<HttpResponse, ContentTypedEntity>>() {

					@Override
					public void completed(Message<HttpResponse, ContentTypedEntity> result) {
						StatusLine status = new StatusLine(result.getHead());
						try {
							long timestamp = ClockUtil.nanoRealtime();
							LOGGER.debug("Incoming http response: {}", status);
							// translate the received http response in a coap
							// response
							Response coapResponse = translator.getCoapResponse(result, incomingCoapRequest);
							int size = coapResponse.getPayloadSize();
							if (!checkMaxResourceBodySize(size)) {
								coapResponse = new Response(ResponseCode.BAD_GATEWAY);
								coapResponse.setPayload(
										"HTTP response of " + size + " bytes exceeds maximum support size of "
												+ getMaxResourceBodySize() + " bytes!");
								coapResponse.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
							}
							coapResponse.setNanoTimestamp(timestamp);
							if (cache != null) {
								cache.cacheResponse(cacheKey, coapResponse);
							}
							exchange.sendResponse(coapResponse);
						} catch (InvalidFieldException e) {
							LOGGER.debug("Problems during the http/coap translation: {}", e.getMessage());
							Response response = new Response(Coap2CoapTranslator.STATUS_FIELD_MALFORMED);
							response.setPayload(e.getMessage());
							response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
							exchange.sendResponse(response);
						} catch (TranslationException e) {
							LOGGER.debug("Problems during the http/coap translation: {}", e.getMessage());
							Response response = new Response(Coap2CoapTranslator.STATUS_TRANSLATION_ERROR);
							response.setPayload(e.getMessage());
							response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
							exchange.sendResponse(response);
						} catch (Throwable e) {
							LOGGER.debug("Error during the http/coap translation: {}", e.getMessage(), e);
							Response response = new Response(Coap2CoapTranslator.STATUS_FIELD_MALFORMED);
							response.setPayload(e.getMessage());
							response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
							exchange.sendResponse(response);
						}
						LOGGER.debug("Incoming http response: {} processed!", status);
					}

					@Override
					public void failed(Exception ex) {
						LOGGER.debug("Failed to get the http response: {}", ex.getMessage(), ex);
						if (ex instanceof SocketTimeoutException) {
							exchange.sendResponse(new Response(ResponseCode.GATEWAY_TIMEOUT));
						} else {
							Response response = new Response(ResponseCode.BAD_GATEWAY);
							response.setPayload(ex.getMessage());
							response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
							exchange.sendResponse(response);
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
	public CoapUriTranslator getUriTranslater() {
		return translator;
	}

	@Override
	public Set<String> getDestinationSchemes() {
		return Collections.unmodifiableSet(schemes);
	}

}
