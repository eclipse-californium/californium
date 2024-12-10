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
import java.net.URI;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.proxy2.Coap2CoapTranslator;
import org.eclipse.californium.proxy2.CoapUriTranslator;
import org.eclipse.californium.proxy2.TranslationException;
import org.eclipse.californium.proxy2.http.Coap2HttpProxy;
import org.eclipse.californium.proxy2.http.Coap2HttpTranslator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resource that forwards a coap request with the proxy-uri, proxy-scheme,
 * URI-host, or URI-port option set to the desired http server.
 */
public class ProxyHttpClientResource extends ProxyCoapResource {

	private static final Logger LOGGER = LoggerFactory.getLogger(ProxyHttpClientResource.class);

	private final Coap2HttpTranslator translator;
	private final Coap2HttpProxy proxy;

	private final Set<String> schemes = new HashSet<String>();

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
		this.proxy = new Coap2HttpProxy(translator);
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

		if (accept) {
			exchange.sendAccept();
		}

		proxy.handleForward(destination, null, incomingCoapRequest, (response) -> exchange.sendResponse(response));

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
