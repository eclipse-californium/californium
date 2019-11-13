/*******************************************************************************
 * Copyright (c) 2017 NTNU Gjøvik and others.
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
 *    Martin Storø Nyfløtt (NTNU Gjøvik) - performance improvements to HTTP cross-proxy
 ******************************************************************************/
package org.eclipse.californium.proxy;

import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.StatusLine;
import org.apache.http.impl.EnglishReasonPhraseCatalog;
import org.apache.http.message.BasicStatusLine;
import org.apache.http.nio.protocol.HttpAsyncExchange;
import org.eclipse.californium.core.coap.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Locale;

/**
 * This class deals encapsulates members related to a HTTP request in order to
 * send a response to the original HTTP request.
 */
public final class HttpRequestContext {
	private final HttpAsyncExchange httpExchange;
	private final HttpRequest httpRequest;

	private static final Logger LOGGER = LoggerFactory.getLogger(HttpRequestContext.class);

	/**
	 * Instantiates a new coap response worker.
	 *
	 * @param httpExchange   the http exchange
	 * @param httpRequest    the http request
	 */
	public HttpRequestContext(HttpAsyncExchange httpExchange, HttpRequest httpRequest) {
		// super(name);
		this.httpExchange = httpExchange;
		this.httpRequest = httpRequest;
	}

	public void handleRequestForwarding(final Response coapResponse) {
		if (coapResponse == null) {
			LOGGER.warn("No coap response");
			sendSimpleHttpResponse(HttpTranslator.STATUS_NOT_FOUND);
			return;
		}

		// get the sample http response
		HttpResponse httpResponse = httpExchange.getResponse();

		try {
			// translate the coap response in an http response
			new HttpTranslator().getHttpResponse(httpRequest, coapResponse, httpResponse);

			LOGGER.debug("Outgoing http response: {}", httpResponse.getStatusLine());
		} catch (TranslationException e) {
			LOGGER.warn("Failed to translate coap response to http response: {}", e.getMessage());
			sendSimpleHttpResponse(HttpTranslator.STATUS_TRANSLATION_ERROR);
			return;
		}

		// send the response
		httpExchange.submitResponse();
	}

	/**
	 * Send simple http response.
	 *
	 * @param httpCode     the http code
	 */
	public void sendSimpleHttpResponse(int httpCode) {
		// get the empty response from the exchange
		HttpResponse httpResponse = httpExchange.getResponse();

		// create and set the status line
		StatusLine statusLine = new BasicStatusLine(HttpVersion.HTTP_1_1, httpCode, EnglishReasonPhraseCatalog.INSTANCE.getReason(httpCode, Locale.ENGLISH));
		httpResponse.setStatusLine(statusLine);

		// send the error response
		httpExchange.submitResponse();
	}
}
