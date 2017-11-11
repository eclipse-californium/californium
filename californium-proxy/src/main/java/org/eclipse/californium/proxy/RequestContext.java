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
package org.eclipse.californium.proxy;

import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.StatusLine;
import org.apache.http.impl.EnglishReasonPhraseCatalog;
import org.apache.http.message.BasicStatusLine;
import org.apache.http.nio.protocol.HttpAsyncExchange;
import org.eclipse.californium.core.coap.Response;

import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The Class RequestContext. This thread waits a response from the lower
 * layers. It is the consumer of the producer/consumer pattern.
 */
public final class RequestContext {
	private final HttpAsyncExchange httpExchange;
	private final HttpRequest httpRequest;

	private static final Logger LOGGER = Logger.getLogger(RequestContext.class.getName());

	/**
	 * Instantiates a new coap response worker.
	 *
	 * @param httpExchange   the http exchange
	 * @param httpRequest    the http request
	 */
	public RequestContext(HttpAsyncExchange httpExchange, HttpRequest httpRequest) {
		// super(name);
		this.httpExchange = httpExchange;
		this.httpRequest = httpRequest;
	}

	public void handleRequestForwarding(final Response coapResponse) {
		if (coapResponse == null) {
			LOGGER.warning("No coap response");
			sendSimpleHttpResponse(HttpTranslator.STATUS_NOT_FOUND);
			return;
		}

		// get the sample http response
		HttpResponse httpResponse = httpExchange.getResponse();

		try {
			// translate the coap response in an http response
			HttpTranslator.getHttpResponse(httpRequest, coapResponse, httpResponse);

			LOGGER.log(Level.FINER, "Outgoing http response: {0}", httpResponse.getStatusLine());
		} catch (TranslationException e) {
			LOGGER.log(Level.WARNING, "Failed to translate coap response to http response: {0}", e.getMessage());
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
