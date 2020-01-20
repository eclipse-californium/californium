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

import org.apache.http.HttpEntity;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.StatusLine;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.EnglishReasonPhraseCatalog;
import org.apache.http.message.BasicStatusLine;
import org.apache.http.nio.protocol.HttpAsyncExchange;
import org.eclipse.californium.core.coap.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
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
	 * @deprecated use {@link HttpRequestContext#HttpRequestContext(HttpAsyncExchange) instead
	 */
	@Deprecated
	public HttpRequestContext(HttpAsyncExchange httpExchange, HttpRequest httpRequest) {
		// super(name);
		this.httpExchange = httpExchange;
		this.httpRequest = httpRequest;
	}

	/**
	 * Instantiates a new coap response worker.
	 *
	 * @param httpExchange   the http exchange
	 */
	public HttpRequestContext(HttpAsyncExchange httpExchange) {
		// super(name);
		this.httpExchange = httpExchange;
		this.httpRequest = httpExchange.getRequest();
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
			// send the response
			httpExchange.submitResponse();
		} catch (TranslationException e) {
			LOGGER.warn("Failed to translate coap response to http response: {}", e.getMessage());
			sendSimpleHttpResponse(HttpTranslator.STATUS_TRANSLATION_ERROR);
		}

	}

	/**
	 * Send simple http response.
	 *
	 * @param httpCode     the http code
	 */
	public void sendSimpleHttpResponse(int httpCode) {
		sendSimpleHttpResponse(httpCode, null);
	}

	/**
	 * Send simple http response.
	 *
	 * @param httpCode     the http code
	 * @param message      additional message, may be {@code null}
	 */
	public void sendSimpleHttpResponse(int httpCode, String message) {
		// get the empty response from the exchange
		HttpResponse httpResponse = httpExchange.getResponse();

		// create and set the status line
		String reason = EnglishReasonPhraseCatalog.INSTANCE.getReason(httpCode, Locale.ENGLISH);
		StatusLine statusLine = new BasicStatusLine(HttpVersion.HTTP_1_1, httpCode, reason);
		httpResponse.setStatusLine(statusLine);

		try {
			StringBuilder payload = new StringBuilder();
			payload.append(httpCode).append(": ").append(reason);
			if (message != null) {
				payload.append("\r\n\r\n").append(message);
			}
			HttpEntity entity = new StringEntity(payload.toString());
			httpResponse.setEntity(entity);
		} catch (UnsupportedEncodingException e) {
		}

		// send the error response
		httpExchange.submitResponse();
	}
}
