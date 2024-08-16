/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.proxy2.http;

import java.net.SocketTimeoutException;
import java.net.URI;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.concurrent.FutureCallback;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.Message;
import org.apache.hc.core5.http.message.StatusLine;
import org.apache.hc.core5.http.nio.support.BasicResponseConsumer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.ResponseConsumer;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.proxy2.Coap2CoapTranslator;
import org.eclipse.californium.proxy2.InvalidFieldException;
import org.eclipse.californium.proxy2.TranslationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.net.HttpHeaders;

/**
 * CoAP to Http proxy.
 * 
 * @since 3.13
 */
public class Coap2HttpProxy {

	private static final Logger LOGGER = LoggerFactory.getLogger(Coap2HttpProxy.class);

	/**
	 * DefaultHttpClient is thread safe. It is recommended that the same
	 * instance of this class is reused for multiple request executions.
	 */
	private final CloseableHttpAsyncClient asyncClient = HttpClientFactory.createClient();
	/**
	 * Coap2Http translator.
	 */
	private final Coap2HttpTranslator translator;

	/**
	 * Create http proxy.
	 * 
	 * @param translator translator. May be {@code null}, when default
	 *            translator should be used.
	 */
	public Coap2HttpProxy(Coap2HttpTranslator translator) {
		if (translator == null) {
			translator = new Coap2HttpTranslator();
		}
		this.translator = translator;
	}

	/**
	 * Handle http-forward request.
	 * 
	 * @param destination http destination
	 * @param authentication http authentication. Maybe {@code null}.
	 * @param incomingCoapRequest incoming coap request
	 * @param onResponse callback for coap-response
	 */
	public void handleForward(URI destination, String authentication, final Request incomingCoapRequest,
			final ResponseConsumer onResponse) {

		HttpClientContext context = null;

		if (authentication != null) {
			if (authentication.startsWith("Bearer ")) {
				// pass to translator
			} else {
				int index = authentication.indexOf(':');
				if (index > 0) {
					BasicCredentialsProvider provider = new BasicCredentialsProvider();
					char[] pw = authentication.toCharArray();
					pw = Arrays.copyOfRange(pw, index + 1, pw.length);
					provider.setCredentials(new AuthScope(null, -1),
							new UsernamePasswordCredentials(authentication.substring(0, index), pw));
					context = HttpClientContext.create();
					context.setCredentialsProvider(provider);
				}
				authentication = null;
			}
		}

		ProxyRequestProducer httpRequest = null;
		try {
			// get the mapping to http for the outgoing coap request
			httpRequest = translator.getHttpRequest(destination, authentication, incomingCoapRequest);
			LOGGER.debug("Outgoing http request: {}", httpRequest.getRequestLine());
			if (LOGGER.isDebugEnabled()) {
				String ct = httpRequest.getContentType();
				if (ct != null) {
					LOGGER.debug("   content-type: {}", ct);
				}
				for (Header header : httpRequest.getHttpRequest().getHeaders()) {
					if (header.getName().equals(HttpHeaders.AUTHORIZATION)) {
						if (header.getValue().startsWith("Bearer ")) {
							LOGGER.debug("   {}: Bearer ...", header.getName());
						} else {
							LOGGER.debug("   {}: ...", header.getName());
						}
					} else {
						LOGGER.debug("   {}", header);
					}
				}
			}
		} catch (InvalidFieldException e) {
			LOGGER.debug("Problems during the http/coap translation: {}", e.getMessage());
			onResponse.respond(new Response(Coap2CoapTranslator.STATUS_FIELD_MALFORMED));
			return;
		} catch (TranslationException e) {
			LOGGER.debug("Problems during the http/coap translation: {}", e.getMessage());
			onResponse.respond(new Response(Coap2CoapTranslator.STATUS_TRANSLATION_ERROR));
			return;
		}

		final long now = ClockUtil.nanoRealtime();

		asyncClient.execute(httpRequest,
				new BasicResponseConsumer<ContentTypedEntity>(new ContentTypedEntityConsumer()), context,
				new FutureCallback<Message<HttpResponse, ContentTypedEntity>>() {

					@Override
					public void completed(Message<HttpResponse, ContentTypedEntity> result) {
						long timestamp = ClockUtil.nanoRealtime();
						StatusLine status = new StatusLine(result.getHead());
						try {
							LOGGER.debug("Incoming http response: {}", status);
							if (LOGGER.isDebugEnabled()) {
								for (Header header : result.getHead().getHeaders()) {
									LOGGER.debug("   {}", header);
								}
							}
							// translate the received http response
							// in a coap response
							Response coapResponse = translator.getCoapResponse(result, incomingCoapRequest);
							coapResponse.setNanoTimestamp(timestamp);
							onResponse.respond(coapResponse);
						} catch (InvalidFieldException e) {
							LOGGER.debug("Problems during the http/coap translation: {}", e.getMessage());
							Response response = new Response(Coap2CoapTranslator.STATUS_FIELD_MALFORMED);
							response.setPayload(e.getMessage());
							response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
							onResponse.respond(response);
						} catch (TranslationException e) {
							LOGGER.debug("Problems during the http/coap translation: {}", e.getMessage());
							Response response = new Response(Coap2CoapTranslator.STATUS_TRANSLATION_ERROR);
							response.setPayload(e.getMessage());
							response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
							onResponse.respond(response);
						} catch (Throwable e) {
							LOGGER.debug("Error during the http/coap translation: {}", e.getMessage(), e);
							Response response = new Response(Coap2CoapTranslator.STATUS_FIELD_MALFORMED);
							response.setPayload(e.getMessage());
							response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
							onResponse.respond(response);
						}
						LOGGER.debug("Incoming http response: {} processed ({}ms)!", status,
								TimeUnit.NANOSECONDS.toMillis(timestamp - now));
					}

					@Override
					public void failed(Exception ex) {
						LOGGER.debug("Failed to get the http response: {}", ex.getMessage(), ex);
						if (ex instanceof SocketTimeoutException) {
							onResponse.respond(new Response(ResponseCode.GATEWAY_TIMEOUT));
						} else {
							Response response = new Response(ResponseCode.BAD_GATEWAY);
							response.setPayload(ex.getMessage());
							response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
							onResponse.respond(response);
						}
					}

					@Override
					public void cancelled() {
						LOGGER.debug("Request canceled");
						onResponse.respond(new Response(ResponseCode.SERVICE_UNAVAILABLE));
					}
				});

	}

}
