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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;

import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.protocol.RequestAcceptEncoding;
import org.apache.http.client.protocol.ResponseContentEncoding;
import org.apache.http.impl.client.AbstractHttpClient;
import org.apache.http.impl.client.DefaultConnectionKeepAliveStrategy;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.RequestConnControl;
import org.apache.http.protocol.RequestDate;
import org.apache.http.protocol.RequestExpectContinue;
import org.apache.http.protocol.RequestTargetHost;
import org.apache.http.protocol.RequestUserAgent;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.proxy.CoapTranslator;
import org.eclipse.californium.proxy.HttpTranslator;
import org.eclipse.californium.proxy.InvalidFieldException;
import org.eclipse.californium.proxy.TranslationException;


public class ProxyHttpClientResource extends ForwardingResource {
	
	private static final int KEEP_ALIVE = 5000;
	
	/**
	 * DefaultHttpClient is thread safe. It is recommended that the same
	 * instance of this class is reused for multiple request executions.
	 */
	private static final AbstractHttpClient HTTP_CLIENT = new DefaultHttpClient();

	// http client static configuration
	static {
		// request interceptors
		HTTP_CLIENT.addRequestInterceptor(new RequestAcceptEncoding());
		HTTP_CLIENT.addRequestInterceptor(new RequestConnControl());
		// HTTP_CLIENT.addRequestInterceptor(new RequestContent());
		HTTP_CLIENT.addRequestInterceptor(new RequestDate());
		HTTP_CLIENT.addRequestInterceptor(new RequestExpectContinue());
		HTTP_CLIENT.addRequestInterceptor(new RequestTargetHost());
		HTTP_CLIENT.addRequestInterceptor(new RequestUserAgent());

		// response intercptors
		HTTP_CLIENT.addResponseInterceptor(new ResponseContentEncoding());

		HTTP_CLIENT.setKeepAliveStrategy(new DefaultConnectionKeepAliveStrategy() {
			@Override
			public long getKeepAliveDuration(HttpResponse response, HttpContext context) {
				long keepAlive = super.getKeepAliveDuration(response, context);
				if (keepAlive == -1) {
					// Keep connections alive if a keep-alive value
					// has not be explicitly set by the server
					keepAlive = KEEP_ALIVE;
				}
				return keepAlive;
			}

		});
	}

	public ProxyHttpClientResource() {
		this(100000);
	}

	public ProxyHttpClientResource(long timeout) {
		super("httpClient");
	}

	@Override
	public Response forwardRequest(Request request) {
		final Request incomingCoapRequest = request;
		
		// check the invariant: the request must have the proxy-uri set
		if (!incomingCoapRequest.getOptions().hasProxyUri()) {
			LOGGER.warning("Proxy-uri option not set.");
			return new Response(ResponseCode.BAD_OPTION);
		}

		// get the proxy-uri set in the incoming coap request
		URI proxyUri;
		try {
			String proxyUriString = URLDecoder.decode(incomingCoapRequest.getOptions().getProxyUri(), "UTF-8");
			proxyUri = new URI(proxyUriString);
		} catch (UnsupportedEncodingException e) {
			LOGGER.warning("Proxy-uri option malformed: " + e.getMessage());
			return new Response(CoapTranslator.STATUS_FIELD_MALFORMED);
		} catch (URISyntaxException e) {
			LOGGER.warning("Proxy-uri option malformed: " + e.getMessage());
			return new Response(CoapTranslator.STATUS_FIELD_MALFORMED);
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
			return new Response(CoapTranslator.STATUS_FIELD_MALFORMED);
		} catch (TranslationException e) {
			LOGGER.warning("Problems during the http/coap translation: " + e.getMessage());
			return new Response(CoapTranslator.STATUS_TRANSLATION_ERROR);
		}

		ResponseHandler<Response> httpResponseHandler = new ResponseHandler<Response>() {
			@Override
			public Response handleResponse(HttpResponse httpResponse) throws ClientProtocolException, IOException {
				long timestamp = System.nanoTime();
				LOGGER.finer("Incoming http response: " + httpResponse.getStatusLine());
				// the entity of the response, if non repeatable, could be
				// consumed only one time, so do not debug it!
				// System.out.println(EntityUtils.toString(httpResponse.getEntity()));

				// translate the received http response in a coap response
				try {
					Response coapResponse = HttpTranslator.getCoapResponse(httpResponse, incomingCoapRequest);
					coapResponse.setTimestamp(timestamp);
					return coapResponse;
				} catch (InvalidFieldException e) {
					LOGGER.warning("Problems during the http/coap translation: " + e.getMessage());
					return new Response(CoapTranslator.STATUS_FIELD_MALFORMED);
				} catch (TranslationException e) {
					LOGGER.warning("Problems during the http/coap translation: " + e.getMessage());
					return new Response(CoapTranslator.STATUS_TRANSLATION_ERROR);
				}
			}
		};

		// accept the request sending a separate response to avoid the timeout
		// in the requesting client
		LOGGER.finer("Acknowledge message sent");

		Response coapResponse = null;
		try {
			// execute the request
			coapResponse = HTTP_CLIENT.execute(httpHost, httpRequest, httpResponseHandler, null);
		} catch (IOException e) {
			LOGGER.warning("Failed to get the http response: " + e.getMessage());
			return new Response(ResponseCode.INTERNAL_SERVER_ERROR);
		}

		return coapResponse;
	}
}
