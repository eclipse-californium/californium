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
package org.eclipse.californium.proxy2;

import java.net.URI;
import java.util.List;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.HttpVersion;
import org.apache.http.RequestLine;
import org.apache.http.entity.ContentType;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.message.BasicHttpRequest;
import org.apache.http.message.BasicRequestLine;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class providing the translations (mappings) from the CoAP request
 * representations to the HTTP request representations and back from HTTP
 * response representations to CoAP response representations.
 */
public class Coap2HttpTranslator extends CoapUriTranslator {

	private static final Logger LOGGER = LoggerFactory.getLogger(Coap2HttpTranslator.class);

	protected final HttpTranslator httpTranslator;

	public Coap2HttpTranslator(String mappingPropertiesFileName) {
		httpTranslator = new HttpTranslator(mappingPropertiesFileName);
	}

	public Coap2HttpTranslator() {
		httpTranslator = new HttpTranslator();
	}

	public HttpRequest getHttpRequest(URI uri, Request coapRequest) throws TranslationException {
		if (coapRequest == null) {
			throw new IllegalArgumentException("coapRequest == null");
		}

		String coapMethod = httpTranslator.getHttpMethod(coapRequest.getCode());

		// create the requestLine
		RequestLine requestLine = new BasicRequestLine(coapMethod, uri.toASCIIString(), HttpVersion.HTTP_1_1);

		// get the http entity
		HttpEntity httpEntity = httpTranslator.getHttpEntity(coapRequest);

		// create the http request
		HttpRequest httpRequest;
		if (httpEntity == null) {
			httpRequest = new BasicHttpRequest(requestLine);
		} else {
			httpRequest = new BasicHttpEntityEnclosingRequest(requestLine);
			((HttpEntityEnclosingRequest) httpRequest).setEntity(httpEntity);

			// get the content-type from the entity and set the header
			ContentType contentType = ContentType.get(httpEntity);
			httpRequest.setHeader("content-type", contentType.toString());
		}

		// set the headers
		Header[] headers = httpTranslator.getHttpHeaders(coapRequest.getOptions().asSortedList());
		for (Header header : headers) {
			httpRequest.addHeader(header);
		}

		LOGGER.debug("Incoming request translated correctly");

		return httpRequest;
	}

	/**
	 * Gets the CoAP response from an incoming HTTP response. No null value is
	 * returned. The response is created from a the mapping of the HTTP response
	 * code retrieved from the properties file. If the code is 204, which has
	 * multiple meaning, the mapping is handled looking on the request method
	 * that has originated the response. The options are set thorugh the HTTP
	 * headers and the option max-age, if not indicated, is set to the default
	 * value (60 seconds). if the response has an enclosing entity, it is mapped
	 * to a CoAP payload and the content-type of the CoAP message is set
	 * properly.
	 * 
	 * @param httpResponse the http response
	 * @param coapRequest
	 * @return the coap response
	 * @throws TranslationException the translation exception
	 */
	public Response getCoapResponse(HttpResponse httpResponse, Request coapRequest) throws TranslationException {
		if (httpResponse == null) {
			throw new IllegalArgumentException("httpResponse == null");
		}
		if (coapRequest == null) {
			throw new IllegalArgumentException("coapRequest == null");
		}

		// get/set the response code
		int httpCode = httpResponse.getStatusLine().getStatusCode();
		Code coapMethod = coapRequest.getCode();

		if (httpCode == HttpStatus.SC_NO_CONTENT) {
			// special mapping for http 2.04 using the coap request code
			// RFC 7252 5.9.1.2 and 5.9.1.4
			httpCode += 10000 * coapMethod.value;
		}
		// get the translation from the property file
		ResponseCode coapCode = httpTranslator.getCoapResponseCode(httpCode);

		// create the coap reaponse
		Response coapResponse = new Response(coapCode);

		// translate the http headers in coap options
		List<Option> coapOptions = httpTranslator.getCoapOptions(httpResponse.getAllHeaders());

		for (Option option : coapOptions) {
			coapResponse.getOptions().addOption(option);
		}

		// the response should indicate a max-age value (RFC 7252, Section
		// 10.1.1)
		if (!coapResponse.getOptions().hasMaxAge()) {
			// The Max-Age Option for responses to POST, PUT or DELETE requests
			// should always be set to 0 (draft-castellani-core-http-mapping).
			if (coapMethod == Code.GET) {
				coapResponse.getOptions().setMaxAge(OptionNumberRegistry.Defaults.MAX_AGE);
			} else {
				coapResponse.getOptions().setMaxAge(0);
			}
		}

		// get the entity
		HttpEntity httpEntity = httpResponse.getEntity();
		if (httpEntity != null) {
			// translate the http entity in coap payload
			byte[] payload = httpTranslator.getCoapPayload(httpEntity);
			if (payload != null && payload.length > 0) {
				coapResponse.setPayload(payload);

				// set the content-type
				int coapContentType = httpTranslator.getCoapMediaType(httpResponse);
				coapResponse.getOptions().setContentFormat(coapContentType);
			}
		}

		LOGGER.debug("Incoming response translated correctly");

		return coapResponse;
	}

}
