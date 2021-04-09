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
package org.eclipse.californium.proxy2.http;

import java.net.URI;
import java.util.List;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.Message;
import org.apache.hc.core5.http.message.BasicHttpRequest;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.proxy2.CoapUriTranslator;
import org.eclipse.californium.proxy2.TranslationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class providing the translations (mappings) from the CoAP request
 * representations to the HTTP request representations and back from HTTP
 * response representations to CoAP response representations.
 */
public class Coap2HttpTranslator extends CoapUriTranslator {

	private static final Logger LOGGER = LoggerFactory.getLogger(Coap2HttpTranslator.class);

	protected final CrossProtocolTranslator httpTranslator;
	protected final CrossProtocolTranslator.EtagTranslator etagTranslator;

	/**
	 * Creates coap2http translator from properties file.
	 * 
	 * @param mappingPropertiesFileName properties file name
	 * @see CrossProtocolTranslator#CrossProtocolTranslator(String)
	 */
	public Coap2HttpTranslator(String mappingPropertiesFileName) {
		this(new CrossProtocolTranslator(mappingPropertiesFileName),
				new CrossProtocolTranslator.HttpServerEtagTranslator());
	}

	/**
	 * Creates coap2http translator with default translator.
	 * 
	 * @see CrossProtocolTranslator#CrossProtocolTranslator()
	 */
	public Coap2HttpTranslator() {
		this(new CrossProtocolTranslator(), new CrossProtocolTranslator.HttpServerEtagTranslator());
	}

	/**
	 * Create coap2http translator with provided translator.
	 * 
	 * @param httpTranslator translator
	 * @param etagTranslator translator for etag
	 * @throws NullPointerException if any translator is {@code null}.
	 */
	public Coap2HttpTranslator(CrossProtocolTranslator httpTranslator,
			CrossProtocolTranslator.EtagTranslator etagTranslator) {
		if (httpTranslator == null) {
			throw new NullPointerException("http-translator must not be null!");
		}
		if (etagTranslator == null) {
			throw new NullPointerException("etag-translator must not be null!");
		}
		this.httpTranslator = httpTranslator;
		this.etagTranslator = etagTranslator;
	}

	/**
	 * Maps a coap-request into a http-request.
	 * 
	 * @param uri destination to use
	 * @param coapRequest coap-request
	 * @return http-request
	 * @throws TranslationException if request could not be translated
	 * @throws NullPointerException if one of the provided arguments is
	 *             {@code null}.
	 */
	public ProxyRequestProducer getHttpRequest(URI uri, Request coapRequest) throws TranslationException {
		if (uri == null) {
			throw new NullPointerException("URI must not be null!");
		}
		if (coapRequest == null) {
			throw new NullPointerException("Coap-request must not be null!");
		}

		String coapMethod = httpTranslator.getHttpMethod(coapRequest.getCode());

		// create the http request
		BasicHttpRequest httpRequest = new BasicHttpRequest(coapMethod, uri);

		// get the http body
		ContentTypedEntity httpEntity = httpTranslator.getHttpEntity(coapRequest);

		// set the headers
		Header[] headers = httpTranslator.getHttpHeaders(coapRequest.getOptions().asSortedList(), etagTranslator);
		for (Header header : headers) {
			httpRequest.addHeader(header);
		}

		LOGGER.debug("Incoming request translated correctly");
		return new ProxyRequestProducer(httpRequest, ContentTypedEntity.createProducer(httpEntity));
	}

	/**
	 * Gets the CoAP response from an incoming HTTP response. No {@code null}
	 * value is returned. The response is created from a the mapping of the HTTP
	 * response code retrieved from the properties file. If the code is 204,
	 * which has multiple meaning, the mapping is handled looking on the request
	 * method that has originated the response. The options are set through the
	 * HTTP headers and the option max-age, if not indicated, is set to the
	 * default value (60 seconds). if the response has an enclosing entity, it
	 * is mapped to a CoAP payload and the content-type of the CoAP message is
	 * set properly.
	 * 
	 * @param httpResponse the http-response
	 * @param coapRequest related coap-request. Some response codes are
	 *            translated according the requested code.
	 * @return the coap response
	 * @throws TranslationException the translation exception
	 * @throws NullPointerException if one of the provided arguments is
	 *             {@code null}.
	 */
	public Response getCoapResponse(Message<HttpResponse, ContentTypedEntity> httpResponse, Request coapRequest)
			throws TranslationException {
		if (httpResponse == null) {
			throw new NullPointerException("Http-response must not be null!");
		}
		if (coapRequest == null) {
			throw new NullPointerException("Coap-request must not be null!");
		}

		// get/set the response code
		int httpCode = httpResponse.getHead().getCode();
		Code coapMethod = coapRequest.getCode();

		// get the translation from the property file
		ResponseCode coapCode = httpTranslator.getCoapResponseCode(coapMethod, httpCode);

		// create the coap response
		Response coapResponse = new Response(coapCode);

		// translate the http headers in coap options
		List<Option> coapOptions = httpTranslator.getCoapOptions(httpResponse.getHead().getHeaders(), etagTranslator);
		coapResponse.getOptions().addOptions(coapOptions);

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

		// translate the http body in coap payload
		ContentTypedEntity entity = httpResponse.getBody();
		httpTranslator.setCoapPayload(entity, coapResponse);

		LOGGER.debug("Incoming response translated correctly");

		return coapResponse;
	}

}
