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
import java.net.URISyntaxException;
import java.util.List;
import java.util.Locale;

import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpVersion;
import org.apache.hc.core5.http.Message;
import org.apache.hc.core5.http.Method;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.http.impl.EnglishReasonPhraseCatalog;
import org.apache.hc.core5.http.message.BasicHttpResponse;
import org.apache.hc.core5.net.WWWFormCodec;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.util.StandardCharsets;
import org.eclipse.californium.proxy2.InvalidFieldException;
import org.eclipse.californium.proxy2.TranslationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Class providing the translations (mappings) from the HTTP request
 * representations to the CoAP request representations and back from CoAP
 * response representations to HTTP response representations.
 */
public class Http2CoapTranslator {

	private static final Logger LOGGER = LoggerFactory.getLogger(Http2CoapTranslator.class);

	protected final CrossProtocolTranslator httpTranslator;
	protected final CrossProtocolTranslator.EtagTranslator etagTranslator;

	/**
	 * Creates http2coap translator from properties file.
	 * 
	 * @param mappingPropertiesFileName properties file name
	 * @see CrossProtocolTranslator#CrossProtocolTranslator(String)
	 */
	public Http2CoapTranslator(String mappingPropertiesFileName) {
		this(new CrossProtocolTranslator(mappingPropertiesFileName),
				new CrossProtocolTranslator.CoapServerEtagTranslator());
	}

	/**
	 * Creates http2coap translator with default translator.
	 * 
	 * @see CrossProtocolTranslator#CrossProtocolTranslator()
	 */
	public Http2CoapTranslator() {
		this(new CrossProtocolTranslator(), new CrossProtocolTranslator.CoapServerEtagTranslator());
	}

	/**
	 * Creates http2coap translator with provided translator.
	 * 
	 * @param httpTranslator translator
	 * @param etagTranslator translator for etag
	 * @throws NullPointerException if any translator is {@code null}.
	 */
	public Http2CoapTranslator(CrossProtocolTranslator httpTranslator,
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
	 * Gets the coap request.
	 * 
	 * Creates the CoAP request from the HTTP method and mapping it through the
	 * properties file. The URI is translated by extracting the part after the
	 * provided httpResource.
	 * (http://proxyname.domain:80/proxy/coap://coapserver:5683/resource
	 * converted in coap://coapserver:5683/resource.) It support proxy requests
	 * or request mapped to a local coap-server. It also support http-request
	 * send to this proxy using the http-proxy function itself. Though the
	 * primary scheme maybe tested to be http/https, the destination scheme must
	 * The method uses a decoder to translate the
	 * application/x-www-form-urlencoded format of the uri. The CoAP options are
	 * set translating the headers. If the HTTP message has an enclosing entity,
	 * it is converted to create the payload of the CoAP message; finally the
	 * content-type is set accordingly to the header and to the entity type.
	 * 
	 * @param httpRequest the http request
	 * @param httpResource the http resource, if present in the uri, indicates
	 *            the need of forwarding for the current request
	 * @param proxyingEnabled {@code true} to forward the request using the
	 *            sub-path as URI, {@code false} to access a local coap
	 *            resource.
	 * @return the coap request
	 * @throws TranslationException the translation exception
	 * @throws NullPointerException if one of the provided arguments is
	 *             {@code null}.
	 */
	public Request getCoapRequest(Message<HttpRequest, ContentTypedEntity> httpRequest, String httpResource,
			boolean proxyingEnabled) throws TranslationException {
		if (httpRequest == null) {
			throw new NullPointerException("httpRequest must not be null!");
		}
		if (httpResource == null) {
			throw new NullPointerException("httpResource must not be null!");
		}

		// get the http method
		String httpMethod = httpRequest.getHead().getMethod();

		// get the coap method
		Code code = httpTranslator.getCoapCode(httpMethod);

		// create the request -- since HTTP is reliable use CON
		Request coapRequest = new Request(code, Type.CON);

		// get the uri
		URI uri;
		try {
			uri = httpRequest.getHead().getUri();
			LOGGER.debug("URI <= '{}'", uri);
		} catch (URISyntaxException ex) {
			throw new TranslationException("Malformed uri: " + ex.getMessage());
		}

		if (!httpResource.startsWith("/")) {
			httpResource = "/" + httpResource;
		}
		// if the uri contains the proxy resource name, the request should be
		// forwarded and it is needed to get the real requested coap server's
		// uri e.g.:
		// /proxy/coap://vslab-dhcp-17.inf.ethz.ch:5684/helloWorld
		// proxy resource: /proxy
		// coap server: coap://vslab-dhcp-17.inf.ethz.ch:5684
		// coap resource: helloWorld
		String path = uri.getPath();
		LOGGER.debug("URI path => '{}'", path);
		if (path.startsWith(httpResource + "/")) {
			path = path.substring(httpResource.length() + 1);
			String target = path;
			if (uri.getQuery() != null) {
				target = path + "?" + uri.getQuery();
			}
			int index = target.indexOf(":/");
			if (index > 0) {
				// "coap://host" may have been normalized to "coap:/host"
				index += 2;
				if (target.charAt(index) != '/') {
					// add /
					target = target.substring(0, index) + "/" + target.substring(index);
				}
			}
			try {
				uri = new URI(target);
				if (proxyingEnabled) {
					// forwarding proxy
					// if the uri hasn't the indication of the scheme, add it
					if (uri.getScheme() == null) {
						throw new InvalidFieldException(
								"Malformed uri: destination scheme missing! Use http://<proxy-host>" + httpResource
										+ "/coap://<destination-host>/<path>");
					}
					// the uri will be set as a proxy-uri option
					LOGGER.debug("URI destination => '{}'", target);
					coapRequest.getOptions().setProxyUri(target);
				} else {
					if (uri.getScheme() != null) {
						throw new InvalidFieldException(
								"Malformed uri: local destination doesn't support scheme! Use http://<proxy-host>"
										+ httpResource + "/<path>");
					}
					// the uri will be set as a coap-uri
					target = "coap://localhost/" + target;
					LOGGER.debug("URI local => '{}'", target);
					coapRequest.setURI(target);
				}
			} catch (URISyntaxException e) {
				LOGGER.warn("Malformed destination uri", e);
				throw new InvalidFieldException("Malformed destination uri: " + target + "!");
			}
		} else if (proxyingEnabled && path.equals(httpResource)) {
			String target = null;
			if (uri.getQuery() != null) {
				List<NameValuePair> query = WWWFormCodec.parse(uri.getQuery(), StandardCharsets.UTF_8);
				for (NameValuePair arg : query) {
					if (arg.getName().equalsIgnoreCase("target_uri")) {
						target = arg.getValue();
						break;
					}
				}
			}
			if (target == null) {
				throw new InvalidFieldException("Malformed uri: target_uri is missing! Use http://<proxy-host>"
						+ httpResource + "?target_uri=coap://<destination-host>/<path>");
			}
			try {
				uri = new URI(target);
				// forwarding proxy
				// if the uri hasn't the indication of the scheme, add it
				if (uri.getScheme() == null) {
					throw new InvalidFieldException("Malformed uri: destination scheme missing! Use http://<proxy-host>"
							+ httpResource + "?target_uri=coap://<destination-host>/<path>");
				}
				// the uri will be set as a proxy-uri option
				LOGGER.debug("URI destination => '{}'", target);
				coapRequest.getOptions().setProxyUri(target);
			} catch (URISyntaxException e) {
				LOGGER.warn("Malformed destination uri", e);
				throw new InvalidFieldException("Malformed destination uri: " + target + "!");
			}
		} else if (proxyingEnabled && uri.getScheme() != null) {
			// http-server configured as http-proxy
			int index = path.lastIndexOf('/');
			if (0 < index) {
				String scheme = path.substring(index + 1);
				if (scheme.matches("\\w+:$")) {
					scheme = scheme.substring(0, scheme.length() - 1);
					path = path.substring(0, index);
					try {
						URI destination = new URI(scheme, null, uri.getHost(), uri.getPort(), path, uri.getQuery(),
								null);
						coapRequest.getOptions().setProxyUri(destination.toASCIIString());
					} catch (URISyntaxException e) {
						LOGGER.debug("Malformed proxy uri", e);
						throw new TranslationException("Malformed proxy uri: '" + uri + "' " + e.getMessage());
					}
				} else {
					throw new TranslationException(
							"Malformed proxy uri: target scheme missing! Use http://<destination-host>/<path>/<target-scheme>:");
				}
			} else {
				throw new TranslationException(
						"Malformed proxy uri: target scheme missing! Use http://<destination-host>/<path>/<target-scheme>:");
			}
		} else {
			throw new IllegalArgumentException("URI '" + uri + "' doesn't match handler '" + httpResource + "'!");
		}

		// translate the http headers in coap options
		List<Option> coapOptions = httpTranslator.getCoapOptions(httpRequest.getHead().getHeaders(), etagTranslator);
		coapRequest.getOptions().addOptions(coapOptions);

		// set the payload if the http entity is present
		ContentTypedEntity entity = httpRequest.getBody();
		httpTranslator.setCoapPayload(entity, coapRequest);

		return coapRequest;
	}

	/**
	 * Sets the parameters of the outgoing http response from a CoAP response.
	 * The status code is mapped through the properties file and is set through
	 * the StatusLine. The options are translated to the corresponding headers
	 * and the max-age (in the header cache-control) is set to the default value
	 * (60 seconds) if not already present. If the request method was not HEAD
	 * and the coap response has a payload, the entity and the content-type are
	 * set in the http response.
	 * 
	 * @param httpRequest http-request
	 * @param coapResponse the coap-response
	 * @return httpResponse producer
	 * @throws TranslationException the translation exception
	 * @throws NullPointerException if one of the provided arguments is
	 *             {@code null}.
	 */
	public ProxyResponseProducer getHttpResponse(HttpRequest httpRequest, Response coapResponse)
			throws TranslationException {
		if (httpRequest == null) {
			throw new NullPointerException("HTTP request must not be null!");
		}
		if (coapResponse == null) {
			throw new NullPointerException("CoAP response must not be null!");
		}

		// get/set the response code
		ResponseCode coapCode = coapResponse.getCode();
		int httpCode = httpTranslator.getHttpCode(coapResponse.getCode());

		BasicHttpResponse httpResponse = new BasicHttpResponse(httpCode);
		httpResponse.setVersion(HttpVersion.HTTP_1_1);
		String reason = EnglishReasonPhraseCatalog.INSTANCE.getReason(httpCode, Locale.ENGLISH);
		httpResponse.setReasonPhrase(reason);

		// set the headers
		Header[] headers = httpTranslator.getHttpHeaders(coapResponse.getOptions().asSortedList(), etagTranslator);
		httpResponse.setHeaders(headers);

		// set max-age if not already set
		if (!httpResponse.containsHeader("cache-control")) {
			httpResponse.setHeader("cache-control", "max-age=" + OptionNumberRegistry.Defaults.MAX_AGE);
		}

		ContentTypedEntity httpEntity = null;

		if (!Method.HEAD.name().equalsIgnoreCase(httpRequest.getMethod())) {
			// get the http entity if the request was not HEAD

			// if the content-type is not set in the coap response and if the
			// response contains an error, then the content-type should set to
			// text-plain
			if (coapResponse.getOptions().getContentFormat() == MediaTypeRegistry.UNDEFINED
					&& (coapCode.isClientError() || coapCode.isServerError())) {
				LOGGER.info("Set content-type to TEXT_PLAIN");
				coapResponse.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
				if (coapResponse.getPayloadSize() == 0) {
					coapResponse.setPayload(httpCode + ": " + reason);
				}
			}
			httpEntity = httpTranslator.getHttpEntity(coapResponse);
			if (httpEntity != null) {
				// get the content-type from the entity and set the header
				ContentType contentType = httpEntity.getContentType();
				httpResponse.setHeader("content-type", contentType.toString());
			}
		}
		return new ProxyResponseProducer(httpResponse, ContentTypedEntity.createProducer(httpEntity));
	}
}
