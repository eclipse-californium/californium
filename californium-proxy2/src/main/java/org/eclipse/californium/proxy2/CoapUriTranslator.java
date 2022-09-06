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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/

package org.eclipse.californium.proxy2;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.proxy2.resources.ForwardProxyMessageDeliverer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Basic destination translations for CoAP requests.
 */
public class CoapUriTranslator {

	/** The Constant LOG. */
	private static final Logger LOGGER = LoggerFactory.getLogger(CoapUriTranslator.class);

	// Error constants
	public static final ResponseCode STATUS_FIELD_MALFORMED = ResponseCode.BAD_OPTION;
	public static final ResponseCode STATUS_TIMEOUT = ResponseCode.GATEWAY_TIMEOUT;
	public static final ResponseCode STATUS_TRANSLATION_ERROR = ResponseCode.BAD_GATEWAY;

	/**
	 * Get destination scheme of request for forward-proxy processing.
	 * 
	 * If a Proxy-URI is provided, that is used to determine the scheme.
	 * Otherwise the {@link OptionSet#getProxyScheme()} is, if available, or the
	 * scheme of the request in absence of the other schemes.
	 * 
	 * @param incomingRequest the original request
	 * @return destination scheme, or {@code null}, to bypass the forward-proxy
	 *         processing.
	 * @throws TranslationException the translation exception
	 * @see ForwardProxyMessageDeliverer
	 */
	public String getDestinationScheme(Request incomingRequest) throws TranslationException {
		if (incomingRequest == null) {
			throw new NullPointerException("incomingRequest == null");
		}
		OptionSet options = incomingRequest.getOptions();
		if (options.hasProxyUri()) {
			try {
				return new URI(options.getProxyUri()).getScheme();
			} catch (URISyntaxException e) {
				LOGGER.warn("Cannot translate the server uri", e);
				throw new TranslationException("Cannot translate the server uri", e);
			}
		} else if (options.hasProxyScheme()) {
			return options.getProxyScheme();
		} else {
			return incomingRequest.getScheme();
		}
	}

	/**
	 * Return the exposed interface the request is received with.
	 * 
	 * In container deployments the receiving local interface may differ from
	 * the exposed one. That interface may be required, if the request doesn't
	 * contain a uri-host or uri-port option. In that case, the interface is
	 * used to fill in the missing information. This default implementation
	 * returns {@link Message#getLocalAddress()}, if this is not an any address.
	 * Otherwise, {@code null} is returned and requires, that the requests
	 * contains the uri-host and uri-port option.
	 * 
	 * @param incomingRequest the received request. The request's local address
	 *            contains the address of the local receiving interface.
	 * @return exposed interface. {@code null}, if not available.
	 * @since 3.0 use local address instead of destination context
	 */
	public InetSocketAddress getExposedInterface(Request incomingRequest) {
		InetSocketAddress incoming = incomingRequest.getLocalAddress();
		if (incoming != null) {
			if (incoming.getAddress().isAnyLocalAddress()) {
				return null;
			}
		}
		return incoming;
	}

	/**
	 * Get "final" destination URI from request.
	 * 
	 * If a Proxy-URI is provided, that is used. Otherwise the "final
	 * destination" is constructed using the options
	 * {@link OptionSet#getProxyScheme()}, {@link OptionSet#getUriHost()},
	 * {@link OptionSet#getUriPort()}, {@link OptionSet#getUriPath()}, and
	 * {@link OptionSet#getUriQuery()}.
	 * 
	 * @param incomingRequest the original request
	 * @param exposed the exposed interface of this request. {@code null}, if
	 *            unknown.
	 * @return "final destination" URI
	 * @throws TranslationException the translation exception
	 */
	public URI getDestinationURI(Request incomingRequest, InetSocketAddress exposed) throws TranslationException {
		// check parameters
		if (incomingRequest == null) {
			throw new NullPointerException("incomingRequest == null");
		}
		try {
			OptionSet options = incomingRequest.getOptions();
			if (options.hasProxyUri()) {
				return new URI(options.getProxyUri());
			} else {
				String scheme = options.hasProxyScheme() ? options.getProxyScheme() : incomingRequest.getScheme();
				String host = options.getUriHost();
				if (host == null) {
					if (exposed == null) {
						throw new TranslationException("Destination host missing! Neither the Uri-Host nor the exposed interface is available!");
					}
					host = StringUtil.getUriHostname(exposed.getAddress());
				}
				Integer port = options.getUriPort();
				if (port == null) {
					port = -1;
				}
				String path = "/" + options.getUriPathString();
				String query = options.getURIQueryCount() > 0 ? options.getUriQueryString() : null;
				return new URI(scheme, null, host, port, path, query, null);
			}
		} catch (URISyntaxException e) {
			LOGGER.warn("Cannot translate the server uri", e);
			throw new TranslationException("Cannot translate the server uri", e);
		}
	}
}
