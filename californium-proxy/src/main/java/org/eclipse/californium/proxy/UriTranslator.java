/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.proxy;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;

import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Static class that provides the translations between the messages from the
 * internal CoAP nodes and external ones.
 */
public final class UriTranslator {

	/** The Constant LOG. */
	private static final Logger LOGGER = LoggerFactory.getLogger(UriTranslator.class);

	/**
	 * Get "final" destination URI from request.
	 * 
	 * If a Proxy-URI is provided, that is used. Otherwise the "final destination"
	 * is constructed using the options {@link OptionSet#getProxyScheme()},
	 * {@link OptionSet#getUriHost()}, {@link OptionSet#getUriPort()},
	 * {@link OptionSet#getUriPath()}, and {@link OptionSet#getUriQuery()}.
	 * 
	 * @param incomingRequest the original request
	 * @return "final destination" URI
	 * @throws TranslationException the translation exception
	 */
	public static URI getDestinationURI(final Request incomingRequest) throws TranslationException {
		// check parameters
		if (incomingRequest == null) {
			throw new NullPointerException("incomingRequest == null");
		}
		try {
			OptionSet options = incomingRequest.getOptions();
			if (options.hasProxyUri()) {
				String proxyUriString = URLDecoder.decode(options.getProxyUri(), "UTF-8");
				return new URI(proxyUriString);
			} else {
				String scheme = options.hasProxyScheme() ? options.getProxyScheme() : incomingRequest.getScheme();
				String host = options.getUriHost();
				int port = options.getUriPort();
				String path = "/" + options.getUriPathString();
				String query = options.getURIQueryCount() > 0 ? options.getUriQueryString() : null;
				return new URI(scheme, null, host, port, path, query, null);
			}
		} catch (UnsupportedEncodingException e) {
			LOGGER.warn("UTF-8 do not support this encoding", e);
			throw new TranslationException("UTF-8 do not support this encoding", e);
		} catch (URISyntaxException e) {
			LOGGER.warn("Cannot translate the server uri", e);
			throw new TranslationException("Cannot translate the server uri", e);
		}
	}

	/**
	 * The Constructor is private because the class is an helper class and cannot be
	 * instantiated.
	 */
	private UriTranslator() {
	}
}
