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

package org.eclipse.californium.proxy2.resources;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.ServerMessageDeliverer;
import org.eclipse.californium.proxy2.ClientEndpoints;
import org.eclipse.californium.proxy2.Coap2CoapTranslator;
import org.eclipse.californium.proxy2.Coap2HttpTranslator;
import org.eclipse.californium.proxy2.CoapUriTranslator;
import org.eclipse.californium.proxy2.Http2CoapTranslator;
import org.eclipse.californium.proxy2.TranslationException;

/**
 * Resource that forwards a coap request.
 * 
 * According <a href="https://tools.ietf.org/html/rfc7252#section-5.7">RFC 7252,
 * 5.7 Proxying</a> proxies are classified into <a href=
 * "https://tools.ietf.org/html/rfc7252#section-5.7.2">Forward-Proxies</a> and
 * <a href=
 * "https://tools.ietf.org/html/rfc7252#section-5.7.3">Reverse-Proxies</a>.
 * 
 * The forward-proxies operates in a generic way. The destination to sent the
 * request by the proxy is contained in the request itself. It is provided in
 * the coap-options (Uri-Host, Uri-Port, Uri-Path, Uri-Query, and Proxy-Scheme,
 * or Proxy-Uri). This is very similar to a http proxy, where the http-request
 * including the destination host, is sent to the http-proxy.
 * 
 * The reverse-proxies instead are specific. They don't use the above options to
 * define the destination, instead this destination is defined by configuration
 * or/and information in the request.
 * 
 * Over the time, it seems, that these two variants got mixed. One reason for
 * that may be the fact, that the Proxy-URI is the only standard option, which
 * may contain more than 255 bytes. That mix makes it hard to implement a proxy
 * functionality, especially, if such none-compliant cases should be also
 * considered.
 * 
 * This {@link ProxyCoapResource} supports both variants adapting the conversion
 * using custom implementations of {@link Coap2CoapTranslator} or
 * {@link Http2CoapTranslator}.
 * 
 * Forward proxies are implemented replacing the default
 * {@link ServerMessageDeliverer} by {@link ForwardProxyMessageDeliverer} and
 * add {@link ProxyCoapClientResource} and/or {@link ProxyHttpClientResource} to
 * this message-forwarded.
 * 
 * Reverse proxies maybe implemented using
 * {@link #createReverseProxy(String, boolean, boolean, boolean, URI, ClientEndpoints...)}.
 * If a reverse proxy requires a customized conversion, add a customized
 * {@link ProxyCoapClientResource} and/or {@link ProxyHttpClientResource} to the
 * coap-server.
 * 
 * Mixed proxies maybe implemented using both approaches, the
 * {@link ForwardProxyMessageDeliverer} and
 * {@link #createReverseProxy(String, boolean, boolean, boolean, URI, ClientEndpoints...)}
 * or customized {@link ProxyCoapClientResource} and/or
 * {@link ProxyHttpClientResource}. In cases, where it is ambiguous, if the
 * request should be processed by the forwarding-proxy or by a reverse-proxy
 * resource, the {@link ForwardProxyMessageDeliverer} may use a customized
 * {@link CoapUriTranslator}, which returns {@code null} in
 * {@link CoapUriTranslator#getDestinationScheme(Request)} to bypass
 * forwarding-proxy.
 */
public abstract class ProxyCoapResource extends CoapResource {

	/**
	 * Accept CON request before forwarding it.
	 */
	protected final boolean accept;

	/**
	 * Cache resource.
	 * 
	 * @since 2.4
	 */
	private volatile CacheResource cache;

	/**
	 * Statistic resource.
	 * 
	 * @since 2.4
	 */
	private volatile StatsResource statsResource;

	/**
	 * Create proxy resource.
	 * 
	 * @param name name of the resource
	 * @param visible visibility of the resource
	 * @param accept accept CON request before forwarding the request
	 */
	public ProxyCoapResource(String name, boolean visible, boolean accept) {
		// set the resource hidden
		super(name, visible);
		this.accept = accept;
	}

	/**
	 * Get cache resource.
	 * 
	 * @return cache resource
	 * @since 2.4
	 */
	public CacheResource getCache() {
		return cache;
	}

	/**
	 * Set cache resource.
	 * 
	 * @param cache cache resource
	 * @since 2.4
	 */
	public void setCache(CacheResource cache) {
		this.cache = cache;
	}

	/**
	 * Get statistics resource.
	 * 
	 * @return statistic resource
	 * @since 2.4
	 */
	public StatsResource getStatsResource() {
		return statsResource;
	}

	/**
	 * Set statistic resource.
	 * 
	 * @param statsResource statistic resource
	 * @since 2.4
	 */
	public void setStatsResource(StatsResource statsResource) {
		this.statsResource = statsResource;
	}

	/**
	 * Get URI translator for forward-proxy.
	 * 
	 * @return URI translator. May be {@code null} for reverse-proxy.
	 * @see ForwardProxyMessageDeliverer
	 * @since 2.4
	 */
	public abstract CoapUriTranslator getUriTranslater();

	/**
	 * Set of supported destination schemes for forward-proxy.
	 * 
	 * @return set of supported destination schemes for forward-proxy. May be
	 *         {@code null} for reverse-proxy.
	 * @see ForwardProxyMessageDeliverer
	 */
	public abstract Set<String> getDestinationSchemes();

	@Override
	public abstract void handleRequest(final Exchange exchange);

	/**
	 * Create reverse-proxy for fixed destination.
	 * 
	 * @param name name of the resource
	 * @param visible visibility of the resource
	 * @param accept accept CON request befor forwarding the request
	 * @param copyQuery {@code true} copy query parameter to destination,
	 *            {@code false}, otherwise.
	 * @param destination fixed destination
	 * @param endpointsList list of client endpoints for coap2coap
	 * @return coap resource, or {@code null}, if destination scheme is not
	 *         supported.
	 */
	public static ProxyCoapResource createReverseProxy(String name, boolean visible, boolean accept, final boolean copyQuery,
			final URI destination, ClientEndpoints... endpointsList) {
		String scheme = destination.getScheme();
		for (ClientEndpoints endpoints : endpointsList) {
			if (endpoints.getScheme().equals(scheme)) {
				Coap2CoapTranslator translator = new Coap2CoapTranslator() {

					@Override
					public URI getDestinationURI(Request incomingRequest, InetSocketAddress exposed)
							throws TranslationException {
						if (copyQuery && incomingRequest.getOptions().getURIQueryCount() > 0) {
							String query = incomingRequest.getOptions().getUriQueryString();
							try {
								return new URI(destination.getScheme(), null, destination.getHost(),
										destination.getPort(), destination.getPath(), query, null);
							} catch (URISyntaxException e) {
							}
						}
						return destination;
					}
				};
				return new ProxyCoapClientResource(name, visible, accept, translator, endpoints);
			}
		}
		if (scheme.equals("http") || scheme.equals("https")) {
			Coap2HttpTranslator translator = new Coap2HttpTranslator() {

				@Override
				public URI getDestinationURI(Request incomingRequest, InetSocketAddress exposed)
						throws TranslationException {
					if (copyQuery && incomingRequest.getOptions().getURIQueryCount() > 0) {
						String query = incomingRequest.getOptions().getUriQueryString();
						try {
							return new URI(destination.getScheme(), null, destination.getHost(), destination.getPort(),
									destination.getPath(), query, null);
						} catch (URISyntaxException e) {
						}
					}
					return destination;
				}
			};
			return new ProxyHttpClientResource(name, visible, accept, translator, scheme);
		}
		return null;
	}
}
