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
import org.eclipse.californium.proxy2.Coap2CoapTranslator;
import org.eclipse.californium.proxy2.Coap2HttpTranslator;
import org.eclipse.californium.proxy2.EndpointPool;
import org.eclipse.californium.proxy2.TranslationException;

/**
 * Resource that forwards a coap request.
 */
public abstract class ProxyCoapResource extends CoapResource {

	/**
	 * Accept CON request before forwarding it.
	 */
	protected final boolean accept;

	/**
	 * Create proxy resource.
	 * 
	 * @param name name of the resource
	 * @param visible visibility of the resource
	 * @param accept accept CON request befor forwarding the request
	 */
	public ProxyCoapResource(String name, boolean visible, boolean accept) {
		// set the resource hidden
		super(name, visible);
		this.accept = accept;
	}

	/**
	 * Set of supported destination schemes.
	 * 
	 * @return set of supported destination schemes.
	 */
	public abstract Set<String> getDestinationSchemes();

	@Override
	public abstract void handleRequest(final Exchange exchange);

	/**
	 * Create reverse proxy for fixed destination.
	 * 
	 * @param name name of the resource
	 * @param visible visibility of the resource
	 * @param accept accept CON request befor forwarding the request
	 * @param copyQuery {@code true} copy query parameter to destination,
	 *            {@code false}, otherwise.
	 * @param destination fixed destination
	 * @param pools endpoint pools for coap2coap
	 * @return coap resource, or {@code null}, if destination scheme is not
	 *         supported.
	 */
	public static CoapResource createReverseProxy(String name, boolean visible, boolean accept, final boolean copyQuery,
			final URI destination, EndpointPool... pools) {
		String scheme = destination.getScheme();
		for (EndpointPool pool : pools) {
			if (pool.getScheme().equals(scheme)) {
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
				return new ProxyCoapClientResource(name, visible, accept, translator, pool);
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
