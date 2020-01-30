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

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.ServerMessageDeliverer;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.proxy2.CoapUriTranslator;
import org.eclipse.californium.proxy2.TranslationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Proxy message deliverer
 * 
 * Delivers message either to proxy resources registered for the destination
 * scheme, or, to local resources using the requests path.
 */
public class ProxyMessageDeliverer extends ServerMessageDeliverer {

	private static final Logger LOGGER = LoggerFactory.getLogger(ProxyMessageDeliverer.class);

	/**
	 * Translator to determine destination scheme.
	 * 
	 * @see CoapUriTranslator#getDestinationScheme(Request)
	 */
	private final CoapUriTranslator translater;
	/**
	 * Map schemes to proxy resources.
	 */
	private final Map<String, Resource> scheme2resource;
	/**
	 * Set of exposed services. Using containers, this may be different from the
	 * local interfaces.
	 */
	private final Set<InetSocketAddress> exposedServices;
	/**
	 * Set of exposed addresses. Using containers, this may be different from
	 * the local interfaces.
	 */
	private final Set<InetAddress> exposedHosts;
	/**
	 * Set of exposed ports. Using containers, this may be different from the
	 * local ports.
	 */
	private final Set<Integer> exposedPorts;
	/**
	 * Create message deliverer with proxy support.
	 * 
	 * @param root root resource of coap-proxy-server
	 * @param translater translator for coap-request-uri's
	 */
	public ProxyMessageDeliverer(Resource root, CoapUriTranslator translater) {
		super(root);
		this.translater = translater;
		this.scheme2resource = new HashMap<String, Resource>();
		this.exposedServices = new HashSet<>();
		this.exposedPorts = new HashSet<>();
		this.exposedHosts = new HashSet<>();
	}

	/**
	 * Add exposed service address to suppress recursive requests.
	 * 
	 * @param exposed list of exposed interface addresses to suppress recursive
	 *            proxy request. The exposed interfaces may differ from the
	 *            localone, if containers are used. Maybe {@code null} or empty,
	 *            if recursion suppression is not required.
	 */
	public ProxyMessageDeliverer addExposedServiceAddresses(InetSocketAddress... exposed) {
		if (exposed == null) {
			throw new NullPointerException("exposed interfaces must not be null!");
		}
		if (exposed.length == 0) {
			throw new IllegalArgumentException("exposed interfaces must not be empty!");
		}
		Collection<InetAddress> all = NetworkInterfacesUtil.getNetworkInterfaces();
		for (InetSocketAddress inetAddress : exposed) {
			LOGGER.info("address {}", inetAddress);
			this.exposedPorts.add(inetAddress.getPort());
			InetAddress address = inetAddress.getAddress();
			if (address.isAnyLocalAddress()) {
				for (InetAddress eAddress : all) {
					this.exposedServices.add(new InetSocketAddress(eAddress, inetAddress.getPort()));
					this.exposedHosts.add(eAddress);
				}
			} else {
				this.exposedServices.add(inetAddress);
				this.exposedHosts.add(address);
			}
		}
		for (Integer port : exposedPorts) {
			LOGGER.info("Exposed port {}", port);
		}
		for (InetAddress address : exposedHosts) {
			LOGGER.info("Exposed host {}", address);
		}
		for (InetSocketAddress inetAddress : exposedServices) {
			LOGGER.info("Exposed service {}", inetAddress);
		}
		return this;
	}

	/**
	 * 
	 * @param proxies list of proxy resources.
	 */
	public ProxyMessageDeliverer addProxyCoapResources(ProxyCoapResource... proxies) {
		if (proxies == null) {
			throw new NullPointerException("proxies must not be null!");
		}
		if (proxies.length == 0) {
			throw new IllegalArgumentException("proxies must not be empty!");
		}
		for (ProxyCoapResource proxy : proxies) {
			Set<String> schemes = proxy.getDestinationSchemes();
			for (String scheme : schemes) {
				if (scheme2resource.put(scheme, proxy) != null) {
					LOGGER.warn("ambig proxy resource for scheme {}!", scheme);
				}
			}
		}
		return this;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Route proxy requests to registered proxy resources. Suppress forwarding
	 * of proxy request to own exposed interfaces reducing recursion.
	 */
	@Override
	protected Resource findResource(Exchange exchange) {
		Resource resource = null;
		Request request = exchange.getRequest();
		OptionSet options = request.getOptions();
		boolean proxyOption = options.hasProxyUri() || options.hasProxyScheme();
		boolean hostOption = options.hasUriHost() || options.hasUriPort();

		if (proxyOption || hostOption) {
			try {
				String scheme = translater.getDestinationScheme(request);
				if (scheme != null) {
					scheme = scheme.toLowerCase();
					resource = scheme2resource.get(scheme);
					if (!proxyOption && CoAP.isSupportedScheme(scheme) && !exposedServices.isEmpty()) {
						if (resource != null) {
							// check, if proxy is destination.
							Integer port = options.getUriPort();
							String host = options.getUriHost();
							if (host == null) {
								if (exposedPorts.contains(port)) {
									// proxy is destination
									resource = null;
								}
							} else {
								if (port == null) {
									try {
										InetAddress address = InetAddress.getByName(host);
										if (exposedHosts.contains(address)) {
											// proxy is destination
											resource = null;
										}
									} catch (UnknownHostException e) {
										// destination not reachable
										resource = null;
									}
								} else {
									InetSocketAddress destination = new InetSocketAddress(host, port);
									if (destination.isUnresolved() || exposedServices.contains(destination)) {
										// destination not reachable
										// or proxy is destination
										resource = null;
									}
								}
							}
						}
						if (resource == null) {
							// proxy is destionation, try to find local resource
							resource = super.findResource(exchange);
						}
					}
			}
			} catch (TranslationException e) {
				LOGGER.debug("Bad proxy request", e);
			}
		} else {
			resource = super.findResource(exchange);
		}
		if (resource != null && request.getDestinationContext() == null) {
			if (exchange.getEndpoint() != null) {
				// set local receiving addess as destination
				request.setDestinationContext(new AddressEndpointContext(exchange.getEndpoint().getAddress()));
			}
		}
		return resource;
	}
}
