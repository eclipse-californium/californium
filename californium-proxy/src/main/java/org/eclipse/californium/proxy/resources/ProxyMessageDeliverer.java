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

package org.eclipse.californium.proxy.resources;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.ServerMessageDeliverer;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.proxy.CoapUriTranslator;
import org.eclipse.californium.proxy.TranslationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ProxyMessageDeliverer extends ServerMessageDeliverer {

	private static final Logger LOGGER = LoggerFactory.getLogger(ProxyMessageDeliverer.class);

	private final CoapUriTranslator translater;
	private final Map<String, Resource> scheme2resource;
	private final Set<InetSocketAddress> exposedServices;
	private final Set<InetAddress> exposedHosts;
	private final Set<Integer> exposedPorts;

	public ProxyMessageDeliverer(Resource root, CoapUriTranslator translater, Map<String, Resource> scheme2resource,
			InetSocketAddress... exposed) {
		super(root);
		this.translater = translater;
		this.scheme2resource = scheme2resource;
		this.exposedServices = new HashSet<>();
		this.exposedPorts = new HashSet<>();
		this.exposedHosts = new HashSet<>();
		if (exposed == null || exposed.length == 0) {
			LOGGER.warn("No exposed interfaces are provided!");
		} else {
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
		}
	}

	@Override
	protected Resource findResource(Exchange exchange) {
		Resource resource = super.findResource(exchange);
		Request request = exchange.getRequest();
		boolean proxyOption = request.getOptions().hasProxyUri() || request.getOptions().hasProxyScheme();
		if (resource == getRootResource() && proxyOption) {
			resource = null;
		}
		if (resource == null) {
			try {
				String scheme = translater.getDestinationScheme(request);
				if (scheme != null) {
					scheme = scheme.toLowerCase();
					resource = scheme2resource.get(scheme);
					if (resource != null && !proxyOption && CoAP.isSupportedScheme(scheme)) {
						// check, if proxy is destination.
						Integer port = request.getOptions().getUriPort();
						String host = request.getOptions().getUriHost();
						if (host == null) {
							if (port == null || exposedPorts.contains(port)) {
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
				}
			} catch (TranslationException e) {
				LOGGER.debug("Bad proxy request", e);
			}
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
