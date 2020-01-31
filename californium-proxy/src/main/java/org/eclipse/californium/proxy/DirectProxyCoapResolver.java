/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Francesco Corazza - HTTP cross-proxy
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.proxy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.proxy.resources.ForwardingResource;


public class DirectProxyCoapResolver implements ProxyCoapResolver {

	private final static Logger LOGGER = LoggerFactory.getLogger(DirectProxyCoapResolver.class.getCanonicalName());
	
	private ForwardingResource proxyCoapClientResource;
	
	public DirectProxyCoapResolver() { }
	
	public DirectProxyCoapResolver(ForwardingResource proxyCoapClientResource) {
		this.proxyCoapClientResource = proxyCoapClientResource;
	}

	public ForwardingResource getProxyCoapClientResource() {
		return proxyCoapClientResource;
	}

	public void setProxyCoapClientResource(ForwardingResource proxyCoapClientResource) {
		this.proxyCoapClientResource = proxyCoapClientResource;
	}

	@Override
	public void forwardRequest(Exchange exchange) {
		LOGGER.debug("Forward CoAP request to ProxyCoap2Coap: {}", exchange.getRequest());
		proxyCoapClientResource.handleRequest(exchange);
	}
}
