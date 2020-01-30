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

import java.util.Set;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.network.Exchange;

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
	 * @param visable visibility of the resource
	 * @param accept accept CON request befor forwarding the request
	 */
	public ProxyCoapResource(String name, boolean visable, boolean accept) {
		// set the resource hidden
		super(name, visable);
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
}
