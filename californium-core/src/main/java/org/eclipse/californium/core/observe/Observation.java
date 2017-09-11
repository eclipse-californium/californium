/*******************************************************************************
 * Copyright (c) 2016 Sierra Wireless and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 *    
 * Contributors:
 * Please refer to gitlog.
 * 
 * Achim Kraus (Bosch Software Innovations GmbH) - rename CorrelationContext to
 *                                                 EndpointContext. 
 ******************************************************************************/
package org.eclipse.californium.core.observe;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.EndpointContext;

/**
 * An observation initiated by a given request, for a particular correlation
 * context.
 */
public final class Observation {

	/**
	 * Initiate request for observation. 
	 */
	private final Request request;
	/**
	 * Endpoint context the request was sent in.
	 */
	private final EndpointContext context;

	/**
	 * Creates a new observation for a request and a endpoint context.
	 * 
	 * @param request The request that initiated the observation.
	 * @param context The endpoint context of the request.
	 * @throws NullPointerException if the request is {@code null}.
	 * @throws IllegalArgumentException if the request doesn't have its observe option set to 0.
	 */
	public Observation(final Request request, final EndpointContext context) {

		if (request == null) {
			throw new NullPointerException("request must not be null");
		} else if (!request.isObserve()) {
			throw new IllegalArgumentException("request has no observe=0 option");
		}
		this.request = request;
		this.context = context;
	}

	/**
	 * @return the request which initiated the observation
	 */
	public Request getRequest() {
		return request;
	}

	/**
	 * Gets the endpoint context the requeste was sent in.
	 * 
	 * @return the endpoint context for this observation
	 */
	public EndpointContext getContext() {
		return context;
	}
}
