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
 ******************************************************************************/
package org.eclipse.californium.core.observe;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.CorrelationContext;

/**
 * An observation initiated by a given request, for a particular correlation
 * context.
 */
public class Observation {

	private final Request request;
	private final CorrelationContext context;

	public Observation(Request request, CorrelationContext context) {
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
	 * @return the correlation context for this observation
	 */
	public CorrelationContext getContext() {
		return context;
	}



}
