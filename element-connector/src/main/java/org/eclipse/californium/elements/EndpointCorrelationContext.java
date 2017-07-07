/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.elements;

/**
 * A correlation context that supports endpoint identity.
 */
public class EndpointCorrelationContext extends MapBasedCorrelationContext {

	/**
	 * Creates a new correlation context from endpoint identity.
	 * 
	 * @param endpointId the endpoint identifier.
	 * @throws NullPointerException if endpointId is <code>null</code>.
	 */
	public EndpointCorrelationContext(String endpointId) {
		if (endpointId == null) {
			throw new NullPointerException("endpoint ID must not be null");
		} else {
			put(KEY_ENDPOINT_ID, endpointId);
		}
	}

	public String getEndpointId() {
		return get(KEY_ENDPOINT_ID);
	}

	@Override
	public String toString() {
		return String.format("EPID(%s)", getEndpointId());
	}
}
