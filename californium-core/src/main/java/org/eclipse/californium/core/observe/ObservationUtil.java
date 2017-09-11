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
 *    Bosch Software Innovations GmbH - initial implementation. 
 *    Achim Kraus (Bosch Software Innovations GmbH) - add endpoint context 
 *                                                    to shallow clone.
 ******************************************************************************/
package org.eclipse.californium.core.observe;

import org.eclipse.californium.core.coap.Request;

/**
 * Utility for observation.
 */
public final class ObservationUtil {

	/**
	 * Create shallow clone of observation and the contained request.
	 * 
	 * @return a cloned observation with a shallow clone of request, or null, if
	 *         null was provided.
	 * @throws IllegalArgumentException, if observation didn't contain a
	 *             request.
	 */
	public static Observation shallowClone(Observation observation) {
		if (null == observation) {
			return null;
		}
		Request request = observation.getRequest();
		if (null == request) {
			throw new IllegalArgumentException("missing request for observation!");
		}
		Request clonedRequest = new Request(request.getCode());
		clonedRequest.setDestinationContext(request.getDestinationContext());
		clonedRequest.setType(request.getType());
		clonedRequest.setMID(request.getMID());
		clonedRequest.setToken(request.getToken());
		clonedRequest.setOptions(request.getOptions());
		clonedRequest.setPayload(request.getPayload());
		clonedRequest.setUserContext(request.getUserContext());
		return new Observation(clonedRequest, observation.getContext());
	}
}
