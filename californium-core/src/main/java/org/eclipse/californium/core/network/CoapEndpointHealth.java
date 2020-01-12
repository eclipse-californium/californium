/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.network;

import org.eclipse.californium.core.network.interceptors.MessageInterceptor;

/**
 * Health interface for {@link CoapEndpoint}
 * 
 * @deprecated use {@link MessageInterceptor} and
 *             {@link CoapEndpoint#addPostProcessInterceptor(MessageInterceptor)}
 */
@Deprecated
public interface CoapEndpointHealth {

	/**
	 * Dump health data.
	 * 
	 * @param tag logging tag
	 */
	void dump(String tag);

	/**
	 * Check, if collecting health data is enabled.
	 * 
	 * @return {@code true}, if health is enabled, {@code false}, otherwise.
	 */
	boolean isEnabled();

	/**
	 * Report received request.
	 * 
	 * @param duplicate {@code true} for duplicates, {@code false} for new
	 *            requests.
	 */
	void receivedRequest(boolean duplicate);

	/**
	 * Report received responses.
	 * 
	 * @param duplicate {@code true} for duplicates, {@code false} for new
	 *            responses.
	 */
	void receivedResponse(boolean duplicate);

	/**
	 * Report received reject.
	 */
	void receivedReject();

	/**
	 * Report sent request.
	 * 
	 * @param retransmission {@code true} for retransmission, {@code false} for
	 *            initial transmission.
	 */
	void sentRequest(boolean retransmission);

	/**
	 * Report sent response.
	 * 
	 * @param retransmission {@code true} for retransmission, {@code false} for
	 *            initial transmission.
	 */
	void sentResponse(boolean retransmission);

	/**
	 * Report sent reject.
	 */
	void sentReject();

	/**
	 * Report send error.
	 */
	void sendError();
}
