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
package org.eclipse.californium.proxy2;

import java.io.IOException;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;

/**
 * A single endpoint.
 * 
 * A {@link CoapEndpoint} process multiple request. The chosen "congestion
 * control" strategy may limit that.
 */
public class ClientSingleEndpoint implements ClientEndpoints {

	/**
	 * Scheme of endpoints.
	 */
	protected String scheme;

	/**
	 * Single endpoint.
	 */
	protected Endpoint endpoint;

	/**
	 * Create new instance from single endpoint.
	 * 
	 * @param endpoint endpoint to send outgoing requests
	 */
	public ClientSingleEndpoint(Endpoint endpoint) {
		this.endpoint = endpoint;
		this.scheme = endpoint.getUri().getScheme();
	}

	@Override
	public String getScheme() {
		return scheme;
	}

	@Override
	public void sendRequest(Request outgoingRequest) throws IOException {
		if (!endpoint.isStarted()) {
			endpoint.start();
		}
		endpoint.sendRequest(outgoingRequest);
	}

	@Override
	public void destroy() {
		endpoint.destroy();
	}

}
