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

/**
 * Client Endpoints.
 */
public interface ClientEndpoints {

	/**
	 * Returns scheme of endpoints.
	 * 
	 * @return scheme of endpoints
	 */
	String getScheme();

	/**
	 * Send request using the client endpoints.
	 * 
	 * @param outgoingRequest outgoing request
	 * @throws IOException if an i/o error occurred.
	 */
	public void sendRequest(Request outgoingRequest) throws IOException;

	/**
	 * Destroy client endpoints.
	 */
	public void destroy();
}
