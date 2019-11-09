/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation. 
 ******************************************************************************/
package org.eclipse.californium.core.network;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;

/**
 * Endpoint message receiver. Passes exchange and message to endpoints
 * protocol-stack.
 */
public interface EndpointReceiver {

	/**
	 * Process received request.
	 * 
	 * @param exchange exchange of request
	 * @param request received request
	 */
	void receiveRequest(Exchange exchange, Request request);

	/**
	 * Process received response.
	 * 
	 * @param exchange exchange of response
	 * @param response received response
	 */
	void receiveResponse(Exchange exchange, Response response);

	/**
	 * Process received empty message.
	 * 
	 * @param exchange exchange of empty message
	 * @param message received empty message
	 */
	void receiveEmptyMessage(Exchange exchange, EmptyMessage message);

	/**
	 * Reject (received) message.
	 * 
	 * @param message received message to reject
	 */
	void reject(Message message);
}
