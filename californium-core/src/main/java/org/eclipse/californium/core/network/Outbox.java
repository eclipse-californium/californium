/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 ******************************************************************************/
package org.eclipse.californium.core.network;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;

public interface Outbox {

	/**
	 * Sends the specified request over the connector that the stack is
	 * connected to.
	 * 
	 * @param exchange
	 *            the exchange
	 * @param request
	 *            the request
	 */
	public void sendRequest(Exchange exchange, Request request);

	/**
	 * Sends the specified response over the connector that the stack is
	 * connected to.
	 * 
	 * @param exchange
	 *            the exchange
	 * @param response
	 *            the response
	 */
	public void sendResponse(Exchange exchange, Response response);

	/**
	 * Sends the specified empty message over the connector that the stack is
	 * connected to.
	 * 
	 * @param exchange
	 *            the exchange
	 * @param emptyMessage
	 *            the empty message
	 */
	public void sendEmptyMessage(Exchange exchange, EmptyMessage emptyMessage);
	
}
