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
package org.eclipse.californium.core.server;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;

/**
 * A strategy for delivering inbound CoAP messages to an appropriate processor.
 * 
 * Implementations should try to deliver incoming CoAP requests to a published
 * resource matching the request's URI. If no such resource exists, implementations
 * should respond with a CoAP {@link ResponseCode#NOT_FOUND}. An incoming CoAP response
 * message should be delivered to its corresponding outbound request.
 */
public interface MessageDeliverer {

	/**
	 * Delivers an inbound CoAP request to an appropriate resource.
	 * 
	 * @param exchange
	 *            the exchange containing the inbound {@code Request}
	 * @throws NullPointerException if exchange is {@code null}.
	 */
	void deliverRequest(Exchange exchange);

	/**
	 * Delivers an inbound CoAP response message to its corresponding request.
	 * 
	 * @param exchange
	 *            the exchange containing the originating CoAP request
	 * @param response
	 *            the inbound CoAP response message
	 * @throws NullPointerException if exchange or response are {@code null}.
	 * @throws IllegalArgumentException if the exchange does not contain a request.
	 */
	void deliverResponse(Exchange exchange, Response response);
}
