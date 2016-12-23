/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - Initial implementation
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;

/**
 * TCP adaption layer. Set acknowledged on response receiving.
 */
public class TcpAdaptionLayer extends AbstractLayer {

	private static final Logger LOGGER = Logger.getLogger(TcpAdaptionLayer.class.getName());

	@Override
	public void sendEmptyMessage(final Exchange exchange, final EmptyMessage message) {

		if (message.isConfirmable()) {
			// CoAP over TCP uses empty messages as pings for keep alive.
			// TODO: Should we isntead rely on TCP keep-alives configured via TCP Connector?
			lower().sendEmptyMessage(exchange, message);
		} else {
			// Empty messages don't make sense when running over TCP connector.
			LOGGER.log(Level.WARNING, "Attempting to send empty message (ACK/RST) in TCP mode {0}", message);
		}
	}

	@Override
	public void receiveRequest(final Exchange exchange, final Request request) {
		request.setAcknowledged(true);
		upper().receiveRequest(exchange, request);
	}

	@Override
	public void receiveResponse(Exchange exchange, Response response) {
		response.setAcknowledged(true);
		upper().receiveResponse(exchange, response);
	}

	@Override
	public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
		// Empty messages are ignored when running over TCP connector.
		LOGGER.log(Level.INFO, "Received empty message in TCP mode {0}", message);
	}

}
