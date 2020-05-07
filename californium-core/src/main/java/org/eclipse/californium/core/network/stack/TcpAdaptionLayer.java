/*******************************************************************************
 * Copyright (c) 2015, 2017 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - Initial implementation
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;

/**
 * TCP adaption layer. Set acknowledged on response receiving.
 */
public class TcpAdaptionLayer extends AbstractLayer {

	private static final Logger LOGGER = LoggerFactory.getLogger(TcpAdaptionLayer.class);

	@Override
	public void sendEmptyMessage(final Exchange exchange, final EmptyMessage message) {

		if (message.isConfirmable()) {
			// CoAP over TCP uses empty messages as pings for keep alive.
			// TODO: Should we instead rely on TCP keep-alives configured via TCP Connector?
			lower().sendEmptyMessage(exchange, message);
		} else if (exchange != null) {
			// Empty messages don't make sense when running over TCP connector.
			LOGGER.warn("attempting to send empty message (ACK/RST) in TCP mode {} - {}", message, exchange.getCurrentRequest(), new Throwable());
		} else {
			// Empty messages don't make sense when running over TCP connector.
			LOGGER.warn("attempting to send empty message (ACK/RST) in TCP mode {}", message, new Throwable());
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
		LOGGER.info("discarding empty message received in TCP mode: {}", message);
	}

}
