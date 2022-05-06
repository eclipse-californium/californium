/*******************************************************************************
 * Copyright (c) 2016, 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - add special multicast cleanup
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.elements.config.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A layer that reacts to user cancelled outgoing requests or messages which
 * failed to be send, and completes exchange, which causes state clean up.
 */
public class ExchangeCleanupLayer extends AbstractLayer {

	static final Logger LOGGER = LoggerFactory.getLogger(ExchangeCleanupLayer.class);

	/**
	 * Multicast and NoResponse lifetime in milliseconds.
	 */
	private final int lifetime;

	/**
	 * Create exchange cleanup layer.
	 * 
	 * @param config configuration
	 * @since 3.0 (changed parameter to Configuration)
	 */
	public ExchangeCleanupLayer(final Configuration config) {
		this.lifetime = config.getTimeAsInt(CoapConfig.NON_LIFETIME, TimeUnit.MILLISECONDS)
				+ config.getTimeAsInt(CoapConfig.MAX_LATENCY, TimeUnit.MILLISECONDS)
				+ config.getTimeAsInt(CoapConfig.MAX_SERVER_RESPONSE_DELAY, TimeUnit.MILLISECONDS);
	}

	/**
	 * Adds a message observer to the request to be sent which completes the
	 * exchange if the request gets canceled or failed.
	 * 
	 * @param exchange The (locally originating) exchange that the request is
	 *            part of.
	 * @param request The outbound request.
	 */
	@Override
	public void sendRequest(final Exchange exchange, final Request request) {
		if (request.isMulticast()) {
			request.addMessageObserver(new MulticastCleanupMessageObserver(exchange, executor, lifetime));
		} else {
			if (request.getOptions().hasNoResponse()) {
				request.addMessageObserver(new NoResponseCleanupMessageObserver(exchange, executor, lifetime));
			} else {
				request.addMessageObserver(new CleanupMessageObserver(exchange));
			}
		}
		super.sendRequest(exchange, request);
	}

	/**
	 * Adds a message observer to a confirmable response to be sent which
	 * completes the exchange if the response gets canceled or failed.
	 * 
	 * @param exchange The (remotely originating) exchange that the response is
	 *            part of.
	 * @param response The outbound response.
	 */
	@Override
	public void sendResponse(final Exchange exchange, final Response response) {
		if (exchange.getRelation() == null) {
			Type type = response.getType();
			if (type == null || type == Type.CON) {
				// if type is set later, add the cleanup preventive
				response.addMessageObserver(new CleanupMessageObserver(exchange));
			}
		}
		super.sendResponse(exchange, response);
	}

	@Override
	public void receiveResponse(final Exchange exchange, final Response response) {
		if (!exchange.getRequest().isMulticast()) {
			// multicast exchanges are completed with MulticastCleanupMessageObserver
			exchange.setComplete();
			exchange.getRequest().onTransferComplete();
		}
		super.receiveResponse(exchange, response);
	}

}
