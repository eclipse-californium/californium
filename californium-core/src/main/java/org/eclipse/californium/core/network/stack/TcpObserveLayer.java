/*******************************************************************************
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - Initial implementation,
 *                                                    Derived from ObserveLayer
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import java.util.logging.Logger;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.observe.ObserveRelation;

/**
 * TCP related observe/notify handling.
 * No CON/NON logic possible nor required.
 */
public class TcpObserveLayer extends AbstractLayer {

	private static final Logger LOGGER = Logger.getLogger(TcpObserveLayer.class.getName());

	private static final Integer CANCEL = 1;

	/**
	 * Creates a new observe layer for a configuration.
	 * 
	 * @param config The configuration values to use.
	 */
	public TcpObserveLayer(final NetworkConfig config) {
		// so far no configuration values for this layer
	}

	@Override
	public void sendRequest(final Exchange exchange, final Request request) {
		if (CANCEL.equals(request.getOptions().getObserve())) {
			/* TODO: don't send, if connection is not available */
		}
		lower().sendRequest(exchange, request);
	}

	@Override
	public void sendResponse(final Exchange exchange, final Response response) {
		final ObserveRelation relation = exchange.getRelation();
		if (relation != null && relation.isEstablished()) {
			if (!response.getOptions().hasObserve()) {
				/* response for cancel request */
				relation.cancel();
				response.setLast(true);
			} else {
				response.setLast(false);
			}
		} // else no observe was requested or the resource does not allow it
		lower().sendResponse(exchange, response);
	}

	@Override
	public void receiveResponse(final Exchange exchange, final Response response) {
		if (response.getOptions().hasObserve() && exchange.getRequest().isCanceled()) {
			// The request was canceled and we no longer want notifications
			LOGGER.finer("Ignore notification for canceled TCP Exchange");
		} else {
			// No observe option in response => always deliver
			upper().receiveResponse(exchange, response);
		}
	}
}
