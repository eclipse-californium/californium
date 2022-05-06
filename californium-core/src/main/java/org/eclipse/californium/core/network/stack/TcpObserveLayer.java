/*******************************************************************************
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - Initial implementation,
 *                                                    Derived from ObserveLayer
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove "is last", not longer meaningful
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.observe.ObserveRelation;
import org.eclipse.californium.core.observe.ObserveRelation.State;
import org.eclipse.californium.elements.config.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TCP related observe/notify handling.
 * No CON/NON logic possible nor required.
 */
public class TcpObserveLayer extends AbstractLayer {

	private static final Logger LOGGER = LoggerFactory.getLogger(TcpObserveLayer.class);

	private static final Integer CANCEL = 1;

	/**
	 * Creates a new observe layer for a configuration.
	 * 
	 * @param config The configuration values to use.
	 * @since 3.0 (changed parameter to Configuration)
	 */
	public TcpObserveLayer(final Configuration config) {
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
		// use dummy type for TCP
		response.setType(Type.CON);
		final ObserveRelation relation = exchange.getRelation();
		State state = ObserveRelation.onResponse(relation, response);
		if (relation != null) {
			if (state == State.CANCELED) {
				if (exchange.isComplete()) {
					LOGGER.debug("drop notification {}, relation was canceled!", response);
					response.setCanceled(true);
					return;
				}
			}
			relation.onSend(response);
		}
		lower().sendResponse(exchange, response);
	}

	@Override
	public void receiveResponse(final Exchange exchange, final Response response) {
		if (response.getOptions().hasObserve() && exchange.getRequest().isCanceled()) {
			// The request was canceled and we no longer want notifications
			LOGGER.debug("ignoring notification for canceled TCP Exchange");
		} else {
			// No observe option in response => always deliver
			upper().receiveResponse(exchange, response);
		}
	}
}
