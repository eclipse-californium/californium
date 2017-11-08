/*******************************************************************************
 * Copyright (c) 2016, 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.Exchange;

/**
 * A layer that reacts to user cancelled outgoing requests, and completes exchange, which causes state clean up.
 */
public class ExchangeCleanupLayer extends AbstractLayer {

	private static final Logger LOGGER = LoggerFactory.getLogger(ExchangeCleanupLayer.class.getName());

	/**
	 * Adds a message observer to the request to be sent which
	 * completes the exchange if the request gets canceled.
	 * 
	 * @param exchange The (locally originating) exchange that the request is part of.
	 * @param request The outbound request.
	 */
	@Override
	public void sendRequest(final Exchange exchange, final Request request) {

		request.addMessageObserver(new CancelledMessageObserver(exchange));
		lower().sendRequest(exchange, request);
	}

	private static class CancelledMessageObserver extends MessageObserverAdapter {

		private final Exchange exchange;

		CancelledMessageObserver(final Exchange exchange) {
			this.exchange = exchange;
		}

		@Override
		public void onCancel() {

			if (!exchange.isComplete()) {
				LOGGER.debug("completing canceled request [MID={}, token={}]",
						new Object[]{ exchange.getRequest().getMID(), exchange.getRequest().getTokenString() });
				exchange.setComplete();
			}
		}
	}
}
