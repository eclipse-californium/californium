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
 *    Bosch Software Innovations GmbH - initial creation
 *                                      extracted from ExchangeCleanupLayer
 *    Achim Kraus (Bosch Software Innovations GmbH) - make cleanup message observer
 *                                                    extendible to support multicast
 *                                                    variant.
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.elements.util.NoPublicAPI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Cleanup exchange when user cancelled outgoing requests or messages which
 * failed to be send.
 */
@NoPublicAPI
public class CleanupMessageObserver extends MessageObserverAdapter {

	protected static final Logger LOGGER = LoggerFactory.getLogger(CleanupMessageObserver.class);

	protected final Exchange exchange;

	protected CleanupMessageObserver(final Exchange exchange) {
		super(true);
		this.exchange = exchange;
	}

	@Override
	public boolean isInternal() {
		return true;
	}

	@Override
	public void onCancel() {
		complete("canceled");
	}

	@Override
	public void failed() {
		complete("failed");
	}

	protected void complete(final String action) {
		if (exchange.executeComplete()) {
			if (exchange.isOfLocalOrigin()) {
				Request request = exchange.getCurrentRequest();
				LOGGER.debug("{}, {} request [MID={}, {}]", action, exchange, request.getMID(), request.getToken());
			} else {
				Response response = exchange.getCurrentResponse();
				LOGGER.debug("{}, {} response [MID={}, {}]", action, exchange, response.getMID(), response.getToken());
			}
		}
	}
}
