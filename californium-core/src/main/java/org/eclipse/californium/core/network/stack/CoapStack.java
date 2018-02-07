/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.html.
 * <p>
 * Contributors:
 * (please refer to gitlog)
 * Achim Kraus (Bosch Software Innovations GmbH) - add striped executor
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.MessageDeliverer;

import eu.javaspecialists.tjsn.concurrency.stripedexecutor.StripedExecutorService;

import java.util.concurrent.ScheduledExecutorService;

/**
 * CoapStack is what CoapEndpoint uses to send messages through distinct layers.
 */
public interface CoapStack {

	// delegate to top
	void sendRequest(Request request);

	// delegate to top
	void sendResponse(Exchange exchange, Response response);

	// delegate to top
	void sendEmptyMessage(Exchange exchange, EmptyMessage message);

	// delegate to bottom
	void receiveRequest(Exchange exchange, Request request);

	// delegate to bottom
	void receiveResponse(Exchange exchange, Response response);

	// delegate to bottom
	void receiveEmptyMessage(Exchange exchange, EmptyMessage message);

	void setExecutor(ScheduledExecutorService executor);
	
	void setExecutor(StripedExecutorService stripedExecutor);

	void setDeliverer(MessageDeliverer deliverer);

	void destroy();

	boolean hasDeliverer();
}
