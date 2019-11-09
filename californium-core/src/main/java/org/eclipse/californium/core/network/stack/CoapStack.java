/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    refer to gitlog
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.MessageDeliverer;

import java.util.concurrent.ScheduledExecutorService;

/**
 * CoapStack is what CoapEndpoint uses to send messages through distinct layers.
 */
public interface CoapStack {

	// delegate to top
	void sendRequest(Exchange exchange, Request request);

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

	void setExecutors(ScheduledExecutorService mainExecutor, ScheduledExecutorService secondaryExecutor);

	void setDeliverer(MessageDeliverer deliverer);

	void start();

	void destroy();

	boolean hasDeliverer();
}
