/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    (a lot of changes from different authors, please refer to gitlog).
 *    Achim Kraus (Bosch Software Innovations GmbH) - make exchangeStore final
 *                                                    remove setMessageExchangeStore
 ******************************************************************************/
package org.eclipse.californium.core.network;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.CorrelationContext;

/**
 * Matcher is the component that matches incoming messages to Exchanges. A {@link UdpMatcher} (used by Coap stack
 * running over UDP or DTLS connector) will support matching ACKs and RSTs based on MID. {@link TcpMatcher} (used by
 * Coap stack running over TCP or TLS connector).
 */
public interface Matcher {

	/**
	 * Starts this matcher.
	 */
	void start();

	/**
	 * Stops this matcher.
	 */
	void stop();

	/**
	 * Notified when Coap stack is sending a request. Signal for matcher to begin tracking.
	 */
	void sendRequest(Exchange exchange, Request request);

	/**
	 * Notified when Coap stack is sending a response. Signal for matcher to begin tracking.
	 */
	void sendResponse(Exchange exchange, Response response);

	/**
	 * Notified when Coap stack is sending ACK or RST. Signal for matcher to begin tracking.
	 */
	void sendEmptyMessage(Exchange exchange, EmptyMessage message);

	/**
	 * Notified when Coap stack is receiving a request. Matcher is expecting to match to Exchange.
	 */
	Exchange receiveRequest(Request request);

	/**
	 * Notified when Coap stack is receiving a response. Matcher is expecting to match to Exchange.
	 */
	Exchange receiveResponse(Response response, CorrelationContext responseContext);

	/**
	 * Notified when Coap stack is receiving an ACK or RST. Matcher is expecting to match to Exchange.
	 */
	Exchange receiveEmptyMessage(EmptyMessage message);

	/**
	 * Clears internal state.
	 */
	void clear();
}
