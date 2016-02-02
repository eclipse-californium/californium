/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Kai Hudalla (Bosch Software Innovations GmbH) - remove obsolete dependencies
 *                                                    introduced in JavaDoc
 ******************************************************************************/
package org.eclipse.californium.core.network.interceptors;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;

/**
 * MessageInterceptors register at an endpoint. When messages arrive from the
 * connector, the corresponding receive-method is called. When a message is
 * about to be sent over a connector, the corresponding send method is called.
 * The interceptor can be thought of being placed inside an <code>CoapEndpoint</code>
 * just between the message <code>Serializer</code> and the <code>Matcher</code>.
 * <p>
 * A <code>MessageInterceptor</code> can cancel a message to stop it. If it is
 * an outgoing message that traversed down through the <code>CoapStack</code> to the
 * <code>Matcher</code> and is now intercepted and canceled, will not reach the
 * <code>Connector</code>. If it is an incoming message coming from the
 * <code>Connector</code> to the <code>DataParser</code> and is now intercepted and
 * canceled, will not reach the <code>Matcher</code>.
 */
public interface MessageInterceptor {

	/**
	 * Override this method to be notified when a request is about to be sent.
	 *
	 * @param request the request
	 */
	void sendRequest(Request request);

	/**
	 * Override this method to be notified when a response is about to be sent.
	 *
	 * @param response the response
	 */
	void sendResponse(Response response);

	/**
	 * Override this method to be notified when an empty message is about to be
	 * sent.
	 * 
	 * @param message the empty message
	 */
	void sendEmptyMessage(EmptyMessage message);

	/**
	 * Override this method to be notified when request has been received.
	 *
	 * @param request the request
	 */
	void receiveRequest(Request request);

	/**
	 * Override this method to be notified when response has been received.
	 *
	 * @param response the response
	 */
	void receiveResponse(Response response);

	/**
	 * Override this method to be notified when an empty message has been
	 * received.
	 * 
	 * @param message the message
	 */
	void receiveEmptyMessage(EmptyMessage message);
}
