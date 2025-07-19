/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
import org.eclipse.californium.core.network.Endpoint;

/**
 * MessageInterceptors will be called by a {@link Endpoint} at specific
 * processing stage defined by the method to register it at the
 * {@link Endpoint}.
 * <p>
 * In difference to the Californium API version 2.0.0, where such
 * MessageInterceptors are only intended to be called, when messages arrive from
 * the connector, or when a message is about to be sent over a connector, the
 * processing stage for the callback is now defined by the method to register
 * the interceptor at the {@link Endpoint}. Using
 * {@link Endpoint#addInterceptor(MessageInterceptor)} to register a interceptor
 * results in the exact same behaviour specified as the only scenario supported
 * for 2.0.0.
 * <p>
 * The callbacks are only supported to cancel a message to stop it, if that is
 * documented at the method to register.
 * {@link Endpoint#addInterceptor(MessageInterceptor)} permits that, and
 * therefore results in the exact same behaviour as for 2.0.0.
 */
public interface MessageInterceptor {

	/**
	 * Override this method to be notified when a request is send.
	 *
	 * @param request the request
	 */
	default void sendRequest(Request request) {
		// empty by intention
	}

	/**
	 * Override this method to be notified when a response is send.
	 *
	 * @param response the response
	 */
	default void sendResponse(Response response) {
		// empty by intention
	}

	/**
	 * Override this method to be notified when an empty message is send.
	 * 
	 * @param message the empty message
	 */
	default void sendEmptyMessage(EmptyMessage message) {
		// empty by intention
	}

	/**
	 * Override this method to be notified when request is received.
	 *
	 * @param request the request
	 */
	default void receiveRequest(Request request) {
		// empty by intention
	}

	/**
	 * Override this method to be notified when response is received.
	 *
	 * @param response the response
	 */
	default void receiveResponse(Response response) {
		// empty by intention
	}

	/**
	 * Override this method to be notified when an empty message is received.
	 * 
	 * @param message the message
	 */
	default void receiveEmptyMessage(EmptyMessage message) {
		// empty by intention
	}
}
