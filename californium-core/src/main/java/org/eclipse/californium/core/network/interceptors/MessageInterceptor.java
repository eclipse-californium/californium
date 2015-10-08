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
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 ******************************************************************************/
package org.eclipse.californium.core.network.interceptors;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoAPEndpoint;
import org.eclipse.californium.core.network.Matcher;
import org.eclipse.californium.core.network.serialization.DataParser;
import org.eclipse.californium.core.network.serialization.Serializer;
import org.eclipse.californium.core.network.stack.CoapStack;
import org.eclipse.californium.elements.Connector;


/**
 * MessageIntercepters registers at an endpoint. When messages arrive from the
 * connector, the corresponding receive-method is called. When a message is
 * about to be sent over a connector, the corresponding send-method is called.
 * The intercepter can be sought of being placed inside an {@link CoAPEndpoint} just
 * between the message {@link Serializer} and the {@link Matcher}.
 * <p>
 * A <code>MessageInterceptor</code> can cancel a message to stop it. If it is
 * an outgoing message that traversed down through the {@link CoapStack} to the
 * <code>Matcher</code> and is now intercepted and canceled, will not reach the
 * {@link Connector}. If it is an incoming message coming from the
 * <code>Connector</code> to the {@link DataParser} and is now intercepted and
 * canceled, will not reach the <code>Matcher</code>.
 */
public interface MessageInterceptor {

	/**
	 * Override this method to be notified when a request is about to be sent.
	 *
	 * @param request the request
	 */
	public void sendRequest(Request request);
	
	/**
	 * Override this method to be notified when a response is about to be sent.
	 *
	 * @param response the response
	 */
	public void sendResponse(Response response);
	
	/**
	 * Override this method to be notified when an empty message is about to be
	 * sent.
	 * 
	 * @param message the empty message
	 */
	public void sendEmptyMessage(EmptyMessage message);
	
	/**
	 * Override this method to be notified when request has been received.
	 *
	 * @param request the request
	 */
	public void receiveRequest(Request request);
	
	/**
	 * Override this method to be notified when response has been received.
	 *
	 * @param response the response
	 */
	public void receiveResponse(Response response);
	
	/**
	 * Override this method to be notified when an empty message has been
	 * received.
	 * 
	 * @param message the message
	 */
	public void receiveEmptyMessage(EmptyMessage message);
	
}
