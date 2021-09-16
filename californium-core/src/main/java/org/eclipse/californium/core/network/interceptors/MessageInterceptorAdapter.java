/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.network.interceptors;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Endpoint;

/**
 * An abstract adapter class for reacting to a message's transfer events.
 * <p>
 * The methods in this class are empty.
 * <p>
 * Subclasses should override the methods for the events of interest.
 * <p>
 * An instance of the concrete message intercepter can then be registered with
 * {@link Endpoint#addInterceptor(MessageInterceptor)} or
 * {@link Endpoint#addPostProcessInterceptor(MessageInterceptor)}.
 */
public abstract class MessageInterceptorAdapter implements MessageInterceptor {

	@Override
	public void sendRequest(Request request) {
		// empty default implementation
	}

	@Override
	public void sendResponse(Response response) {
		// empty default implementation
	}

	@Override
	public void sendEmptyMessage(EmptyMessage message) {
		// empty default implementation
	}

	@Override
	public void receiveRequest(Request request) {
		// empty default implementation
	}

	@Override
	public void receiveResponse(Response response) {
		// empty default implementation
	}

	@Override
	public void receiveEmptyMessage(EmptyMessage message) {
		// empty default implementation
	}

}
