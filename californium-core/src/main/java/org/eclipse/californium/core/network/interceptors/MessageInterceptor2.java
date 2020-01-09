/*******************************************************************************
 * Copyright (c) 2020 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.network.interceptors;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Matcher;
import org.eclipse.californium.core.network.stack.CoapStack;

/**
 * This is an extended version of {@link MessageInterceptor} which add post handling events.
 * The "sent" methods are called, when a {@link Message} was successful sent, the
 * {@link #failedToSend(Message, Throwable)}, when that sending failed. The "handled"
 * methods are called, when the message was fully processed by the
 * {@link Matcher} and the {@link CoapStack}.
 */
public interface MessageInterceptor2 extends MessageInterceptor {
	
	/**
	 * Override this method to be notified when a request is sent.
	 *
	 * @param request the request
	 */
	void requestSent(Request request);

	/**
	 * Override this method to be notified when a response is sent.
	 *
	 * @param response the response
	 */
	void responseSent(Response response);

	/**
	 * Override this method to be notified, when sending a message failed.
	 * 
	 * @param message the failed sent message
	 * @param error the send failure.
	 */
	void failedToSend(Message message, Throwable error);

	/**
	 * Override this method to be notified when an empty message is sent.
	 * sent.
	 * 
	 * @param message the empty message
	 */
	void emptyMessageSent(EmptyMessage message);

	/**
	 * Override this method to be notified when a received request has been
	 * handled, unlike {@link #receiveRequest(Request) which is called before.
	 *
	 * @param request the request
	 */
	void requestHandled(Request request);

	/**
	 * Override this method to be notified when a received response has been
	 * handled, unlike {@link #receiveResponse(Response)} which is called before.
	 *
	 * @param response the response
	 */
	void responseHandled(Response response);

	/**
	 * Override this method to be notified when a received empty message has
	 * been handled , unlike {@link #receiveEmptyMessage(EmptyMessage)} which is called
	 * before.
	 * 
	 * @param message the message
	 */
	void emptyMessageHandled(EmptyMessage message);
}
