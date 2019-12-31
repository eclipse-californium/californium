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

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.network.Matcher;
import org.eclipse.californium.core.network.stack.CoapStack;

/**
 * MessagePostInterceptors are called after sending or receiving is completed.
 * The send methods are called, when a {@link Message} was successful sent, the
 * {@link #sendError(Message, Throwable)}, when that sending failed. The receive
 * methods are called, when the message was fully processed by the
 * {@link Matcher} and the {@link CoapStack}.
 */
public interface MessagePostInterceptor extends MessageInterceptor {

	/**
	 * Override this method to be notified, when sending a message failed.
	 * 
	 * @param message the failed sent message
	 * @param error the send failure.
	 */
	void sendError(Message message, Throwable error);

}
