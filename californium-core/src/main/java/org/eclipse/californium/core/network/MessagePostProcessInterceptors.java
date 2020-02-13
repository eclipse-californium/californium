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
package org.eclipse.californium.core.network;

import java.util.List;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.network.interceptors.MessageInterceptor;
import org.eclipse.californium.core.network.stack.CoapStack;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.util.PublicAPIExtension;

/**
 * Extension interface for {@link Endpoint} to add {@link MessageInterceptor} to be
 * called, when the messages are fully processed. Will be merged into
 * {@link Endpoint} with the next major release.
 * @since 2.1
 */
@PublicAPIExtension(type = Endpoint.class)
public interface MessagePostProcessInterceptors {

	/**
	 * Adds a message interceptor to this endpoint to be called, when messages
	 * are fully processed. The send methods are called, when a {@link Message}
	 * was successful sent by the {@link Connector}, or the sending failed. The
	 * receive methods are called, when the message, received by the
	 * {@link Connector}, was fully processed by the {@link Matcher} and the
	 * {@link CoapStack}.
	 * <p>
	 * A {@code MessageInterceptor} registered here must not cancel the message.
	 * </p>
	 *
	 * @param interceptor the interceptor
	 */
	void addPostProcessInterceptor(MessageInterceptor interceptor);

	/**
	 * Removes the interceptor.
	 *
	 * @param interceptor the interceptor
	 */
	void removePostProcessInterceptor(MessageInterceptor interceptor);

	/**
	 * Gets all registered message post process interceptor.
	 *
	 * @return an immutable list of the registered message post process interceptors.
	 */
	List<MessageInterceptor> getPostProcessInterceptors();

}
