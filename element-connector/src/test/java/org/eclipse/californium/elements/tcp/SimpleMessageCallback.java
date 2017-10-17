/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add onError. issue #305
 *    Achim Kraus (Bosch Software Innovations GmbH) - add javadoc for parameter
 *                                                    timeout
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MessageCallback;

/**
 * A simple message callback to access the endpoint context when sending a
 * message.
 */
public class SimpleMessageCallback implements MessageCallback {

	/**
	 * endpoint context of sent message.
	 */
	private EndpointContext context;
	/**
	 * Error of sending message.
	 */
	private Throwable sendError;
	/**
	 * Indicator for message sent.
	 */
	private boolean sent;

	@Override
	public synchronized void onContextEstablished(EndpointContext context) {
		this.context = context;
		notifyAll();
	}

	@Override
	public synchronized void onSent() {
		sent = true;
		notifyAll();
	}

	@Override
	public synchronized void onError(Throwable error) {
		this.sendError = error;
		notifyAll();
	}

	/**
	 * Get endpoint context of sent message.
	 * 
	 * @return endpoint context of sent message, or null, if not jet sent or
	 *         no endpoint context is available.
	 * @see #getEndpointContext(long)
	 */
	public synchronized EndpointContext getEndpointContext() {
		return context;
	}

	/**
	 * Check, if message was sent.
	 * 
	 * @return {@code true}, if message was sent, {@code false} otherwise
	 * @see #isSent(long)
	 */
	public synchronized boolean isSent() {
		return sent;
	}

	/**
	 * Get error of sending message.
	 * 
	 * @return error of sending message, or null, if not jet sent or no error
	 *         occurred.
	 * @see #getError(long)
	 */
	public synchronized Throwable getError() {
		return sendError;
	}

	/**
	 * Get endpoint context of sent message waiting with timeout.
	 * 
	 * @param timeout timeout in milliseconds
	 * @return endpoint context of sent message, or null, if not sent within
	 *         provided timeout or no endpoint context is available.
	 * @see #getEndpointContext()
	 */
	public synchronized EndpointContext getEndpointContext(long timeout) throws InterruptedException {
		if (null == context && null == sendError) {
			wait(timeout);
		}
		return context;
	}

	/**
	 * Check, if message was sent with timeout.
	 * 
	 * @param timeout timeout in milliseconds
	 * @return {@code true}, if message was sent with the timeout, {@code false}
	 *         otherwise
	 * @see #isSent()
	 */
	public synchronized boolean isSent(long timeout) throws InterruptedException {
		if (!sent && null == sendError) {
			wait(timeout);
		}
		return sent;
	}

	/**
	 * Get error of sending message waiting with timeout.
	 * 
	 * @param timeout timeout in milliseconds
	 * @return error of sending message, or {@code null}, if not occurred within
	 *         provided timeout.
	 * @see #getError()
	 */
	public synchronized Throwable getError(long timeout) throws InterruptedException {
		if (!sent && null == sendError) {
			wait(timeout);
		}
		return sendError;
	}

}
