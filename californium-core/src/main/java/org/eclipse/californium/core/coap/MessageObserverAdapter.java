/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add onSent() and onSendError()
 *                                                    implement onReject, onTimeout,
 *                                                    and onSendError calling failed().
 *                                                    issue #305
 *    Achim Kraus (Bosch Software Innovations GmbH) - add onReadyToSend() to fix rare
 *                                                    race condition in block1wise
 *                                                    when the generated token was 
 *                                                    copied too late (after sending). 
 *    Achim Kraus (Bosch Software Innovations GmbH) - move onContextEstablished
 *                                                    to MessageObserver.
 *                                                    Issue #487
 *    Achim Kraus (Bosch Software Innovations GmbH) - add onConnect
 ******************************************************************************/
package org.eclipse.californium.core.coap;

/**
 * An abstract adapter class for reacting to a message's lifecylce events.
 * <p>
 * This class exists as convenience for creating message observer objects.
 * <p>
 * Subclasses should override the methods for the events of interest.
 * <p>
 * An instance of the concrete message observer can then be registered with a
 * message using {@link Message#addMessageObserver(MessageObserver)} or
 * {@link Message#addMessageObserver(int, MessageObserver)}.
 */
public abstract class MessageObserverAdapter implements MessageObserver {

	/**
	 * Indicates, that the observer is used for internal purpose.
	 * 
	 * @since 3.0
	 */
	private final boolean isInternal;

	/**
	 * Create none-internal instance.
	 */
	protected MessageObserverAdapter() {
		this(false);
	}

	/**
	 * Create instance.
	 * 
	 * @param isInternal {@code true}, for internal instances, {@code false},
	 *            otherwise.
	 */
	protected MessageObserverAdapter(boolean isInternal) {
		this.isInternal = isInternal;
	}

	@Override
	public boolean isInternal() {
		return isInternal;
	}

	@Override
	public void onReject() {
		failed();
	}

	@Override
	public void onTimeout() {
		failed();
	}

	@Override
	public void onSendError(Throwable error) {
		failed();
	}

	@Override
	public void onResponseHandlingError(Throwable error) {
		failed();
	}

	/**
	 * Common method to be overwritten to catch failed messages.
	 * 
	 * @see #onReject()
	 * @see #onTimeout()
	 * @see #onSendError(Throwable)
	 * @see #onResponseHandlingError(Throwable)
	 */
	protected void failed() {
		// empty default implementation
	}

}
