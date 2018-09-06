/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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

import org.eclipse.californium.elements.EndpointContext;

/**
 * An abstract adapter class for reacting to a message's lifecylce events.
 * <p>
 * The methods in this class are empty, except {@link #onReject()},
 *  {@link #onTimeout()}, and
 * {@link #onSendError(Throwable)}, which are calling {@link #failed()} as
 * default implementation. This class exists as convenience for creating message
 * observer objects.
 * <p>
 * Subclasses should override the methods for the events of interest.
 * <p>
 * An instance of the concrete message observer can then be registered with a
 * message using the message's <code>addMessageObserver</code> method.
 */
public abstract class MessageObserverAdapter implements MessageObserver {

	@Override
	public void onRetransmission() {
		// empty default implementation
	}

	@Override
	public void onResponse(final Response response) {
		// empty default implementation
	}

	@Override
	public void onAcknowledgement() {
		// empty default implementation
	}

	@Override
	public void onReject() {
		failed();
	}

	@Override
	public void onCancel() {
		// empty default implementation
	}

	@Override
	public void onTimeout() {
		failed();
	}

	@Override
	public void onReadyToSend() {
		// empty default implementation
	}

	@Override
	public void onConnecting() {
		// empty default implementation
	}

	@Override
	public void onDtlsRetransmission(int flight) {
		// empty default implementation
	}

	@Override
	public void onSent() {
		// empty default implementation
	}

	@Override
	public void onSendError(Throwable error) {
		failed();
	}

	@Override
	public void onContextEstablished(EndpointContext endpointContext) {
		// empty default implementation
	}

	@Override
	public void onComplete() {
		// empty default implementation
	}

	/**
	 * Common method to be overwritten to catch failed messages.
	 * 
	 * @see #onReject()
	 * @see #onTimeout()
	 * @see #onSendError(Throwable)
	 */
	protected void failed() {
		// empty default implementation
	}

}
