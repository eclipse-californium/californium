/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Message observer for response timeout.
 * 
 * Starts response timeout for {@code NON} requests after
 * {@link #onSent(boolean)}, and for {@code CON} request after
 * {@link #onAcknowledgement()}.
 * 
 * @since 2.6
 */
public class ResponseTimeout extends MessageObserverAdapter implements Runnable {

	private final static Logger LOGGER = LoggerFactory.getLogger(ResponseTimeout.class);

	private final AtomicReference<ScheduledFuture<?>> responseTimeout = new AtomicReference<>();

	private final Request request;

	private final ScheduledExecutorService executor;

	private final long timeout;

	/**
	 * Create response timeout
	 * 
	 * @param request request to timeout
	 * @param timeout timeout in milliseconds
	 * @param executor service to schedule timeout
	 */
	public ResponseTimeout(Request request, long timeout, ScheduledExecutorService executor) {
		this.request = request;
		this.executor = executor;
		this.timeout = timeout;
	}

	/**
	 * Schedule timeout.
	 * 
	 * Previous schedules are canceled.
	 */
	private void scheduleTimeout() {
		ScheduledFuture<?> schedule = executor.schedule(this, timeout, TimeUnit.MILLISECONDS);
		ScheduledFuture<?> previous = responseTimeout.getAndSet(schedule);
		if (previous != null) {
			previous.cancel(false);
		}
	}

	/**
	 * Cancel timeout.
	 */
	private void cancelTimeout() {
		ScheduledFuture<?> schedule = responseTimeout.getAndSet(null);
		if (schedule != null) {
			schedule.cancel(false);
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Start timeout for {@code NON} requests.
	 */
	@Override
	public void onSent(boolean retransmission) {
		if (!retransmission && (!request.isConfirmable() || !request.hasMID())) {
			// either NON or TCP (no MID)
			if (request.getResponse() == null) {
				LOGGER.trace("start non-response timeout {}", timeout);
				scheduleTimeout();
			}
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Start timeout for {@code CON} requests.
	 */
	@Override
	public void onAcknowledgement() {
		if (request.isConfirmable()) {
			if (request.getResponse() == null) {
				LOGGER.trace("start con-response timeout {}", timeout);
				scheduleTimeout();
			}
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Cancel response timeout.
	 */
	@Override
	public void onResponse(final Response response) {
		cancelTimeout();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Cancel response timeout.
	 */
	@Override
	protected void failed() {
		cancelTimeout();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Mark request as timed out.
	 * 
	 * @see Request#setTimedOut(boolean)
	 */
	@Override
	public void run() {
		if (request.getResponse() == null) {
			LOGGER.trace("response timeout!");
			request.setTimedOut(true);
		}
	}

}
