/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.elements.util.NoPublicAPI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Cleanup no-response exchange also by time.
 * 
 * @since 3.0
 */
@NoPublicAPI
public class NoResponseCleanupMessageObserver extends CleanupMessageObserver {

	static final Logger LOGGER = LoggerFactory.getLogger(NoResponseCleanupMessageObserver.class);

	/**
	 * Scheduler for time based exchange completion.
	 */
	private final ScheduledExecutorService scheduledExecutor;
	/**
	 * Request lifetime in milliseconds.
	 */
	private final long lifetime;
	/**
	 * Future for cleanup task.
	 */
	private volatile ScheduledFuture<?> cleanup;

	/**
	 * Create no-response cleanup observer.
	 * 
	 * @param exchange exchange for no-response request
	 * @param scheduledExecutor scheduler for time based cleanup
	 * @param lifetime lifetime in milliseconds.
	 */
	public NoResponseCleanupMessageObserver(Exchange exchange, ScheduledExecutorService scheduledExecutor,
			long lifetime) {
		super(exchange);
		this.scheduledExecutor = scheduledExecutor;
		this.lifetime = lifetime;
		LOGGER.debug("no-response observer");
	}

	@Override
	public void onSent(boolean retransmission) {
		LOGGER.debug("no-response sent");
		if (!retransmission) {
			cleanup = scheduledExecutor.schedule(new Runnable() {
	
				@Override
				public void run() {
					exchange.execute(new Runnable() {
						@Override
						public void run() {
							LOGGER.debug("no-response-timeout");
							exchange.getRequest().setTimedOut(true);
						}
					});
				}
			}, lifetime, TimeUnit.MILLISECONDS);
		}
	}

	@Override
	protected void complete(final String action) {
		ScheduledFuture<?> cleanup = this.cleanup;
		if (cleanup != null) {
			cleanup.cancel(false);
		}
		super.complete(action);
	}
}
