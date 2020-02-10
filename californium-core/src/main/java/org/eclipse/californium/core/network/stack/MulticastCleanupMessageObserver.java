/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 *                                      extracted from ExchangeCleanupLayer
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
 * Cleanup multicast exchange by time to enable request for multiple responses.
 */
@NoPublicAPI
public class MulticastCleanupMessageObserver extends CleanupMessageObserver {

	static final Logger LOGGER = LoggerFactory.getLogger(MulticastCleanupMessageObserver.class);

	/**
	 * Scheduler for time based exchange completion.
	 */
	private final ScheduledExecutorService scheduledExecutor;
	/**
	 * Multicast lifetime in milliseconds.
	 */
	private final long multicastLifetime;
	/**
	 * Future for cleanup task.
	 */
	private volatile ScheduledFuture<?> cleanup;

	/**
	 * Create multicast cleanup observer.
	 * 
	 * @param exchange exchange for multicast request
	 * @param scheduledExecutor scheduler for time based cleanup
	 * @param multicastLifetime multicast lifetime in milliseconds.
	 */
	public MulticastCleanupMessageObserver(Exchange exchange, ScheduledExecutorService scheduledExecutor,
			long multicastLifetime) {
		super(exchange);
		this.scheduledExecutor = scheduledExecutor;
		this.multicastLifetime = multicastLifetime;
	}

	@Override
	public void onSent(boolean retransmission) {
		cleanup = scheduledExecutor.schedule(new Runnable() {

			@Override
			public void run() {
				exchange.execute(new Runnable() {
					@Override
					public void run() {
						if (exchange.getResponse() == null) {
							exchange.getRequest().setCanceled(true);
						} else {
							exchange.setComplete();
							exchange.getRequest().onComplete();
						}
					}
				});
			}
		}, multicastLifetime, TimeUnit.MILLISECONDS);
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
