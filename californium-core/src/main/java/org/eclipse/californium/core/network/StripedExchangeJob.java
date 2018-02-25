/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.core.network;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.javaspecialists.tjsn.concurrency.stripedexecutor.StripedRunnable;

/**
 * Striped job using exchange as stripe object.
 * 
 * Intended to be used by overriding {@link #runStriped()} and passed as
 * parameter to {@link Exchange#execute(StripedExchangeJob)}.
 */
public abstract class StripedExchangeJob implements StripedRunnable {

	private static final Logger LOGGER = LoggerFactory.getLogger(StripedExchangeJob.class.getCanonicalName());

	/**
	 * Exchange for this job.
	 */
	protected final Exchange exchange;
	/**
	 * Creator of this job. Intended for debug logging.
	 */
	protected final Throwable caller;

	/**
	 * Create job for provided Exchange.
	 * 
	 * @param exchange exchange to access in {@link #runStriped()}.
	 */
	public StripedExchangeJob(Exchange exchange) {
		this.exchange = exchange;
		if (Exchange.DEBUG) {
			this.caller = new Throwable(exchange + " stripe caller");
		} else {
			this.caller = null;
		}
	}

	@Override
	public Object getStripe() {
		return exchange.getStripe();
	}

	@Override
	public void run() {
		try {
			exchange.setOwner();
			runStriped();
		} catch (Throwable t) {
			LOGGER.error("Exception in striped thread: {}", t.getMessage(), t);
			if (t.getCause() != null) {
				LOGGER.error("   Cause:", t.getCause());
			}
			if (caller != null) {
				LOGGER.error("   Caller:", caller);
			}
		} finally {
			exchange.clearOwner();
		}
	}

	/**
	 * Called in scope of striped exchange executor.
	 */
	public abstract void runStriped();
}
