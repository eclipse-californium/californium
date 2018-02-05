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
 * Intended to be used by overriding {@link #runStriped()}.
 */
public abstract class StripedExchangeJob implements StripedRunnable {

	private static final Logger LOGGER = LoggerFactory.getLogger(StripedExchangeJob.class.getCanonicalName());

	/**
	 * Exchange for this job.
	 */
	protected final Exchange exchange;

	public StripedExchangeJob(Exchange exchange) {
		this.exchange = exchange;
	}

	public StripedExchangeJob(StripedExchangeJob job) {
		this.exchange = job.exchange;
	}

	@Override
	public Object getStripe() {
		return exchange;
	}

	@Override
	public void run() {
		try {
			runStriped();
		} catch (Throwable t) {
			LOGGER.error("striped exception in protocol stage thread: {}", t.getMessage(), t);
		}
	}

	public abstract void runStriped();
}
