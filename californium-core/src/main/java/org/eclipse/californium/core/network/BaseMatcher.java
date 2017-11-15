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
 *    Bosch Software Innovations - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - make exchangeStore final
 ******************************************************************************/
package org.eclipse.californium.core.network;

import org.eclipse.californium.core.network.config.NetworkConfig;

/**
 * A base class for implementing Matchers that provides support for using a
 * {@code MessageExchangeStore}.
 */
public abstract class BaseMatcher implements Matcher {

	protected final NetworkConfig config;
	protected final MessageExchangeStore exchangeStore;
	protected boolean running = false;

	/**
	 * Creates a new matcher based on configuration values.
	 * 
	 * @param config the configuration to use.
	 * @param exchangeStore the exchange store to use for keeping track of
	 *            message exchanges with endpoints.
	 * @throws NullPointerException if the configuration,
	 *             or the exchange store is {@code null}.
	 */
	public BaseMatcher(final NetworkConfig config, final MessageExchangeStore exchangeStore) {
		if (config == null) {
			throw new NullPointerException("Config must not be null");
		} else if (exchangeStore == null) {
			throw new NullPointerException("ExchangeStore must not be null");
		} else {
			this.config = config;
			this.exchangeStore = exchangeStore;
		}
	}

	@Override
	public synchronized void start() {
		if (!running) {
			exchangeStore.start();
			running = true;
		}
	}

	@Override
	public synchronized void stop() {
		if (running) {
			exchangeStore.stop();
			clear();
			running = false;
		}
	}

	/**
	 * This method does nothing.
	 * <p>
	 * Subclasses should override this method in order to clear any internal
	 * state.
	 */
	@Override
	public void clear() {
	}
}
