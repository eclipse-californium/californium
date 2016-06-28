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
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.network.config.NetworkConfig;

/**
 * A base class for implementing Matchers that provides support for
 * using a {@code MessageExchangeStore}.
 */
public abstract class BaseMatcher implements Matcher {

	private static final Logger LOG = Logger.getLogger(BaseMatcher.class.getName());
	protected final NetworkConfig config;
	protected boolean running = false;
	protected MessageExchangeStore exchangeStore;

	/**
	 * Creates a new matcher based on configuration values.
	 * 
	 * @param config the configuration to use.
	 */
	public BaseMatcher(final NetworkConfig config) {
		if (config == null) {
			throw new NullPointerException("Config must not be null");
		} else {
			this.config = config;
		}
	}

	@Override
	public synchronized final void setMessageExchangeStore(final MessageExchangeStore store) {
		if (running) {
			throw new IllegalStateException("MessageExchangeStore can only be set on stopped Matcher");
		} else if (store == null) {
			throw new NullPointerException("Message exchange store must not be null");
		} else {
			this.exchangeStore = store;
		}
	}

	protected final void assertMessageExchangeStoreIsSet() {
		if (exchangeStore == null) {
			LOG.log(Level.CONFIG, "no MessageExchangeStore set, using default {0}", InMemoryMessageExchangeStore.class.getName());
			exchangeStore = new InMemoryMessageExchangeStore(config);
		}
	}

	@Override
	public synchronized void start() {
		if (!running) {
			assertMessageExchangeStoreIsSet();
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
	 * Subclasses should override this method in order to clear any internal state.
	 */
	@Override
	public void clear() {
	}
}
