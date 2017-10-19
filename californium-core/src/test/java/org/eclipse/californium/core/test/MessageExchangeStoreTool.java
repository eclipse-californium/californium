/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - reduce external dependency
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.junit.Assert.assertTrue;

import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.CheckCondition;
import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.network.InMemoryMessageExchangeStore;
import org.eclipse.californium.core.network.MessageExchangeStore;
import org.eclipse.californium.core.network.config.NetworkConfig;

/**
 * Test tools for MessageExchangeStore.
 * 
 * Dumps exchanges, if MessageExchangeStore is not finally empty.
 */
public class MessageExchangeStoreTool {

	/**
	 * Logger used to adjust log-level to dump exchanges, if not empty.
	 */
	private static final Logger STORE_LOGGER = Logger.getLogger(InMemoryMessageExchangeStore.class.getName());

	/**
	 * Assert, that all exchanges in both stores are empty.
	 * 
	 * dump exchanges, if not empty.
	 * 
	 * @param config used network configuration.
	 * @param clientExchangeStore client message exchange store.
	 * @param serverExchangeStore server message exchange store.
	 */
	public static void assertAllExchangesAreCompleted(NetworkConfig config,
			final MessageExchangeStore clientExchangeStore, final MessageExchangeStore serverExchangeStore) {
		int exchangeLifetime = (int) config.getLong(NetworkConfig.Keys.EXCHANGE_LIFETIME);
		int sweepInterval = config.getInt(NetworkConfig.Keys.MARK_AND_SWEEP_INTERVAL);
		Level level = STORE_LOGGER.getLevel();
		try {
			waitUntilDeduplicatorShouldBeEmpty(exchangeLifetime, sweepInterval, new CheckCondition() {

				@Override
				public boolean isFulFilled() throws IllegalStateException {
					return clientExchangeStore.isEmpty() && serverExchangeStore.isEmpty();
				}
			});
			STORE_LOGGER.setLevel(Level.FINEST);
			assertTrue("Client side message exchange store still contains exchanges", clientExchangeStore.isEmpty());
			assertTrue("Server side message exchange store still contains exchanges", serverExchangeStore.isEmpty());
		} finally {
			STORE_LOGGER.setLevel(level);
		}
	}

	/**
	 * Assert, that all exchanges in store are empty.
	 * 
	 * dump exchanges, if not empty.
	 * 
	 * @param config used network configuration.
	 * @param exchangeStore message exchange store.
	 */
	public static void assertAllExchangesAreCompleted(NetworkConfig config, final MessageExchangeStore exchangeStore) {
		int exchangeLifetime = (int) config.getLong(NetworkConfig.Keys.EXCHANGE_LIFETIME);
		int sweepInterval = config.getInt(NetworkConfig.Keys.MARK_AND_SWEEP_INTERVAL);
		Level level = STORE_LOGGER.getLevel();
		try {
			waitUntilDeduplicatorShouldBeEmpty(exchangeLifetime, sweepInterval, new CheckCondition() {

				@Override
				public boolean isFulFilled() throws IllegalStateException {
					return exchangeStore.isEmpty();
				}
			});
			STORE_LOGGER.setLevel(Level.FINER);
			assertTrue("message exchange store still contains exchanges", exchangeStore.isEmpty());
		} finally {
			STORE_LOGGER.setLevel(level);
		}
	}
	
	public static void waitUntilDeduplicatorShouldBeEmpty(final int exchangeLifetime, final int sweepInterval, CheckCondition check) {
		try {
			int timeToWait = exchangeLifetime + sweepInterval + 300; // milliseconds
			System.out.println("Wait until deduplicator should be empty (" + timeToWait/1000f + " seconds)");
			TestTools.waitForCondition(timeToWait, timeToWait / 10, TimeUnit.MILLISECONDS, check);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

}
