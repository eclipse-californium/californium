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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add waitForCondition
 ******************************************************************************/
package org.eclipse.californium;

import java.net.InetSocketAddress;
import java.util.Map.Entry;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.InMemoryMessageExchangeStore;

/**
 * A collection of utility methods for implementing tests.
 */
public final class TestTools {

	private static final Random RAND = new Random();
	private static final String URI_TEMPLATE = "coap://%s:%d/%s";
	private static final Logger LOGGER = Logger.getLogger(TestTools.class.getName());

	private TestTools() {
		// prevent instantiation
	}

	/**
	 * Creates a URI string for a resource hosted on an endpoint.
	 * 
	 * @param endpoint The endpoint the resource is hosted on.
	 * @param path The path of the resource on the endpoint.
	 * @return The URI string.
	 */
	public static String getUri(final Endpoint endpoint, final String path) {
		return getUri(endpoint.getAddress(), path);
	}

	/**
	 * Creates a URI string for a resource hosted on an endpoint.
	 * 
	 * @param address The address of the endpoint that the resource is hosted
	 *            on.
	 * @param path The path of the resource on the endpoint.
	 * @return The URI string.
	 */
	public static String getUri(final InetSocketAddress address, final String path) {
		return String.format(URI_TEMPLATE, address.getHostString(), address.getPort(), path);
	}

	/**
	 * Creates a string of random single digit numbers of a given length.
	 * 
	 * @param length The length of the string to create.
	 * @return The string.
	 */
	public static String generateRandomPayload(final int length) {
		StringBuilder buffer = new StringBuilder();
		int counter = 0;
		while (counter < length) {
			buffer.append(Integer.toString(RAND.nextInt(10)));
			counter++;
		}
		return buffer.toString();
	}

	/**
	 * Creates a string of ascending single digit numbers of a given length.
	 * 
	 * @param length The length of the string to create.
	 * @return The string.
	 */
	public static String generatePayload(final int length) {
		StringBuilder buffer = new StringBuilder();
		int n = 0;
		while (buffer.length() < length) {
			buffer.append(Integer.toString(n % 10));
			n++;
		}
		return buffer.toString();
	}

	/**
	 * Wait for condition to come {@code true}.
	 * 
	 * Used for none notifying conditions, which must be polled.
	 * 
	 * @param timeout timeout in {@code unit}
	 * @param interval interval of condition check in {@code unit}
	 * @param unit time units for {@code timeout} and {@code interval}
	 * @param check callback for condition check
	 * @return {@code true}, if the condition is fulfilled within timeout,
	 *         {@code false} otherwise.
	 * @throws InterruptedException if the Thread is interrupted.
	 */
	public static boolean waitForCondition(long timeout, long interval, TimeUnit unit, CheckCondition check)
			throws InterruptedException {
		if (0 >= timeout) {
			throw new IllegalArgumentException("timeout must be greather than 0!");
		}
		if (0 >= interval || timeout < interval) {
			throw new IllegalArgumentException("interval must be greather than 0, and not greather than timeout!");
		}
		if (null == check) {
			throw new NullPointerException("check must be provided!");
		}
		long leftTimeInMilliseconds = unit.toMillis(timeout);
		long sleepTimeInMilliseconds = unit.toMillis(interval);
		long end = System.nanoTime() + unit.toNanos(timeout);
		while (0 < leftTimeInMilliseconds) {
			if (check.isFulFilled()) {
				return true;
			}
			Thread.sleep(sleepTimeInMilliseconds);
			leftTimeInMilliseconds = TimeUnit.NANOSECONDS.toMillis(end - System.nanoTime());
			if (sleepTimeInMilliseconds > leftTimeInMilliseconds) {
				sleepTimeInMilliseconds = leftTimeInMilliseconds;
			}
		}
		return check.isFulFilled();
	}

	/**
	 * Check if InMemoryExchangeStore is empty and dump partial content. Display
	 * maximum 3 exchanges in the dump. Log level used is WARNING.
	 * 
	 * @param store the exchange store to check
	 */
	public static boolean isEmptyWithDump(InMemoryMessageExchangeStore store) {
		return isEmptyWithDump(store, LOGGER, Level.WARNING, 3);
	}

	/**
	 * Check if InMemoryExchangeStore is empty and dump partial content.
	 * 
	 * @param store the exchange store to check
	 * @param logger logger used to log dump
	 * @param logLevel log level for dump
	 * @param logMaxExchanges maximum number of exchanges to include in dump.
	 */
	public static boolean isEmptyWithDump(InMemoryMessageExchangeStore store, Logger logger, Level logLevel,
			int logMaxExchanges) {
		if (store.isEmpty()) {
			return true;
		} else {
			dumpInMemoryExchangeStore(store, logger, logLevel, logMaxExchanges);
			return false;
		}
	}

	/**
	 * Dump exchanges of maps from InMemoryExchangeStore.
	 * 
	 * @param logger logger used to log dump
	 * @param logLevel log level for dump
	 * @param logMaxExchanges maximum number of exchanges to include in dump.
	 */
	public static void dumpInMemoryExchangeStore(InMemoryMessageExchangeStore store, Logger logger, Level logLevel,
			int logMaxExchanges) {
		if (logger.isLoggable(logLevel)) {
			logger.log(logLevel, store.toString());
			if (0 < logMaxExchanges) {
				if (!store.getExchangesByMID().isEmpty()) {
					dumpExchanges(logger, logLevel, logMaxExchanges, store.getExchangesByMID().entrySet());
				}
				if (!store.getExchangesByToken().isEmpty()) {
					dumpExchanges(logger, logLevel, logMaxExchanges, store.getExchangesByToken().entrySet());
				}
			}
		}
	}

	/**
	 * Dump collection of exchange entries.
	 * 
	 * @param logger logger used to log dump
	 * @param logLevel log level for dump
	 * @param logMaxExchanges maximum number of exchanges to include in dump.
	 * @param exchangeEntries collection with exchanges entries
	 */
	public static <K> void dumpExchanges(Logger logger, Level logLevel, int logMaxExchanges,
			Set<Entry<K, Exchange>> exchangeEntries) {
		for (Entry<K, Exchange> exchangeEntry : exchangeEntries) {
			Exchange exchange = exchangeEntry.getValue();
			logger.log(logLevel, "  {0}, {1}, {2}", new Object[] { exchangeEntry.getKey(), exchange.getCurrentRequest(),
					exchange.getCurrentResponse() });
			if (0 >= --logMaxExchanges) {
				break;
			}
		}
	}
}
