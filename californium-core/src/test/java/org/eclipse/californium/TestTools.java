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
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.network.Endpoint;

/**
 * A collection of utility methods for implementing tests.
 */
public final class TestTools {

	private static final Random RAND = new Random();
	private static final String URI_TEMPLATE = "coap://%s:%d/%s";

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
	 * @param address The address of the endpoint that the resource is hosted on.
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
}
