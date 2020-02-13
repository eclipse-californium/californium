/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add waitForCondition
 *    Achim Kraus (Bosch Software Innovations GmbH) - add inRange
 ******************************************************************************/
package org.eclipse.californium;

import static org.junit.Assert.assertThat;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageObserver;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.elements.util.CounterStatisticManager;
import org.hamcrest.Description;
import org.hamcrest.Matcher;

/**
 * A collection of utility methods for implementing tests.
 */
public final class TestTools {

	public static final String URI_SEPARATOR = "/";
	private static final Random RAND = new Random();
	private static final String URI_TEMPLATE = "coap://%s:%d%s";
	public static final InetSocketAddress LOCALHOST_EPHEMERAL = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);

	private TestTools() {
		// prevent instantiation
	}

	/**
	 * Normalize relative URI path.
	 * 
	 * The values {@code null}, {@code ""}, or {@value #URI_SEPARATOR} are
	 * normalized to {@code null}. For all other values, the returned value is
	 * normalized to start with {@value #URI_SEPARATOR}.
	 * 
	 * @param relativePath path to be normalized
	 * @return normalized path
	 */
	public static String normalizeRelativePath(final String relativePath) {
		if (relativePath != null && !relativePath.isEmpty() && !relativePath.equals(URI_SEPARATOR)) {
			if (relativePath.startsWith(URI_SEPARATOR)) {
				return relativePath;
			} else {
				return URI_SEPARATOR + relativePath;
			}
		} else {
			return "";
		}
	}

	/**
	 * Creates a URI string for a resource hosted on an endpoint.
	 * 
	 * @param endpoint The endpoint the resource is hosted on.
	 * @param path The path of the resource on the endpoint. The value is
	 *            {@link #normalizeRelativePath(String)}.
	 * @return The URI string.
	 */
	public static String getUri(final Endpoint endpoint, final String path) {
		URI uri = endpoint.getUri();
		String resourcePath = normalizeRelativePath(path);
		if (!resourcePath.isEmpty()) {
			try {
				uri = new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(), uri.getPort(),
						uri.getPath() + resourcePath, uri.getQuery(), uri.getFragment());
			} catch (URISyntaxException e) {
			}
		}
		return uri.toASCIIString();
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
		String resourcePath = normalizeRelativePath(path);
		return String.format(URI_TEMPLATE, address.getHostString(), address.getPort(), resourcePath);
	}

	/**
	 * Creates a URI string for a resource hosted on an endpoint.
	 * 
	 * @param address The address of the endpoint that the resource is hosted
	 *            on.
	 * @param port The port of the endpoint that the resource is hosted on.
	 * @param path The path of the resource on the endpoint.
	 * @return The URI string.
	 */
	public static String getUri(final InetAddress address, final int port, final String path) {
		String resourcePath = normalizeRelativePath(path);
		return String.format(URI_TEMPLATE, address.getHostAddress(), port, resourcePath);
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
	 * Remove all observer of the provided type from the message.
	 * 
	 * Cleanup for retransmitted messages.
	 * 
	 * @param message message to remove observer
	 * @param clz type of observer to remove.
	 */
	public static void removeMessageObservers(Message message, Class<?> clz) {
		List<MessageObserver> list = message.getMessageObservers();
		for (MessageObserver observer : list) {
			if (clz.isInstance(observer)) {
				message.removeMessageObserver(observer);
			}
		}
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
	 * Get in range matcher.
	 * 
	 * @param <T> type of values.
	 * @param min inclusive minimum value
	 * @param max exclusive maximum value
	 * @return matcher.
	 */
	public static <T extends Number> org.hamcrest.Matcher<T> inRange(T min, T max) {
		return new InRange<T>(min, max);
	}

	/**
	 * In range matcher.
	 * 
	 * @see TestTools#inRange(Number, Number)
	 */
	private static class InRange<T extends Number> extends org.hamcrest.BaseMatcher<T> {

		private final Number min;
		private final Number max;

		private InRange(Number min, Number max) {
			this.min = min;
			this.max = max;
		}

		@Override
		public boolean matches(Object item) {
			if (!min.getClass().equals(item.getClass())) {
				throw new IllegalArgumentException("value type " + item.getClass().getSimpleName()
						+ " doesn't match range type " + min.getClass().getSimpleName());
			}
			Number value = (Number) item;
			if (item instanceof Float || item instanceof Double) {
				return min.doubleValue() <= value.doubleValue() && value.doubleValue() < max.doubleValue();
			} else {
				return min.longValue() <= value.longValue() && value.longValue() < max.longValue();
			}
		}

		@Override
		public void describeTo(Description description) {
			description.appendText("range[");
			description.appendText(min.toString());
			description.appendText("-");
			description.appendText(max.toString());
			description.appendText(")");
		}
	}

	public static void assertCounter(final CounterStatisticManager manager, final String name,
			final Matcher<? super Long> matcher, long timeout) throws InterruptedException {
		if (timeout > 0) {
			TestTools.waitForCondition(timeout, timeout / 10l, TimeUnit.MILLISECONDS, new CheckCondition() {

				@Override
				public boolean isFulFilled() throws IllegalStateException {
					return matcher.matches(manager.getCounter(name));
				}
			});
		}
		assertThat(name, manager.getCounter(name), matcher);
	}

	public static void assertCounter(CounterStatisticManager manager, String name,
			Matcher<? super Long> matcher) {
		assertThat(name, manager.getCounter(name), matcher);
	}
}
