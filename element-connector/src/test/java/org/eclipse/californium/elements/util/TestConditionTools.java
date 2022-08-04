/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 *                    Derived for californium-core TestTools
 ******************************************************************************/

package org.eclipse.californium.elements.util;

import static org.hamcrest.MatcherAssert.assertThat;

import java.util.concurrent.TimeUnit;

import org.hamcrest.Description;
import org.hamcrest.Matcher;

/**
 * A collection of utility methods for implementing tests.
 * 
 * @since 2.3
 */
public final class TestConditionTools {

	private TestConditionTools() {
		// prevent instantiation
	}

	/**
	 * Wait for condition to come {@code true}.
	 * 
	 * Used for none notifying conditions, which must be polled.
	 * 
	 * @param timeout timeout in {@code unit}
	 * @param interval interval of condition check in {@code unit}
	 * @param unit time units for {@code timeout} and {@code interval}
	 * @param check callback for condition test
	 * @return {@code true}, if the condition is fulfilled within timeout,
	 *         {@code false} otherwise.
	 * @throws InterruptedException if the Thread is interrupted.
	 */
	public static boolean waitForCondition(long timeout, long interval, TimeUnit unit, TestCondition check)
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
	 * @throws IllegalArgumentException if min is not less than max
	 */
	public static <T extends Number> org.hamcrest.Matcher<T> inRange(T min, T max) {
		return new InRange<T>(min, max);
	}

	/**
	 * In range matcher.
	 * 
	 * @see TestConditionTools#inRange(Number, Number)
	 */
	private static class InRange<T extends Number> extends org.hamcrest.BaseMatcher<T> {

		private final Number min;
		private final Number max;

		private InRange(Number min, Number max) {
			if (min instanceof Float || min instanceof Double) {
				if (min.doubleValue() >= max.doubleValue()) {
					throw new IllegalArgumentException("Min " + min + " must be less than max " + max + "!");
				}
			} else {
				if (min.longValue() >= max.longValue()) {
					throw new IllegalArgumentException("Min " + min + " must be less than max " + max + "!");
				}
			}
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

	/**
	 * Assert, that a statistic counter reaches the matcher's criterias within
	 * the provided timeout.
	 * 
	 * @param manager statistic manager
	 * @param name name of statistic.
	 * @param matcher matcher for statistic counter value
	 * @param timeout timeout to match
	 * @param unit unit of timeout
	 * @throws InterruptedException if wait is interrupted.
	 * @see TestConditionTools#assertStatisticCounter(CounterStatisticManager,
	 *      String, Matcher)
	 */
	public static void assertStatisticCounter(final CounterStatisticManager manager, final String name,
			final Matcher<? super Long> matcher, long timeout, TimeUnit unit) throws InterruptedException {
		if (timeout > 0) {
			long timeoutMillis = unit.toMillis(timeout);
			waitForCondition(timeoutMillis, timeoutMillis / 10l, TimeUnit.MILLISECONDS, new TestCondition() {

				@Override
				public boolean isFulFilled() throws IllegalStateException {
					return matcher.matches(manager.getCounterByKey(name));
				}
			});
		}
		assertThat(prepareMessage(null, name, manager), manager.getCounterByKey(name), matcher);
	}

	/**
	 * Assert, that a statistic counter reaches the matcher's criteria within
	 * the provided timeout.
	 * 
	 * @param message message prepended to name
	 * @param manager statistic manager
	 * @param name name of statistic.
	 * @param matcher matcher for statistic counter value
	 * @param timeout timeout to match
	 * @param unit unit of timeout
	 * @throws InterruptedException if wait is interrupted.
	 * @see TestConditionTools#assertStatisticCounter(CounterStatisticManager,
	 *      String, Matcher)
	 * @since 2.4
	 */
	public static void assertStatisticCounter(String message, final CounterStatisticManager manager, final String name,
			final Matcher<? super Long> matcher, long timeout, TimeUnit unit) throws InterruptedException {
		if (timeout > 0) {
			long timeoutMillis = unit.toMillis(timeout);
			waitForCondition(timeoutMillis, timeoutMillis / 10l, TimeUnit.MILLISECONDS, new TestCondition() {

				@Override
				public boolean isFulFilled() throws IllegalStateException {
					return matcher.matches(manager.getCounterByKey(name));
				}
			});
		}
		assertThat(prepareMessage(message, name, manager), manager.getCounterByKey(name), matcher);
	}

	/**
	 * Assert, that a statistic counter matches the provided criteria.
	 * 
	 * @param manager statistic manager
	 * @param name name of statistic.
	 * @param matcher matcher for statistic counter value
	 */
	public static void assertStatisticCounter(CounterStatisticManager manager, String name,
			Matcher<? super Long> matcher) {
		assertThat(prepareMessage(null, name, manager), manager.getCounterByKey(name), matcher);
	}

	/**
	 * Assert, that a statistic counter matches the provided criteria.
	 * 
	 * @param message message prepended to name
	 * @param manager statistic manager
	 * @param name name of statistic.
	 * @param matcher matcher for statistic counter value
	 * @since 2.4
	 */
	public static void assertStatisticCounter(String message, CounterStatisticManager manager, String name,
			Matcher<? super Long> matcher) {
		assertThat(prepareMessage(message, name, manager), manager.getCounterByKey(name), matcher);
	}

	/**
	 * Prepare assert message.
	 * 
	 * @param message passed in message
	 * @param name name of statistic
	 * @param manager statistic manager
	 * @return prepared message with format "[message-][tag-]name".
	 * @since 2.5
	 */
	private static String prepareMessage(String message, String name, CounterStatisticManager manager) {
		StringBuilder builder = new StringBuilder();
		if (message != null && !message.isEmpty()) {
			builder.append(message).append("-");
		}
		String tag = manager.getTag().trim();
		if (tag != null && !tag.isEmpty() && !tag.equals(message)) {
			builder.append(tag).append("-");
		}
		builder.append(name);
		return builder.toString();
	}
}
