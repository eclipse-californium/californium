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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.concurrent.TimeUnit;

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
	 * <p>
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
	 * Assert condition to come {@code true}.
	 * <p>
	 * Used for none notifying conditions, which must be polled.
	 * 
	 * @param timeout timeout in {@code unit}
	 * @param interval interval of condition check in {@code unit}
	 * @param unit time units for {@code timeout} and {@code interval}
	 * @param check callback for condition test
	 * @throws InterruptedException if the Thread is interrupted.
	 * @throws AssertionError if assertion has failed
	 * @since 4.0
	 */
	public static void assertCondition(long timeout, long interval, TimeUnit unit, TestCondition check)
			throws InterruptedException {
		assertThat(waitForCondition(timeout, interval, unit, check), is(true));
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
	 * @throws AssertionError if assertion has failed
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
	 * @throws AssertionError if assertion has failed
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
	 * @throws AssertionError if assertion has failed
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
	 * @throws AssertionError if assertion has failed
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
