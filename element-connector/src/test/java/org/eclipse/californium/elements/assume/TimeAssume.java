/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - use system property to enable it
 ******************************************************************************/
package org.eclipse.californium.elements.assume;

import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.rule.TestTimeRule;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.StringDescription;
import org.junit.AssumptionViolatedException;

/**
 * Implements timing assumptions.
 * 
 * So test are timing related and may fail, if the executing host is too slow.
 * This converts such failure into assumptions and ignore them.
 */
public class TimeAssume {

	/**
	 * Shift time in {@link ClockUtil} instead of real sleeps.
	 * 
	 * @since 3.0
	 */
	private final TestTimeRule timeRule;

	/**
	 * Enable in time assumption.
	 * 
	 * @see system property
	 *      "org.eclipse.californium.elements.assume.TimeAssume.enable".
	 */
	private boolean enabled;

	/**
	 * Estimated end time.
	 */
	private long end;

	/**
	 * Create new timing assumption.
	 * 
	 * @param timeRule to shift time instead of real sleep.
	 * @since 3.0
	 */
	public TimeAssume(TestTimeRule timeRule) {
		enabled = Boolean.getBoolean(TimeAssume.class.getName() + ".enable");
		this.timeRule = timeRule;
	}

	/**
	 * Create new timing assumption.
	 */
	public TimeAssume() {
		this(null);
	}

	/**
	 * Create new timing assumption with initial timeout.
	 * 
	 * @param timeout initial timeout in milliseconds
	 * @throws IllegalArgumentException if timeout is not larger than 0
	 */
	public TimeAssume(long timeout) {
		this(null, timeout);
	}

	/**
	 * Create new timing assumption with initial timeout.
	 * 
	 * @param timeRule to shift time instead of real sleep.
	 * @param timeout initial timeout in milliseconds
	 * @throws IllegalArgumentException if timeout is not larger than 0
	 * @since 3.0
	 */
	public TimeAssume(TestTimeRule timeRule, long timeout) {
		this(timeRule);
		if (timeout <= 0) {
			throw new IllegalArgumentException("timeout must be larger than 0!");
		}
		if (enabled) {
			end = ClockUtil.nanoRealtime() + TimeUnit.MILLISECONDS.toNanos(timeout);
		}
	}

	/**
	 * Sleep for provided milliseconds.
	 * 
	 * Check the actual times using a tolerance of 10% and use the 10% as
	 * timeout for the assumption.
	 * 
	 * @param milliseconds time to sleep in milliseconds.
	 * @throws AssumptionViolatedException if sleep is shorter or longer than
	 *             the provided time.
	 * @throws IllegalArgumentException if milliseconds is not larger than 0
	 */
	public void sleep(long milliseconds) {
		sleep(milliseconds, milliseconds / 10);
	}

	/**
	 * Sleep for provided milliseconds and setup time assumption with timeout.
	 * 
	 * Check the actual times using a tolerance of 10%.
	 * 
	 * @param milliseconds time to sleep in milliseconds.
	 * @param timeout timeout of assumption in milliseconds.
	 * @throws AssumptionViolatedException if sleep is shorter or longer than
	 *             the provided time.
	 * @throws IllegalArgumentException if one of the arguments is not larger
	 *             than 0
	 */
	public void sleep(long milliseconds, long timeout) {
		if (milliseconds <= 0) {
			throw new IllegalArgumentException("sleep milliseconds must be larger than 0!");
		}
		if (timeout <= 0) {
			throw new IllegalArgumentException("timeout must be larger than 0!");
		}
		long start = ClockUtil.nanoRealtime();
		if (timeRule != null) {
			timeRule.addTestTimeShift(milliseconds, TimeUnit.MILLISECONDS);
		} else {
			try {
				Thread.sleep(milliseconds);
			} catch (InterruptedException e) {
			}
		}
		long tolerance = milliseconds / 10;
		long now = ClockUtil.nanoRealtime();
		long time = TimeUnit.NANOSECONDS.toMillis(now - start);
		if (time < (milliseconds - tolerance)) {
			throw new AssumptionViolatedException("sleep too short! " + time + " instead of " + milliseconds + " ms");
		} else if ((milliseconds + timeout) < time) {
			throw new AssumptionViolatedException("sleep too long! " + time + " instead of " + milliseconds + " ms");
		}
		end = start + TimeUnit.MILLISECONDS.toNanos(milliseconds + timeout);
	}

	/**
	 * Check, if the actual execution time is still within the tolerance of the
	 * last {@link #sleep(long)}.
	 * 
	 * @return {@code true}, if the actual execution time is still within the
	 *         assumption, {@code true}, false, if not.
	 */
	public boolean inTime() {
		return !enabled || 0 == end || ClockUtil.nanoRealtime() <= end;
	}

	/**
	 * Create a generic matcher, which checks the actual execution time on
	 * failures. If that time violates that assumption of the last
	 * {@link #sleep(long)}, it ignores the test using an
	 * AssumptionViolatedException.
	 * 
	 * @param matcher actual matcher
	 * @return matcher taking the actual execution time into account when
	 *         provided actual matcher fails.
	 * @throws AssumptionViolatedException if the provided actual matcher fails
	 *             and the actual execution time is out of the assumption of the
	 *             last {@link #sleep(long)}.
	 */
	public <T> Matcher<T> inTime(final Matcher<T> matcher) {
		return new BaseMatcher<T>() {

			@Override
			public void describeTo(Description description) {
				matcher.describeTo(description);
			}

			@Override
			public boolean matches(Object item) {
				boolean result = matcher.matches(item);
				if (!result) {
					if (!inTime()) {
						StringDescription description = new StringDescription();
						description.appendText("expected: ");
						matcher.describeTo(description);
						description.appendText(StringUtil.lineSeparator());
						description.appendText("actual: ");
						describeMismatch(item, description);
						description.appendText(", assumed time expired!");
						throw new AssumptionViolatedException(description.toString());
					}
				}
				return result;
			}

			@Override
			public void describeMismatch(Object item, Description mismatchDescription) {
				matcher.describeMismatch(item, mismatchDescription);
				if (!enabled && 0 < end) {
					long left = end - ClockUtil.nanoRealtime();
					if (left < 0) {
						mismatchDescription.appendText(", assumed time expired! ");
						mismatchDescription.appendText(Long.toString(TimeUnit.NANOSECONDS.toMillis(-left)));
						mismatchDescription.appendText("ms");
					}
				}
			}
		};
	}

}
