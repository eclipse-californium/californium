/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.rule;

import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.util.ClockUtil;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Rule to adjust the test time nanoseconds.
 * 
 * Only affects {@link ClockUtil#nanoRealtime()}, but not
 * {@link java.util.concurrent.ScheduledExecutorService} nor
 * {@link Thread#wait()}.
 */
public class TestTimeRule extends TestWatcher {

	public static final Logger LOGGER = LoggerFactory.getLogger(TestTimeRule.class);

	/**
	 * Realtime handler applying the {@link #timeShiftNanos}.
	 */
	private final ClockUtil.Realtime handler = new ClockUtil.Realtime() {

		@Override
		public long nanoRealtime() {
			long shift;
			Long fixed;
			synchronized (TestTimeRule.this) {
				shift = timeShiftNanos;
				fixed = timeFixed;
			}
			if (fixed != null) {
				return fixed + shift;
			} else {
				return System.nanoTime() + shift;
			}
		}
	};

	/**
	 * Current test time shift in nanoseconds.
	 * 
	 * @see #addTestTimeShift(long, TimeUnit)
	 * @see #setTestTimeShift(long, TimeUnit)
	 * @see #getTestTimeShiftNanos()
	 */
	private long timeShiftNanos;

	/**
	 * Fix test time.
	 * 
	 * @see #setFixedTestTime(boolean)
	 * @since 3.0
	 */
	private Long timeFixed;

	/**
	 * Set fixed test time.
	 * 
	 * If enabled, fixes the time of {@link ClockUtil} except the modifications
	 * applied by {@link #addTestTimeShift(long, TimeUnit)} or
	 * {@link #setTestTimeShift(long, TimeUnit)}.
	 * 
	 * @param enable {@code true} to fix the {@link ClockUtil} time,
	 *            {@code false}, to release it.
	 * @since 3.0
	 */
	public final synchronized void setFixedTestTime(boolean enable) {
		LOGGER.debug("set fixed test time {}", enable);
		if (enable) {
			timeFixed = System.nanoTime();
		} else {
			timeFixed = null;
		}
	}

	/**
	 * Add provided time to {@link #timeShiftNanos}.
	 * 
	 * @param delta time to add
	 * @param unit unit of time to add
	 */
	public final synchronized void addTestTimeShift(final long delta, final TimeUnit unit) {
		LOGGER.debug("add {} {} to timeshift {} ns", delta, unit, timeShiftNanos);
		timeShiftNanos += unit.toNanos(delta);
	}

	/**
	 * Set time shift.
	 * 
	 * @param shift time shift
	 * @param unit unit of time shift
	 */
	public final synchronized void setTestTimeShift(final long shift, final TimeUnit unit) {
		LOGGER.debug("set {} {} as timeshift", shift, unit);
		timeShiftNanos = unit.toNanos(shift);
	}

	/**
	 * Gets current time shift in nanoseconds.
	 * 
	 * @return time shift in nanoseconds
	 */
	public final synchronized long getTestTimeShiftNanos() {
		return timeShiftNanos;
	}

	@Override
	protected void starting(Description description) {
		ClockUtil.setRealtimeHandler(handler);
	}

	@Override
	protected void finished(Description description) {
		if (getTestTimeShiftNanos() != 0) {
			setTestTimeShift(0, TimeUnit.NANOSECONDS);
		}
	}
}
