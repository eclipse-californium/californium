/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 * {@link ScheduledExecutorService} nor {@link Thread#wait()}.
 */
public class TestTimeRule extends TestWatcher {

	public static final Logger LOGGER = LoggerFactory.getLogger(TestTimeRule.class.getName());

	/**
	 * Realtime handler applying the {@link #timeShiftNanos}.
	 */
	private final ClockUtil.Realtime handler = new ClockUtil.Realtime() {

		@Override
		public long nanoRealtime() {
			return System.nanoTime() + getTestTimeShiftNanos();
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
