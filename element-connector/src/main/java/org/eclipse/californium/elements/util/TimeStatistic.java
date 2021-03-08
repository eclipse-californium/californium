/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.util.Statistic.Scale;
import org.eclipse.californium.elements.util.Statistic.Summary;

/**
 * Time statistic.
 * 
 * Implemented using a table of counters for time-slots.
 * 
 * @since 3.0
 */
public class TimeStatistic {

	private static final Scale NANOS_TO_MILLIS = new Scale() {

		@Override
		public long scale(long value) {
			return TimeUnit.NANOSECONDS.toMillis(value);
		}
	};

	/**
	 * Statistic of nano-seconds.
	 */
	private final Statistic statistic;

	/**
	 * Create time statistic.
	 * 
	 * @param timeRange overall range.
	 * @param timeSlot time slot width
	 * @param unit time unit for the both other time values
	 */
	public TimeStatistic(long timeRange, long timeSlot, TimeUnit unit) {
		long range = unit.toNanos(timeRange);
		long slot = unit.toNanos(timeSlot);
		statistic = new Statistic(range, slot);
	}

	/**
	 * Add time to statistic.
	 * 
	 * @param time time
	 * @param unit time unit
	 */
	public void add(long time, TimeUnit unit) {
		if (time >= 0) {
			long nanos = unit.toNanos(time);
			statistic.add(nanos);
		}
	}

	/**
	 * Checks, if values are available for this statistic.
	 * 
	 * @return {@code true}, if values are available, {@code false}, otherwise.
	 */
	public boolean available() {
		return statistic.available();
	}

	/**
	 * Get summary of statistic.
	 * 
	 * Include {@code 95%}, {@code 99%}, and {@code 99.9%} percentiles. The
	 * values are normalized to milliseconds.
	 * 
	 * @return summary as text
	 */
	public String getSummaryAsText() {
		return getSummary(950, 990, 999).toString(" ms");
	}

	/**
	 * Get summary of statistic.
	 * 
	 * The values are normalized to milliseconds.
	 * 
	 * @param percentiles per mill percentiles, e.g. {@code 990} for
	 *            {@code 99%}. If no percentiles are provided, only the average
	 *            and the maximum is included in the summary.
	 * @return summary
	 */
	public Summary getSummary(int... percentiles) {
		return new Summary(statistic.getSummary(percentiles), NANOS_TO_MILLIS);
	}
}
