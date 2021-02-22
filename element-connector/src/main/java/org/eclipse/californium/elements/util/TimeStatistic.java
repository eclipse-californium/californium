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

import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Time statistic.
 * 
 * Implemented using a table of counters for time-slots.
 * 
 * @since 3.0
 */
public class TimeStatistic {

	/**
	 * Time slot width in nano-seconds.
	 */
	private final long slotWidthNanos;
	/**
	 * Tables of counters. Time slot is defined by {@code index} and
	 * {@link #slotWidthNanos}.
	 */
	private final AtomicLong[] statistic;

	private final AtomicLong maximumTime = new AtomicLong();

	/**
	 * Create time statistic.
	 * 
	 * @param timeRange overall range.
	 * @param timeSlot time slot width
	 * @param unit time unit for the both other time values
	 */
	public TimeStatistic(long timeRange, long timeSlot, TimeUnit unit) {
		int size = (int) (timeRange / timeSlot) + 1;
		statistic = new AtomicLong[size];
		for (int index = 0; index < size; ++index) {
			statistic[index] = new AtomicLong();
		}
		slotWidthNanos = unit.toNanos(timeSlot);
	}

	/**
	 * Add time to statistic.
	 * 
	 * @param time time
	 * @param unit time unit
	 */
	public void add(long time, TimeUnit unit) {
		if (time >= 0) {
			long nanons = unit.toNanos(time);
			int index = (int) (nanons / slotWidthNanos);
			if (index < statistic.length) {
				statistic[index].incrementAndGet();
			} else {
				statistic[statistic.length - 1].incrementAndGet();
			}
			long value = maximumTime.get();
			while (nanons > value) {
				if (maximumTime.compareAndSet(value, nanons)) {
					break;
				}
				value = maximumTime.get();
			}
		}
	}

	/**
	 * Get upper limit of time slot.
	 * 
	 * @param index index of time slot.
	 * @return upper limit time of slot in milliseconds
	 */
	private long getMillis(int index) {
		return TimeUnit.NANOSECONDS.toMillis((index + 1) * slotWidthNanos);
	}

	/**
	 * Checks, if values are available for this statistic.
	 * 
	 * @return {@code true}, if values are available, {@code false}, otherwise.
	 */
	public boolean available() {
		for (int index = 0; index < statistic.length; ++index) {
			if (statistic[index].get() > 0) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Get summary of statistic.
	 * 
	 * Include {@code 95%}, {@code 99%}, and {@code 99.9%} percentiles.
	 * 
	 * @return summary as text
	 */
	public String getSummaryAsText() {
		return getSummary(950, 990, 999).toString();
	}

	/**
	 * Get summary of statistic.
	 * 
	 * @param percentiles per mill percentiles, e.g. {@code 990} for
	 *            {@code 99%}.
	 * @return summary
	 */
	public Summary getSummary(int... percentiles) {
		long sum = 0;
		long count = 0;
		for (int index = 0; index < statistic.length; ++index) {
			long hits = statistic[index].get();
			if (hits > 0) {
				count += hits;
				sum += hits * getMillis(index);
				if (sum < 0) {
					throw new IllegalStateException();
				}
			}
		}
		if (count > 0) {
			long max = TimeUnit.NANOSECONDS.toMillis(maximumTime.get());
			long[] times = null;
			if (percentiles != null && percentiles.length > 0) {
				Arrays.sort(percentiles);
				times = new long[percentiles.length];
				int linesIndex = percentiles.length - 1;
				if (percentiles[linesIndex] < 0 || percentiles[linesIndex] > 999) {
					throw new IllegalArgumentException("line " + percentiles[linesIndex] + " is not in [0...999]%%");
				}
				long line = count * (1000 - percentiles[linesIndex]) / 1000;
				long downCount = 0;
				for (int index = statistic.length - 1; index >= 0; --index) {
					long hits = statistic[index].get();
					if (hits > 0) {
						long next = downCount + hits;
						while (downCount <= line && next > line) {
							long time = getMillis(index);
							if (time > max) {
								time = max;
							}
							times[linesIndex] = time;
							--linesIndex;
							if (linesIndex >= 0) {
								if (percentiles[linesIndex] < 0 || percentiles[linesIndex] > 999) {
									throw new IllegalArgumentException(
											"line " + percentiles[linesIndex] + " is not in [0...999]%%");
								}
								line = count * (1000 - percentiles[linesIndex]) / 1000;
							} else {
								break;
							}
						}
						if (linesIndex < 0) {
							break;
						}
						downCount = next;
					}
				}
			}
			return new Summary((int) count, sum / count, max, percentiles, times);
		} else {
			return new Summary();
		}
	}

	public static class Summary {

		final int count;
		final long average;
		final long maximum;
		final int[] percentiles;
		final long[] times;

		public Summary() {
			this.count = 0;
			this.average = 0;
			this.maximum = 0;
			this.percentiles = null;
			this.times = null;
		}

		public Summary(int count, long average, long maximum, int[] percentiles, long times[]) {
			this.count = count;
			this.average = average;
			this.maximum = maximum;
			this.percentiles = percentiles;
			this.times = times;
		}

		public int getCount() {
			return count;
		}

		public long getAverageMillis() {
			return average;
		}

		public long getMaximumMillis() {
			return maximum;
		}

		public int getPercentileCount() {
			return percentiles != null ? percentiles.length : 0;
		}

		public long getPercentilePerMill(int index) {
			return percentiles != null ? percentiles[index] : -1;
		}

		public long getPercentileTimeMills(int index) {
			return times != null ? times[index] : -1;
		}

		public String toString() {
			if (count > 0) {
				StringBuilder summary = new StringBuilder();
				summary.append(String.format("all: %d, avg.: %d ms", count, average));
				for (int index = 0; index < percentiles.length; ++index) {
					int p = percentiles[index] / 10;
					int pm = percentiles[index] % 10;
					if (pm > 0) {
						summary.append(String.format(", %d.%d%%: %d ms", p, pm, times[index]));
					} else {
						summary.append(String.format(", %d%%: %d ms", p, times[index]));
					}
				}
				summary.append(String.format(", max.: %d ms", maximum));
				return summary.toString();
			} else {
				return "no values available!";
			}
		}
	}
}
