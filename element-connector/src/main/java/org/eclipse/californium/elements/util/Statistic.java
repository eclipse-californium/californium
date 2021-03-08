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
import java.util.concurrent.atomic.AtomicLong;

/**
 * Statistic.
 * 
 * Implemented using a table of counters for slots.
 * 
 * @since 3.0
 */
public class Statistic {

	/**
	 * Slot width.
	 */
	private final long slotWidth;
	/**
	 * Tables of counters. Slot is defined by {@code index} and
	 * {@link #slotWidth}.
	 */
	private final AtomicLong[] statistic;

	private final AtomicLong maximum = new AtomicLong();

	/**
	 * Create statistic.
	 * 
	 * @param range overall range.
	 * @param slot slot width
	 */
	public Statistic(long range, long slot) {
		int size = (int) (range / slot) + 1;
		statistic = new AtomicLong[size];
		for (int index = 0; index < size; ++index) {
			statistic[index] = new AtomicLong();
		}
		slotWidth = slot;
	}

	/**
	 * Add value to statistic.
	 * 
	 * @param value value to add
	 */
	public void add(long value) {
		if (value >= 0) {
			int index = (int) (value / slotWidth);
			if (index < statistic.length) {
				statistic[index].incrementAndGet();
			} else {
				statistic[statistic.length - 1].incrementAndGet();
			}
			long maximumValue = maximum.get();
			while (value > maximumValue) {
				if (maximum.compareAndSet(maximumValue, value)) {
					break;
				}
				maximumValue = maximum.get();
			}
		}
	}

	/**
	 * Get upper limit of slot.
	 * 
	 * @param index index of slot.
	 * @return upper limit of slot
	 */
	private long getUpperLimit(int index) {
		if (slotWidth > 1) {
			return ((index + 1) * slotWidth) - 1;
		} else {
			return index;
		}
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
	 *            {@code 99%}. If no percentiles are provided, only the average
	 *            and the maximum is included in the summary.
	 * @return summary
	 */
	public Summary getSummary(int... percentiles) {
		long sum = 0;
		long count = 0;
		for (int index = 0; index < statistic.length; ++index) {
			long hits = statistic[index].get();
			if (hits > 0) {
				count += hits;
				sum += hits * getUpperLimit(index);
				if (sum < 0) {
					throw new IllegalStateException();
				}
			}
		}
		if (count > 0) {
			long max = maximum.get();
			long[] values = null;
			if (percentiles != null) {
				values = new long[percentiles.length];
				if (percentiles.length > 0) {
					Arrays.sort(percentiles);
					int linesIndex = percentiles.length - 1;
					if (percentiles[linesIndex] < 0 || percentiles[linesIndex] > 999) {
						throw new IllegalArgumentException(
								"line " + percentiles[linesIndex] + " is not in [0...999]%%");
					}
					long line = count * (1000 - percentiles[linesIndex]) / 1000;
					long downCount = 0;
					for (int index = statistic.length - 1; index >= 0; --index) {
						long hits = statistic[index].get();
						if (hits > 0) {
							long next = downCount + hits;
							while (downCount <= line && next > line) {
								long value = getUpperLimit(index);
								if (value > max) {
									value = max;
								}
								values[linesIndex] = value;
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
			}
			return new Summary((int) count, sum / count, max, percentiles, values);
		} else {
			return new Summary();
		}
	}

	public static class Summary {

		final int count;
		final long average;
		final long maximum;
		final int[] percentiles;
		final long[] values;

		public Summary() {
			this.count = 0;
			this.average = 0;
			this.maximum = 0;
			this.percentiles = null;
			this.values = null;
		}

		public Summary(int count, long average, long maximum, int[] percentiles, long values[]) {
			if (percentiles != null) {
				if (values == null) {
					throw new NullPointerException("values must not be null, if percentiles are provided!");
				}
				if (percentiles.length != values.length) {
					throw new IllegalArgumentException(
							"Number of values must match percentiles! " + percentiles.length + " != " + values.length);
				}
			}
			this.count = count;
			this.average = average;
			this.maximum = maximum;
			this.percentiles = percentiles;
			this.values = values;
		}

		public Summary(Summary raw, Scale scale) {
			this.count = raw.count;
			this.average = scale.scale(raw.average);
			this.maximum = scale.scale(raw.maximum);
			this.percentiles = raw.percentiles;
			if (raw.values != null) {
				int numOfValues = raw.values.length;
				this.values = new long[numOfValues];
				for (int index = 0; index < numOfValues; ++index) {
					this.values[index] = scale.scale(raw.values[index]);
				}
			} else {
				this.values = null;
			}
		}

		public int getCount() {
			return count;
		}

		public long getAverage() {
			return average;
		}

		public long getMaximum() {
			return maximum;
		}

		public int getPercentileCount() {
			return percentiles != null ? percentiles.length : 0;
		}

		public long getPercentilePerMill(int index) {
			return percentiles != null ? percentiles[index] : -1;
		}

		public long getPercentileValue(int index) {
			return values != null ? values[index] : -1;
		}

		public String toString() {
			return toString("");
		}

		public String toString(String unit) {
			if (count > 0) {
				StringBuilder summary = new StringBuilder();
				summary.append(String.format("all: %d, avg.: %d%s", count, average, unit));
				if (percentiles != null) {
					for (int index = 0; index < percentiles.length; ++index) {
						int p = percentiles[index] / 10;
						int pm = percentiles[index] % 10;
						if (pm > 0) {
							summary.append(String.format(", %d.%d%%: %d%s", p, pm, values[index], unit));
						} else {
							summary.append(String.format(", %d%%: %d%s", p, values[index], unit));
						}
					}
				}
				summary.append(String.format(", max.: %d%s", maximum, unit));
				return summary.toString();
			} else {
				return "no values available!";
			}
		}
	}

	public interface Scale {

		long scale(long value);
	}
}
