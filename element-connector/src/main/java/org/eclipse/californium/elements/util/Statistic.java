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
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Statistic.
 * 
 * Implemented using a table of counters for sample value slots.
 * 
 * e.g.:
 * 
 * <pre>
 * Statistic retransmission = new Statistic(5, 1):
 * 
 *   slot for 0 retransmissions, counter[0]
 *   slot for 1 retransmissions, counter[1]
 *   slot for 2 retransmissions, counter[2]
 *   slot for 3 retransmissions, counter[3] 
 *   slot for 4 retransmissions and more, counter[4]
 * </pre>
 * 
 * <pre>
 * Statistic payload = new Statistic(256, 64):
 *   slot for 0-63 bytes payload, counter[0]
 *   slot for 64-127 bytes payload, counter[1]
 *   slot for 128-191 bytes payload, counter[2]
 *   slot for 192-    bytes payload, counter[3]
 * </pre>
 * 
 * A sample is processed by incrementing the counter of the related slot.
 * 
 * <pre>
 * retransmission.add(2);
 *   2 retransmissions, increment counter[2] of retransmission statistic.
 * 
 * payload.add(100):
 *   100 bytes payload, increment counter[1] of payload statistic.
 * </pre>
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

	/**
	 * Sum of added sample value.
	 */
	private final AtomicLong sum = new AtomicLong();
	/**
	 * {@code true}, on sum overflow.
	 */
	private final AtomicBoolean invalidSum = new AtomicBoolean();

	/**
	 * Maximum added sample value.
	 */
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
	 * Add sample value to statistic.
	 * 
	 * @param value sample value to add
	 */
	public void add(long value) {
		if (value >= 0) {
			int index = (int) (value / slotWidth);
			if (index < statistic.length) {
				statistic[index].incrementAndGet();
			} else {
				statistic[statistic.length - 1].incrementAndGet();
			}
			if (!invalidSum.get() && sum.addAndGet(value) < 0) {
				invalidSum.set(true);
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
	 * Checks, if sample values are available for this statistic.
	 * 
	 * @return {@code true}, if sample values are available, {@code false},
	 *         otherwise.
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
		long count = 0;
		for (int index = 0; index < statistic.length; ++index) {
			long hits = statistic[index].get();
			if (hits > 0) {
				count += hits;
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
			return new Summary((int) count, invalidSum.get() ? null : sum.get(), max, percentiles, values);
		} else {
			return new Summary();
		}
	}

	/**
	 * Statistic summary.
	 * 
	 * @see Statistic#getSummary(int...)
	 */
	public static class Summary {

		/**
		 * Number of samples
		 */
		private final int count;
		/**
		 * Overall sum of added sample values.
		 */
		private final Long overallSum;
		/**
		 * Maximum added sample value.
		 */
		private final long maximum;
		/**
		 * List of per mill percentiles,. e.g. {@code 990} for {@code 99%}.
		 */
		private final int[] percentiles;
		/**
		 * Values of percentiles according {@link #percentiles}.
		 */
		private final long[] percentileValues;

		/**
		 * Empty statistic, if no values are available.
		 */
		public Summary() {
			this.count = 0;
			this.overallSum = 0L;
			this.maximum = 0L;
			this.percentiles = null;
			this.percentileValues = null;
		}

		/**
		 * Statistic with snapshot of current samples.
		 * 
		 * @param count number of samples
		 * @param overallSum Overall sum of sample values. {@code null} for sum
		 *            overflow.
		 * @param maximum maximum sample value
		 * @param percentiles List of per mill percentiles,. e.g. {@code 990}
		 *            for {@code 99%}.
		 * @param values values of percentiles according percentiles.
		 * @throws NullPointerException if values are {@code null}, and
		 *             percentiles are provided.
		 * @throws IllegalArgumentException if the percentiles and values have
		 *             different lengths.
		 */
		public Summary(int count, Long overallSum, long maximum, int[] percentiles, long values[]) {
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
			this.overallSum = overallSum;
			this.maximum = maximum;
			this.percentiles = percentiles;
			this.percentileValues = values;
		}

		/**
		 * Create a scaled statistic.
		 * 
		 * Apply scale function to all values.
		 * 
		 * @param raw statistic
		 * @param scale scale function
		 */
		public Summary(Summary raw, Scale scale) {
			this.count = raw.count;
			if (raw.overallSum != null) {
				this.overallSum = scale.scale(raw.overallSum);
			} else {
				this.overallSum = null;
			}
			this.maximum = scale.scale(raw.maximum);
			this.percentiles = raw.percentiles;
			if (raw.percentileValues != null) {
				int numOfValues = raw.percentileValues.length;
				this.percentileValues = new long[numOfValues];
				for (int index = 0; index < numOfValues; ++index) {
					this.percentileValues[index] = scale.scale(raw.percentileValues[index]);
				}
			} else {
				this.percentileValues = null;
			}
		}

		/**
		 * Get number of sample values.
		 * 
		 * @return number of sample values
		 */
		public int getCount() {
			return count;
		}

		/**
		 * Get average sample value.
		 * 
		 * @return average sample value. -1.0 on overflow.
		 */
		public double getAverage() {
			if (overallSum == null) {
				return -1.0D;
			}
			return count == 0 ? 0.0D : ((double) overallSum) / count;
		}

		/**
		 * Get overall sum of sample values.
		 * 
		 * @return overall sum of sample values, or {@code null}, on overflow
		 */
		public Long getOverallSum() {
			return overallSum;
		}

		/**
		 * Get maximum sample value.
		 * 
		 * @return maximum sample value
		 */
		public long getMaximum() {
			return maximum;
		}

		/**
		 * Number of percentiles.
		 * 
		 * @return number of percentiles
		 */
		public int getPercentileCount() {
			return percentiles != null ? percentiles.length : 0;
		}

		/**
		 * Get per mill percentile of index.
		 * 
		 * @param index index within {@code [0 ... PercentileCount)}.
		 * @return per mill percentile in of index. Range {@code 0} to
		 *         {@code 999}. {@code 950} for {@code 95%}.
		 */
		public long getPercentilePerMill(int index) {
			return percentiles != null ? percentiles[index] : -1;
		}

		/**
		 * Sample value of percentile.
		 * 
		 * @param index index within {@code [0 ... PercentileCount)}.
		 * @return sample value of percentile
		 */
		public long getPercentileValue(int index) {
			return percentileValues != null ? percentileValues[index] : -1;
		}

		/**
		 * Textual statistic without unit..
		 * 
		 * @return textual statistic.
		 */
		public String toString() {
			return toString("");
		}

		/**
		 * Textual statistic using provide unit.
		 * 
		 * @param unit sample values unit
		 * @return textual statistic with unit.
		 */
		public String toString(String unit) {
			if (count > 0) {
				StringBuilder summary = new StringBuilder();
				summary.append(String.format("#: %d", count));
				if (overallSum != null) {
					double average = getAverage();
					if (average < 1.0F) {
						summary.append(String.format(Locale.UK, ", sum.: %d%s", overallSum, unit));
					} else {
						summary.append(String.format(Locale.UK, ", avg.: %.2f%s", average, unit));
					}
				}
				if (percentiles != null) {
					for (int index = 0; index < percentiles.length; ++index) {
						int p = percentiles[index] / 10;
						int pm = percentiles[index] % 10;
						if (pm > 0) {
							summary.append(String.format(", %d.%d%%: %d%s", p, pm, percentileValues[index], unit));
						} else {
							summary.append(String.format(", %d%%: %d%s", p, percentileValues[index], unit));
						}
					}
				}
				summary.append(String.format(", max.: %d%s", maximum, unit));
				return summary.toString();
			} else {
				return "no values available!";
			}
		}

		/**
		 * Scale summary.
		 * 
		 * Apply scale function to all values.
		 * 
		 * @param scale scale function
		 * @return scaled summary
		 */
		public Summary scale(Scale scale) {
			return new Summary(this, scale);
		}
	}

	/**
	 * Scale function.
	 * 
	 * Scale {@link Summary} sample values.
	 * 
	 * @see Summary#scale
	 */
	public interface Scale {

		long scale(long value);
	}
}
