/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Simple count statistic.
 * 
 * Count current occurrences and transfers them to an overall counter.
 */
public class SimpleCounterStatistic {

	/**
	 * Name of statistic.
	 */
	private final String name;
	/**
	 * Alignment used for {@link #toString()}.
	 */
	private final int align;
	/**
	 * Alignment group.
	 * 
	 * Determines alignment based on the longest name of the group.
	 */
	private final AlignGroup group;
	/**
	 * Current counter.
	 * 
	 * Transferred to {@link #overallCounter} on {@link #dump(int)} and indirect
	 * on {@link #toString()}.
	 */
	private final AtomicLong currentCounter = new AtomicLong();
	/**
	 * Overall counter.
	 * 
	 * Accumulates the transferred current counters.
	 * 
	 * <b>Note:</b> accessing both counter requires additional synchronization
	 * using this counter!
	 */
	private final AtomicLong overallCounter = new AtomicLong();
	/**
	 * Start counter.
	 * 
	 * Support statistics on external maintained data.
	 * 
	 * @since 3.1
	 */
	private final AtomicLong startCounter = new AtomicLong(-1);

	/**
	 * Create statistic.
	 * 
	 * @param name name of statistic
	 */
	public SimpleCounterStatistic(String name) {
		this.name = name;
		this.align = 0;
		this.group = null;
	}

	/**
	 * Create statistic.
	 * 
	 * @param name name of statistic
	 * @param align align passed to width of
	 *            {@link String#format(String, Object...)}.
	 */
	public SimpleCounterStatistic(String name, int align) {
		this.name = name;
		this.align = align;
		this.group = null;
	}

	/**
	 * Create statistic.
	 * 
	 * @param name name of statistic
	 * @param group group to determine alignment based on the longest name of
	 *            the group.
	 */
	public SimpleCounterStatistic(String name, AlignGroup group) {
		this.name = name;
		this.align = 0;
		this.group = group.add(this);
	}

	/**
	 * Transfer current counter to overall counter.
	 * 
	 * @since 3.1
	 */
	public void transferCounter() {
		synchronized (overallCounter) {
			long current = currentCounter.getAndSet(0);
			overallCounter.addAndGet(current);
		}
	}

	/**
	 * Dump statistic.
	 * 
	 * @param align width to align names. {@code 0}, don't align name.
	 * @return statistic as text.
	 * @since 3.1 ({@link #transferCounter()} must be called explicitly.)
	 */
	public String dump(int align) {
		long current;
		long overall;
		synchronized (overallCounter) {
			current = currentCounter.get();
			overall = overallCounter.get();
		}
		return format(align, name, current) + String.format(" (%8d overall).", overall);
	}

	/**
	 * Gets name of statistic.
	 * 
	 * @return name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Set start value.
	 * 
	 * @param value start value
	 * @see #set(long)
	 * @throws IllegalArgumentException if value is less than {@code 0}.
	 * @since 3.1
	 */
	public void setStart(long value) {
		if (value < 0) {
			throw new IllegalArgumentException("Value " + value + " must not be less than 0!");
		}
		synchronized (overallCounter) {
			startCounter.set(value);
		}
	}

	/**
	 * Set current value.
	 * 
	 * <b>Note:</b> not intended to be called as high frequently as
	 * {@link #increment()}.
	 * 
	 * @param value current value.
	 * @see #setStart(long)
	 * @since 3.1
	 */
	public void set(long value) {
		synchronized (overallCounter) {
			long start = startCounter.get();
			if (start < 0) {
				start = 0;
				startCounter.set(0);
			}
			currentCounter.set(value - overallCounter.get() - start);
		}
	}

	/**
	 * Increment current counter.
	 * 
	 * @return resulting value of the current counter
	 */
	public long increment() {
		return currentCounter.incrementAndGet();
	}

	/**
	 * Increment current counter by value.
	 * 
	 * @param delta delta to be applied to current counter
	 * @return resulting value of the current counter
	 */
	public long increment(int delta) {
		return currentCounter.addAndGet(delta);
	}

	/**
	 * Get counter value.
	 * 
	 * @return counter value
	 * @since 2.1
	 */
	public long getCounter() {
		synchronized (overallCounter) {
			return overallCounter.get() + currentCounter.get();
		}
	}

	/**
	 * Get pair of current counter values.
	 * 
	 * @return array with counter values. Position 0, the current, position 1,
	 *         the overall so far.
	 * @since 3.1
	 */
	public long[] getCountersPair() {
		synchronized (overallCounter) {
			return new long[] { currentCounter.get(), overallCounter.get() };
		}
	}

	/**
	 * Resets counters to {@code 0}.
	 * 
	 * Adjust {@link #startCounter} using the sum of the current and overall
	 * counter.
	 * 
	 * @return values of current and overall counter before reseted.
	 */
	public long reset() {
		synchronized (overallCounter) {
			long current = currentCounter.getAndSet(0);
			overallCounter.addAndGet(current);
			current = overallCounter.getAndSet(0);
			long start = startCounter.get();
			if (start > 0) {
				startCounter.set(current + start);
			} else {
				startCounter.set(current);
			}
			return current;
		}
	}

	/**
	 * Check, if statistic is used.
	 * 
	 * @return {@code true}, if {@link #currentCounter} or
	 *         {@link #overallCounter} is larger than {@code 0}.
	 */
	public boolean isUsed() {
		synchronized (overallCounter) {
			return currentCounter.get() > 0 || overallCounter.get() > 0;
		}
	}

	/**
	 * Check, if statistic is started.
	 * 
	 * @return {@code true}, if {@link #startCounter} is {@code 0} or larger
	 *         than {@code 0}.
	 * @see #setStart(long)
	 * @since 3.1
	 */
	public boolean isStarted() {
		return startCounter.get() >= 0;
	}

	@Override
	public String toString() {
		int align = group == null ? this.align : group.getAlign();
		return dump(align);
	}

	/**
	 * Format header of statistic line.
	 * 
	 * The name will be aligned using the align as width. The number will be
	 * printed with width 8. Intended to be used for additional information not
	 * processed by this counter statistic.
	 * 
	 * @param align alignment for name
	 * @param name name
	 * @param value value
	 * @return line
	 */
	public static String format(int align, String name, long value) {
		if (align == 0) {
			return String.format("%s: %8d", name, value);
		} else {
			return String.format("%" + align + "s: %8d", name, value);
		}
	}

	/**
	 * Group for statistics to determine name alignment based on the longest
	 * name in the group.
	 */
	public static class AlignGroup {

		/**
		 * Longest alignment in group.
		 */
		int align;

		/**
		 * Add statistic to group.
		 * 
		 * @param statistic statistic to consider the name for alignment.
		 * @return this group
		 */
		public AlignGroup add(SimpleCounterStatistic statistic) {
			return add(statistic.getName());
		}

		/**
		 * Add name to group.
		 * 
		 * @param name name to consider or alignment.
		 * @return this group
		 */
		public AlignGroup add(String name) {
			int align = name.length();
			if (align > this.align) {
				this.align = align;
			}
			return this;
		}

		/**
		 * Gets alignment based on the longest name of the group.
		 * 
		 * @return the negative value of one more than length of the longest
		 *         name in the group. Results in left aligned names with one
		 *         additional space.
		 */
		public int getAlign() {
			return -(align + 1);
		}
	}
}
