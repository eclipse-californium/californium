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
 * Simple count statistic. Count current occurrences and transfers them to an
 * overall counter.
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
	 * Alignment group. Determines alignment based on the longest name of the
	 * group.
	 */
	private final AlignGroup group;
	/**
	 * Current counter. Transferred to {@link #overallCounter} on
	 * {@link #dump(int)} and indirect on {@link #toString()}.
	 */
	private final AtomicLong currentCounter = new AtomicLong();
	/**
	 * Overall counter. Accumulates the transferred current counters. Note:
	 * accessing both counter requires additional synchronisation using this
	 * counter!
	 */
	private final AtomicLong overallCounter = new AtomicLong();

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
	 * Dump statistic. Transfer current counts to overall and returns result as
	 * text with name, current counts and overall counts.
	 * 
	 * @param align width to align names. {@code 0}, don't align name.
	 * @return statistic as text.
	 */
	public String dump(int align) {
		long current;
		long overall;
		synchronized (overallCounter) {
			current = currentCounter.getAndSet(0);
			overall = overallCounter.addAndGet(current);
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
	 * Rest counters.
	 * 
	 * @return reseted values of current and overall counter.
	 */
	public long reset() {
		synchronized (overallCounter) {
			long current = currentCounter.getAndSet(0);
			overallCounter.addAndGet(current);
			return overallCounter.getAndSet(0);
		}
	}

	/**
	 * Check, if statistic is used.
	 * 
	 * @return {@code true}, if at least one counter is larger than 0.
	 */
	public boolean isUsed() {
		synchronized (overallCounter) {
			return currentCounter.get() > 0 || overallCounter.get() > 0;
		}
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
	 * Group for statistics to determine name alginment based on the longest
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
		 * Gets alginment based on the longest name of the group.
		 * 
		 * @return the negative value of one more than length of the longest
		 *         name in the group. Results in left algined names with one
		 *         additional space.
		 */
		public int getAlign() {
			return -(align + 1);
		}
	}
}
