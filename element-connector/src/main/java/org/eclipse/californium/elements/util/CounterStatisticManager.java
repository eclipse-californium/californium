/*******************************************************************************
 * Copyright (c) 2020 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Counter statistic manager.
 * 
 * Manage {@link SimpleCounterStatistic} and support timer interval based and
 * external triggered processing.
 * @since 2.1
 */
abstract public class CounterStatisticManager {

	/**
	 * Align group for {@link SimpleCounterStatistic}.
	 */
	protected final SimpleCounterStatistic.AlignGroup align = new SimpleCounterStatistic.AlignGroup();

	/**
	 * Map of statistics.
	 */
	private final Map<String, SimpleCounterStatistic> statistics = new HashMap<>();

	/**
	 * Tag to describe the information.
	 */
	protected final String tag;
	/**
	 * Executor for active repeated {@link #dump()}. {@code null}, if
	 * {@link #dump()} is called externally.
	 */
	private final ScheduledExecutorService executor;
	/**
	 * Interval to call {@link #dump()} in seconds. {@code 0} to disable active
	 * calls of {@link #dump()}.
	 */
	private final int interval;
	/**
	 * Handle of scheduled task.
	 */
	private ScheduledFuture<?> taskHandle;

	/**
	 * Create passive statistic manager.
	 * 
	 * {@link #dump()} is intended to be called externally.
	 * 
	 * @param tag describing information
	 */
	protected CounterStatisticManager(String tag) {
		this.tag = StringUtil.normalizeLoggingTag(tag);
		this.interval = 0;
		this.executor = null;
	}

	/**
	 * Create active statistic manager.
	 * 
	 * {@link #dump()} is called repeated with configurable interval.
	 * 
	 * @param tag describing information
	 * @param interval interval in seconds. {@code 0} to disable actively calling
	 *            {@link #dump()}.
	 * @param executor executor to schedule active calls of {@link #dump()}.
	 * @throws NullPointerException if executor is {@code null}
	 */
	protected CounterStatisticManager(String tag, int interval, ScheduledExecutorService executor) {
		if (executor == null) {
			throw new NullPointerException("executor must not be null!");
		}
		this.tag = StringUtil.normalizeLoggingTag(tag);
		if (isEnabled()) {
			this.interval = interval;
			this.executor = interval > 0 ? executor : null;
		} else {
			this.interval = 0;
			this.executor = null;
		}
	}

	/**
	 * Add {@link SimpleCounterStatistic} to {@link #statistics} map by head and
	 * name.
	 * 
	 * @param head head appended with {@link SimpleCounterStatistic#getName()}
	 *            to build the key for the map.
	 * @param statistic statistic to be added.
	 * @see #getCounter(String)
	 */
	protected void add(String head, SimpleCounterStatistic statistic) {
		statistics.put(head + statistic.getName(), statistic);
	}

	/**
	 * Add {@link SimpleCounterStatistic} to {@link #statistics} map by name.
	 * 
	 * @param statistic statistic to be added by name.
	 * @see #getCounter(String)
	 */
	protected void add(SimpleCounterStatistic statistic) {
		statistics.put(statistic.getName(), statistic);
	}

	/**
	 * Add {@link SimpleCounterStatistic} to {@link #statistics} map by key.
	 * 
	 * @param key the key for the map.
	 * @param statistic statistic to be added.
	 * @see #getCounter(String)
	 */
	protected void addByKey(String key, SimpleCounterStatistic statistic) {
		statistics.put(key, statistic);
	}

	/**
	 * Get {@link SimpleCounterStatistic} by name.
	 * 
	 * @param name name of counter statistic
	 * @return the counter statistic, or {@code null}, if not available.
	 */
	protected SimpleCounterStatistic get(String name) {
		return statistics.get(name);
	}

	/**
	 * Check, if statistic manager is enabled.
	 * 
	 * @return {@code true}, if statistic logger is enabled, {@code false},
	 *         otherwise.
	 */
	public abstract boolean isEnabled();

	/**
	 * Start active calls of {@link #dump()}.
	 */
	public synchronized void start() {
		if (executor != null && taskHandle == null) {
			taskHandle = executor.scheduleAtFixedRate(new Runnable() {

				@Override
				public void run() {
					dump();
				}

			}, interval, interval, TimeUnit.SECONDS);
		}
	}

	/**
	 * Stop active calls of {@link #dump()}.
	 */
	public synchronized void stop() {
		if (taskHandle != null) {
			taskHandle.cancel(false);
			taskHandle = null;
		}
	}

	/**
	 * Dump statistic. Either called active, for
	 * {@link #CounterStatisticManager(String, int, ScheduledExecutorService)},
	 * or externally.
	 */
	public abstract void dump();

	/**
	 * Resets all {@link SimpleCounterStatistic}.
	 */
	public void reset() {
		for (SimpleCounterStatistic statistic : statistics.values()) {
			statistic.reset();
		}
	}

	/**
	 * Get counter of {@link SimpleCounterStatistic}.
	 * 
	 * @param name name to lookup. Created using {@code head} and append
	 *            {@link SimpleCounterStatistic#getName()}.
	 * @return counter of {@link SimpleCounterStatistic}.
	 * @see #add(String, SimpleCounterStatistic)
	 */
	public long getCounter(String name) {
		return get(name).getCounter();
	}
}
