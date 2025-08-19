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

import java.security.Principal;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Counter statistic manager.
 * <p>
 * Manages {@link SimpleCounterStatistic}.
 * <p>
 * Since 3.1: {@link #isEnabled()} is now coupled to the logger info level, if a
 * logger is assigned. In order to write the statistic, the logger must have at
 * least level debug. That enables to collect statistics without writing them.
 * 
 * @since 2.1
 */
abstract public class CounterStatisticManager {

	/**
	 * Align group for {@link SimpleCounterStatistic}.
	 */
	protected final SimpleCounterStatistic.AlignGroup align = new SimpleCounterStatistic.AlignGroup();

	/**
	 * Map of statistics.
	 * 
	 * @since 3.1 (adapted to use concurrent variant)
	 */
	private final ConcurrentMap<String, SimpleCounterStatistic> statistics = new ConcurrentHashMap<>();
	/**
	 * List of keys in order of {@link #add}.
	 * 
	 * @since 3.1
	 */
	private final List<String> orderedKeys = new CopyOnWriteArrayList<>();

	/**
	 * Tag to describe the information.
	 */
	protected final String tag;

	/**
	 * The nano-realtime of the last transfer.
	 * 
	 * @see ClockUtil#nanoRealtime()
	 * @since 3.1
	 */
	private AtomicLong lastTransfer = new AtomicLong(ClockUtil.nanoRealtime());

	/**
	 * Creates statistic manager.
	 * 
	 * @param tag describing information
	 */
	protected CounterStatisticManager(String tag) {
		this.tag = StringUtil.normalizeLoggingTag(tag);
	}

	/**
	 * Adds {@link SimpleCounterStatistic} to {@link #statistics} map by head
	 * and name.
	 * <p>
	 * The head may be used to group sections.
	 * 
	 * @param head head appended with {@link SimpleCounterStatistic#getName()}
	 *            to build the key for the map.
	 * @param statistic statistic to be added.
	 * @see #getByKey(String)
	 * @see #useSections()
	 */
	protected void add(String head, SimpleCounterStatistic statistic) {
		addByKey(head + statistic.getName(), statistic);
	}

	/**
	 * Adds {@link SimpleCounterStatistic} to {@link #statistics} map by name.
	 * 
	 * @param statistic statistic to be added by name.
	 * @see #getByKey(String)
	 */
	protected void add(SimpleCounterStatistic statistic) {
		addByKey(statistic.getName(), statistic);
	}

	/**
	 * Adds {@link SimpleCounterStatistic} to {@link #statistics} map by key.
	 * <p>
	 * If a statistic is replaced, the previous one is removed and the new one
	 * is added at the end.
	 * 
	 * @param key the key for the map.
	 * @param statistic statistic to be added.
	 * @see #getByKey(String)
	 * @see #removeByKey(String, SimpleCounterStatistic)
	 */
	protected void addByKey(String key, SimpleCounterStatistic statistic) {
		SimpleCounterStatistic previous = statistics.put(key, statistic);
		if (previous != null) {
			orderedKeys.remove(key);
		}
		orderedKeys.add(key);
	}

	/**
	 * Removes {@link SimpleCounterStatistic} to {@link #statistics} map by key.
	 * 
	 * @param key the key for the map.
	 * @param statistic statistic to be added.
	 * @see #addByKey(String, SimpleCounterStatistic)
	 * @see #getByKey(String)
	 * @see #removeByKey(String)
	 * @since 3.1
	 */
	protected void removeByKey(String key, SimpleCounterStatistic statistic) {
		if (statistics.remove(key, statistic)) {
			orderedKeys.remove(key);
		}
	}

	/**
	 * Removes {@link SimpleCounterStatistic} to {@link #statistics} map by key.
	 * 
	 * @param key the key for the map.
	 * @see #addByKey(String, SimpleCounterStatistic)
	 * @see #getByKey(String)
	 * @see #removeByKey(String, SimpleCounterStatistic)
	 * @since 3.1
	 */
	protected void removeByKey(String key) {
		if (statistics.containsKey(key)) {
			statistics.remove(key);
			orderedKeys.remove(key);
		}
	}

	/**
	 * Gets {@link SimpleCounterStatistic} by key.
	 * 
	 * @param key key the map
	 * @return the counter statistic, or {@code null}, if not available.
	 * @see #addByKey(String, SimpleCounterStatistic)
	 * @see #removeByKey(String, SimpleCounterStatistic)
	 * @since 3.1
	 */
	public SimpleCounterStatistic getByKey(String key) {
		return statistics.get(key);
	}

	/**
	 * Gets ordered list of keys.
	 * 
	 * @return ordered list of keys.
	 * @since 3.1
	 */
	public List<String> getKeys() {
		return Collections.unmodifiableList(orderedKeys);
	}

	/**
	 * Gets ordered list of selected keys by principal.
	 * <p>
	 * Intended to be overwritten, if principal specific selection is intended.
	 * 
	 * @param principal principal. May be {@code null}.
	 * @return ordered list of selected keys.
	 * @since 3.13
	 */
	public List<String> getKeys(Principal principal) {
		return Collections.unmodifiableList(orderedKeys);
	}

	/**
	 * Indicates to use heads as section.
	 * 
	 * @return {@code true} to use heads as sections, {@code false} otherwise.
	 */
	public boolean useSections() {
		return false;
	}

	/**
	 * Checks, if statistic manager is enabled.
	 * 
	 * @return {@code true}, if statistic logger is enabled, {@code false},
	 *         otherwise.
	 */
	public abstract boolean isEnabled();

	/**
	 * Dumps statistic.
	 */
	public abstract void dump();

	/**
	 * Gets the nano-realtime of the last transfer.
	 * 
	 * @return the nano-realtime of the last transfer
	 * @see ClockUtil#nanoRealtime()
	 * @see #transferCounter()
	 * @see #reset()
	 * @since 3.1
	 */
	public long getLastTransferTime() {
		return lastTransfer.get();
	}

	/**
	 * Transfers all current counters to overall counters.
	 * 
	 * @since 3.1
	 */
	public void transferCounter() {
		for (SimpleCounterStatistic statistic : statistics.values()) {
			statistic.transferCounter();
		}
		lastTransfer.set(ClockUtil.nanoRealtime());
	}

	/**
	 * Resets all {@link SimpleCounterStatistic}.
	 */
	public void reset() {
		for (SimpleCounterStatistic statistic : statistics.values()) {
			statistic.reset();
		}
		lastTransfer.set(ClockUtil.nanoRealtime());
	}

	/**
	 * Gets counter of {@link SimpleCounterStatistic}.
	 * 
	 * @param key key to lookup. If added by
	 *            {@link #add(SimpleCounterStatistic)}, use
	 *            {@link SimpleCounterStatistic#getName()}. If added by
	 *            {@link #add(String, SimpleCounterStatistic)}, use {@code head}
	 *            and append {@link SimpleCounterStatistic#getName()}.
	 * @return counter of {@link SimpleCounterStatistic}.
	 * @see #getByKey(String)
	 * @since 3.1
	 */
	public long getCounterByKey(String key) {
		return getByKey(key).getCounter();
	}

	/**
	 * Gets logging tag.
	 * 
	 * @return logging tag.
	 * @since 2.5
	 */
	public String getTag() {
		return tag;
	}
}
