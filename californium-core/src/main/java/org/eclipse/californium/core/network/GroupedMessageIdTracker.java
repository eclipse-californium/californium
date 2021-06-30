/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 *                                 (derived from MessageIdTracker)
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce MessageIdTracker
 *                                                    interface
 *    Achim Kraus (Bosch Software Innovations GmbH) - add mid range to
 *                                                    support multicast
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.ClockUtil;

/**
 * A helper for keeping track of message IDs.
 * <p>
 * According to the
 * <a href="https://tools.ietf.org/html/rfc7252#section-4.4" target="_blank">CoAP spec</a>
 * 
 * <pre>
 * The same Message ID MUST NOT be reused (in communicating with the
   same endpoint) within the EXCHANGE_LIFETIME (Section 4.8.2).
 * </pre>
 * 
 * This implementation groups the MIDs and only keeps the lease time for the
 * last used MID of the group. This reduces the amount of memory but may take a
 * little longer to use the first MIDs of a group because they freed with the
 * lease of the last MID of the group.
 */
public class GroupedMessageIdTracker implements MessageIdTracker {

	/**
	 * Number of groups.
	 */
	private final int numberOfGroups;
	/**
	 * Size of groups. Number of MIDs per group.
	 */
	private final int sizeOfGroups;
	/**
	 * Minimal MID:
	 */
	private final int min;
	/**
	 * Range of MIDs
	 */
	private final int range;
	/**
	 * Exchange lifetime. Value in nanoseconds.
	 * 
	 * @see ClockUtil#nanoRealtime()
	 */
	private final long exchangeLifetimeNanos;
	/**
	 * Array with end of lease for MID groups. MID divided by
	 * {@link #sizeOfGroups} is used as index. Values in nanoseconds.
	 * 
	 * @see ClockUtil#nanoRealtime()
	 */
	private final long midLease[];
	/**
	 * Current MID.
	 */
	private int currentMID;

	/**
	 * Creates a new MID group based tracker.
	 * 
	 * The following configuration values are used:
	 * <ul>
	 * <li>{@link CoapConfig#MID_TRACKER_GROUPS}
	 * - determine the group size for the message IDs. Each group is marked as
	 * <em>in use</em>, if a MID within the group is used.</li>
	 * <li>{@link CoapConfig#EXCHANGE_LIFETIME}
	 * - each group of a message ID returned by <em>getNextMessageId</em> is
	 * marked as <em>in use</em> for this amount of time (ms).</li>
	 * </ul>
	 * 
	 * @param initialMid initial MID
	 * @param minMid minimal MID (inclusive).
	 * @param maxMid maximal MID (exclusive).
	 * @param config configuration
	 * @throws IllegalArgumentException if minMid is not smaller than maxMid or
	 *             initialMid is not in the range of minMid and maxMid
	 * @since 3.0 (changed parameter to Configuration)
	 */
	public GroupedMessageIdTracker(int initialMid, int minMid, int maxMid, Configuration config) {
		if (minMid >= maxMid) {
			throw new IllegalArgumentException("max. MID " + maxMid + " must be larger than min. MID " + minMid + "!");
		}
		if (initialMid < minMid || maxMid <= initialMid) {
			throw new IllegalArgumentException(
					"initial MID " + initialMid + " must be in range [" + minMid + "-" + maxMid + ")!");
		}
		exchangeLifetimeNanos = config.get(CoapConfig.EXCHANGE_LIFETIME, TimeUnit.NANOSECONDS);
		currentMID = initialMid - minMid;
		this.min = minMid;
		this.range = maxMid - minMid;
		this.numberOfGroups = config.get(CoapConfig.MID_TRACKER_GROUPS);
		this.sizeOfGroups = (range + numberOfGroups - 1) / numberOfGroups;
		midLease = new long[numberOfGroups];
		Arrays.fill(midLease, ClockUtil.nanoRealtime() - 1000);
	}

	@Override
	public int getNextMessageId() {
		final long now = ClockUtil.nanoRealtime();
		synchronized (this) {
			// mask mid to the min-max range
			int mid = (currentMID & 0xffff) % range;
			int index = mid / sizeOfGroups;
			int nextIndex = (index + 1) % numberOfGroups;
			if ((midLease[nextIndex] - now) < 0) {
				midLease[index] = now + exchangeLifetimeNanos;
				currentMID = mid + 1;
				return mid + min;
			}
		}
		String time = TimeUnit.NANOSECONDS.toSeconds(exchangeLifetimeNanos) + "s";
		throw new IllegalStateException(
				"No MID available, all [" + min + "-" + (min + range) + ") MID-groups in use! (MID lifetime " + time + "!)");
	}

	/**
	 * Get number of MIDs per group.
	 * 
	 * @return size of groups
	 * @see #sizeOfGroups
	 */
	public int getGroupSize() {
		return sizeOfGroups;
	}
}
