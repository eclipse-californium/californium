/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 *                                 (derived from MessageIdTracker)
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce MessageIdTracker
 *                                                    interface
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.network.config.NetworkConfig;

/**
 * A helper for keeping track of message IDs.
 * <p>
 * According to the
 * <a href="https://tools.ietf.org/html/rfc7252#section-4.4">CoAP spec</a>
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
	 * Exchange lifetime. Value in nanoseconds.
	 * 
	 * @see System#nanoTime()
	 */
	private final long exchangeLifetimeNanos;
	/**
	 * Array with end of lease for MID groups. MID divided by
	 * {@link #sizeOfGroups} is used as index. Values in nanoseconds.
	 * 
	 * @see System#nanoTime()
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
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#MID_TRACKER_GROUPS}
	 * - determine the group size for the message IDs. Each group is marked as
	 * <em>in use</em>, if a MID within the group is used.</li>
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#EXCHANGE_LIFETIME}
	 * - each group of a message ID returned by <em>getNextMessageId</em> is
	 * marked as <em>in use</em> for this amount of time (ms).</li>
	 * </ul>
	 * 
	 * @param initialMid initial MID
	 * @param config configuration
	 */
	public GroupedMessageIdTracker(int initialMid, NetworkConfig config) {
		exchangeLifetimeNanos = TimeUnit.MILLISECONDS.toNanos(config.getLong(NetworkConfig.Keys.EXCHANGE_LIFETIME));
		numberOfGroups = config.getInt(NetworkConfig.Keys.MID_TRACKER_GROUPS);
		currentMID = initialMid;
		sizeOfGroups = (TOTAL_NO_OF_MIDS + numberOfGroups - 1) / numberOfGroups;
		midLease = new long[numberOfGroups];
	}

	/**
	 * Gets the next usable message ID.
	 * 
	 * @return a message ID or {@code -1} if all message IDs are in use
	 *         currently.
	 */
	public int getNextMessageId() {
		final long now = System.nanoTime();
		synchronized (this) {
			// mask mid to the 16 low bits
			int mid = currentMID & 0x0000FFFF;
			int index = mid / sizeOfGroups;
			int nextIndex = (index + 1) % numberOfGroups;
			if (midLease[nextIndex] < now) {
				midLease[index] = now + exchangeLifetimeNanos;
				++currentMID;
				return mid;
			}
		}
		return Message.NONE;
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
