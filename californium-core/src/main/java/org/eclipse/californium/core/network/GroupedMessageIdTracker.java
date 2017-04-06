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
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

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
public class GroupedMessageIdTracker {

	private static final int TOTAL_NO_OF_MIDS = 1 << 16;
	/**
	 * Number of groups.
	 * 
	 * Configurable using {@link NetworkConfig.Keys#MID_PROVIDER_GROUPS}.
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
	private final long exchangeLifetime;
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
	 * Creates a new tracker based on configuration values.
	 * <p>
	 * The following configuration values are used:
	 * <ul>
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#MID_PROVIDER_GROUPS}
	 * - determine the group size for the message IDs. Each group is marked as
	 * <em>in use</em>, if a MID within the group is used.</li>
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#EXCHANGE_LIFETIME}
	 * - each group of a message ID returned by <em>getNextMessageId</em> is
	 * marked as <em>in use</em> for this amount of time (ms).</li>
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#USE_RANDOM_MID_START}
	 * - if this value is {@code true} then the message IDs returned by
	 * <em>getNextMessageId</em> will start at a random index. Otherwise the
	 * first message ID returned will be {@code 0}.</li>
	 * </ul>
	 * 
	 * @param config the configuration to use.
	 */
	public GroupedMessageIdTracker(final NetworkConfig config) {
		numberOfGroups = config.getInt(NetworkConfig.Keys.MID_PROVIDER_GROUPS);
		sizeOfGroups = (TOTAL_NO_OF_MIDS + numberOfGroups - 1) / numberOfGroups;
		exchangeLifetime = TimeUnit.MILLISECONDS.toNanos(config.getLong(NetworkConfig.Keys.EXCHANGE_LIFETIME));
		boolean useRandomFirstMID = config.getBoolean(NetworkConfig.Keys.USE_RANDOM_MID_START);
		if (useRandomFirstMID) {
			currentMID = new SecureRandom().nextInt(TOTAL_NO_OF_MIDS);
		} else {
			currentMID = 0;
		}
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
			int mid = currentMID % TOTAL_NO_OF_MIDS;
			int index = mid / sizeOfGroups;
			int nextIndex = (index + 1) % numberOfGroups;
			if (midLease[nextIndex] < now) {
				midLease[index] = now + exchangeLifetime;
				++currentMID;
				return mid;
			}
		}
		return -1;
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
