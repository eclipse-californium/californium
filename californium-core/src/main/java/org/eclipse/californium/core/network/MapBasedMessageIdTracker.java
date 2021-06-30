/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - cleanup and use 
 *                                                    System.nanoTime() instead
 *                                                    of currentTimeMillis().
 *    Achim Kraus (Bosch Software Innovations GmbH) - rename MessageIdTracker
 *                                                    to MapBasedMessageIdTracker.
 *                                                    introduce MessageIdTracker
 *                                                    interface.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add mid range to
 *                                                    support multicast
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.ClockUtil;

/**
 * A helper for keeping track of message IDs using a map.
 * <p>
 * According to the
 * <a href="https://tools.ietf.org/html/rfc7252#section-4.4" target="_blank">CoAP spec</a>
 * 
 * <pre>
 * The same Message ID MUST NOT be reused (in communicating with the
   same endpoint) within the EXCHANGE_LIFETIME (Section 4.8.2).
 * </pre>
 */
public class MapBasedMessageIdTracker implements MessageIdTracker {

	private final Map<Integer, Long> messageIds;
	private final long exchangeLifetimeNanos; // milliseconds
	private final int min;
	private final int range;
	private int counter;

	/**
	 * Creates a new tracker based on configuration values.
	 * 
	 * The following configuration value is used:
	 * <ul>
	 * <li>{@link CoapConfig#EXCHANGE_LIFETIME}
	 * - each message ID returned by <em>getNextMessageId</em> is marked as
	 * <em>in use</em> for this amount of time (ms).</li>
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
	public MapBasedMessageIdTracker(int initialMid, int minMid, int maxMid, Configuration config) {
		if (minMid >= maxMid) {
			throw new IllegalArgumentException("max. MID " + maxMid + " must be larger than min. MID " + minMid + "!");
		}
		if (initialMid < minMid || maxMid <= initialMid) {
			throw new IllegalArgumentException(
					"initial MID " + initialMid + " must be in range [" + minMid + "-" + maxMid + ")!");
		}
		exchangeLifetimeNanos = config.get(CoapConfig.EXCHANGE_LIFETIME, TimeUnit.NANOSECONDS);
		counter = initialMid - minMid;
		min = minMid;
		range = maxMid - minMid;
		messageIds = new HashMap<>(range);
	}

	@Override
	public int getNextMessageId() {
		final long now = ClockUtil.nanoRealtime();
		synchronized (messageIds) {
			// mask mid to the range
			counter = (counter & 0xffff) % range;
			final int end = counter + range;
			while (counter < end) {
				// mask mid to the range
				int idx = counter++ % range;
				Long earliestUsage = messageIds.get(idx);
				if (earliestUsage == null || (earliestUsage - now) <= 0) {
					// message Id can be safely re-used
					messageIds.put(idx, now + exchangeLifetimeNanos);
					return idx + min;
				}
			};
		}
		String time = TimeUnit.NANOSECONDS.toSeconds(exchangeLifetimeNanos) + "s";
		throw new IllegalStateException(
				"No MID available, all [" + min + "-" + (min + range) + ") MIDs in use! (MID lifetime " + time + "!)");
	}
}
