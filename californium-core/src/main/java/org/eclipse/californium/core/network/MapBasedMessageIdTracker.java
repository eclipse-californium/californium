/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - cleanup and use 
 *                                                    System.nanoTime() instead
 *                                                    of currentTimeMillis().
 *    Achim Kraus (Bosch Software Innovations GmbH) - rename MessageIdTracker
 *                                                    to MapBasedMessageIdTracker.
 *                                                    introduce MessageIdTracker
 *                                                    interface.
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.network.config.NetworkConfig;

/**
 * A helper for keeping track of message IDs using a map.
 * <p>
 * According to the
 * <a href="https://tools.ietf.org/html/rfc7252#section-4.4">CoAP spec</a>
 * 
 * <pre>
 * The same Message ID MUST NOT be reused (in communicating with the
   same endpoint) within the EXCHANGE_LIFETIME (Section 4.8.2).
 * </pre>
 */
public class MapBasedMessageIdTracker implements MessageIdTracker {

	private final Map<Integer, Long> messageIds;
	private final long exchangeLifetimeNanos; // milliseconds
	private int counter;

	/**
	 * Creates a new tracker based on configuration values.
	 * 
	 * The following configuration value is used:
	 * <ul>
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#EXCHANGE_LIFETIME}
	 * - each message ID returned by <em>getNextMessageId</em> is marked as
	 * <em>in use</em> for this amount of time (ms).</li>
	 * </ul>
	 * 
	 * @param initialMid initial MID
	 * @param config configuration
	 */
	public MapBasedMessageIdTracker(int initialMid, NetworkConfig config) {
		exchangeLifetimeNanos = TimeUnit.MILLISECONDS.toNanos(config.getLong(NetworkConfig.Keys.EXCHANGE_LIFETIME));
		counter = initialMid;
		messageIds = new HashMap<>(TOTAL_NO_OF_MIDS);
	}

	/**
	 * Gets the next usable message ID.
	 * 
	 * @return a message ID or {@code Message.NONE} if all message IDs are in
	 *         use currently.
	 */
	public int getNextMessageId() {
		int result = Message.NONE;
		boolean wrapped = false;
		long now = System.nanoTime();
		synchronized (messageIds) {
			// mask mid to the 16 low bits
			int startIdx = counter & 0x0000FFFF;
			while (result < 0 && !wrapped) {
				// mask mid to the 16 low bits
				int idx = counter++ & 0x0000FFFF;
				Long earliestUsage = messageIds.get(idx);
				if (earliestUsage == null || now >= earliestUsage) {
					// message Id can be safely re-used
					result = idx;
					messageIds.put(idx, now + exchangeLifetimeNanos);
				}
				wrapped = (counter & 0x0000FFFF) == startIdx;
			}
		}
		return result;
	}
}
