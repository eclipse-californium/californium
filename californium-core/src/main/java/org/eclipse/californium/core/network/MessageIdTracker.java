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
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.network.config.NetworkConfig;

/**
 * A helper for keeping track of message IDs.
 * <p>
 * According to the <a href="https://tools.ietf.org/html/rfc7252#section-4.4">CoAP spec</a>
 * <pre>
 * The same Message ID MUST NOT be reused (in communicating with the
   same endpoint) within the EXCHANGE_LIFETIME (Section 4.8.2).
   </pre>
 */
public class MessageIdTracker {

	private static final int TOTAL_NO_OF_MIDS = 1 << 16;
	private final long exchangeLifetime; // milliseconds
	private Map<Integer, Long> messageIds;
	private AtomicInteger counter;

	/**
	 * Creates a new tracker based on configuration values.
	 * <p>
	 * The following configuration values are used:
	 * <ul>
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#EXCHANGE_LIFETIME} - each
	 * message ID returned by <em>getNextMessageId</em> is marked as <em>in use</em> for this amount of
	 * time (ms).</li>
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#USE_RANDOM_MID_START} - if
	 * this value is {@code true} then the message IDs returned by <em>getNextMessageId</em> will start at a
	 * random index. Otherwise the first message ID returned will be {@code 0}.</li>
	 * </ul>
	 * 
	 * @param config the configuration to use.
	 */
	public MessageIdTracker(final NetworkConfig config) {
		exchangeLifetime = config.getLong(NetworkConfig.Keys.EXCHANGE_LIFETIME);
		boolean useRandomFirstMID = config.getBoolean(NetworkConfig.Keys.USE_RANDOM_MID_START);
		if (useRandomFirstMID) {
			counter = new AtomicInteger(new Random().nextInt(1 << 10));
		} else {
			counter = new AtomicInteger(0);
		}
		messageIds = new HashMap<>(TOTAL_NO_OF_MIDS);
	}

	/**
	 * Gets the next usable message ID.
	 * 
	 * @return a message ID or {@code -1} if all message IDs are in use currently.
	 */
	public int getNextMessageId() {
		int result = -1;
		boolean wrapped = false;
		synchronized (messageIds) {
			int startIdx = counter.get() % TOTAL_NO_OF_MIDS;
			while (result < 0 && !wrapped) {
				int idx = counter.getAndIncrement() % TOTAL_NO_OF_MIDS;
				Long earliestUsage = messageIds.get(idx);
				if (earliestUsage != null) {
					// MID has been used before
					if (System.currentTimeMillis() >= earliestUsage) {
						// message Id can be safely re-used
						result = idx;
						messageIds.put(idx, computeMidRetirementPeriod());
					}
				} else {
					// MID has not been used before
					result = idx;
					messageIds.put(idx, computeMidRetirementPeriod());
				}
				wrapped = counter.get() % TOTAL_NO_OF_MIDS == startIdx;
			}
		}
		return result;
	}

	private long computeMidRetirementPeriod() {
		return System.currentTimeMillis() + exchangeLifetime;
	}
}
