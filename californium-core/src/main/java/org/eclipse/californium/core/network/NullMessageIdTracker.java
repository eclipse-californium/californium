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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add mid range to
 *                                                    support multicast
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.util.concurrent.atomic.AtomicInteger;

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
 * This implementation just increments the MIDs and ignores the RFC7252, 4.8.2.
 */
public class NullMessageIdTracker implements MessageIdTracker {

	/**
	 * Current MID.
	 */
	private final AtomicInteger currentMID = new AtomicInteger();

	private final int min;
	private final int range;

	/**
	 * Creates a new tracker based on configuration values.
	 * 
	 * @param initialMid initial MID.
	 * @param minMid minimal MID (inclusive).
	 * @param maxMid maximal MID (exclusive).
	 */
	public NullMessageIdTracker(int initialMid, int minMid, int maxMid) {
		if (minMid >= maxMid) {
			throw new IllegalArgumentException("max. MID " + maxMid + " must be larger than min. MID " + minMid + "!");
		}
		if (initialMid < minMid || maxMid <= initialMid) {
			throw new IllegalArgumentException(
					"initial MID " + initialMid + " must be in range [" + minMid + "-" + maxMid + ")!");
		}
		currentMID.set(initialMid - minMid);
		this.min = minMid;
		this.range = maxMid - minMid;
	}

	/**
	 * Gets the next message ID.
	 * 
	 * @return a message ID.
	 */
	public int getNextMessageId() {
		int mid = currentMID.getAndIncrement();
		int result = mid % range;
		if (result == (range - 1)) {
			currentMID.addAndGet(-range);
		}
		return min + mid;
	}
}
