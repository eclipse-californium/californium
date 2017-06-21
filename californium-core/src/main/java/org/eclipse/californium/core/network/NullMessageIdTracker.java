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
	private AtomicInteger currentMID = new AtomicInteger();

	/**
	 * Creates a new tracker based on configuration values.
	 * 
	 * @param initialMid initial MID.
	 */
	public NullMessageIdTracker(int initialMid) {
		currentMID.set(initialMid);
	}

	/**
	 * Gets the next message ID.
	 * 
	 * @return a message ID.
	 */
	public int getNextMessageId() {
		// mask result to the 16 low bits
		return currentMID.getAndIncrement() & 0x0000FFFF;
	}
}
