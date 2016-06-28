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

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import org.eclipse.californium.core.network.config.NetworkConfig;
import org.junit.Before;
import org.junit.Test;


/**
 * Verifies that MessageIdTracker correctly marks MIDs as <em>in use</em>.
 *
 */
public class MessageIdTrackerTest {

	private static final int TOTAL_NO_OF_MIDS = 1 << 16;
	private NetworkConfig config;

	@Before
	public void setUp() {
		config = NetworkConfig.createStandardWithoutFile();
	}

	@Test
	public void testGetNextMessageIdFailsIfAllMidsAreInUse() throws Exception {
		// GIVEN a tracker whose MIDs are all in use
		MessageIdTracker tracker = new MessageIdTracker(config);
		for (int i = 0; i < TOTAL_NO_OF_MIDS; i++) {
			tracker.getNextMessageId();
		}

		// WHEN retrieving the next message IDs from the tracker
		int mid = tracker.getNextMessageId();

		// THEN the returned MID is -1
		assertThat(mid, is(-1));
	}

	@Test
	public void testGetNextMessageIdReusesIdAfterExchangeLifetime() throws Exception {
		// GIVEN a tracker with an EXCHANGE_LIFETIME of 100ms
		int exchangeLifetime = 100; // ms
		config.setInt(NetworkConfig.Keys.EXCHANGE_LIFETIME, exchangeLifetime);
		MessageIdTracker tracker = new MessageIdTracker(config);

		// WHEN retrieving all message IDs from the tracker
		int firstMid = tracker.getNextMessageId();
		long start = System.currentTimeMillis();
		for (int i = 1; i < TOTAL_NO_OF_MIDS; i++) {
			tracker.getNextMessageId();
		}

		// THEN the first message ID is re-used after EXCHANGE_LIFETIME has expired
		long timeElapsed = System.currentTimeMillis() - start;
		if (timeElapsed < exchangeLifetime) {
			Thread.sleep(exchangeLifetime - timeElapsed);
		}
		int mid = tracker.getNextMessageId();
		assertThat(mid, is(firstMid));
	}
}
