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
 *                                 derived from MessageIdTrackerTest
 ******************************************************************************/
package org.eclipse.californium.core.network;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;
import static org.eclipse.californium.core.network.MessageIdTracker.TOTAL_NO_OF_MIDS;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.CheckCondition;
import org.eclipse.californium.TestTools;
import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verifies that GroupedMessageIdTracker correctly marks MIDs as <em>in
 * use</em>.
 */
@Category(Small.class)
public class GroupedMessageIdTrackerTest {

	private static final int INITIAL_MID = 0;

	@Test
	public void testGetNextMessageIdFailsIfAllMidsAreInUse() throws Exception {
		// GIVEN a tracker whose MIDs are half in use
		NetworkConfig config = NetworkConfig.createStandardWithoutFile();
		GroupedMessageIdTracker tracker = new GroupedMessageIdTracker(INITIAL_MID, config);
		for (int i = 0; i < TOTAL_NO_OF_MIDS / 2; i++) {
			int mid = tracker.getNextMessageId();
			assertThat(mid, is(not(-1)));
		}
		// THEN using the complete other half should not be possible
		for (int i = 0; i < TOTAL_NO_OF_MIDS / 2; i++) {
			int mid = tracker.getNextMessageId();
			if (0 > mid)
				return;
		}
		fail("mids should run out.");
	}

	@Test
	public void testGetNextMessageIdReusesIdAfterExchangeLifetime() throws Exception {
		// GIVEN a tracker with an EXCHANGE_LIFETIME of 100ms
		int exchangeLifetime = 100; // ms
		NetworkConfig config = NetworkConfig.createStandardWithoutFile().setInt(NetworkConfig.Keys.EXCHANGE_LIFETIME,
				exchangeLifetime);
		final GroupedMessageIdTracker tracker = new GroupedMessageIdTracker(INITIAL_MID, config);
		int groupSize = tracker.getGroupSize();

		// WHEN retrieving all message IDs from the tracker
		long start = System.nanoTime();
		for (int i = 1; i < TOTAL_NO_OF_MIDS; i++) {
			int nextMid = tracker.getNextMessageId();
			if (nextMid < 0)
				break;
		}

		// THEN the first message ID is re-used after EXCHANGE_LIFETIME has
		// expired
		exchangeLifetime += (exchangeLifetime >> 1); // a little longer
		long timeLeft = exchangeLifetime - TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
		if (100 > timeLeft) {
			timeLeft = 100;
		}

		final AtomicInteger mid = new AtomicInteger(-1);
		TestTools.waitForCondition(timeLeft, 100, TimeUnit.MILLISECONDS, new CheckCondition() {

			@Override
			public boolean isFulFilled() throws IllegalStateException {
				mid.set(tracker.getNextMessageId());
				return 0 <= mid.get();
			}
		});
		assertThat(mid.get(), is(not(-1)));

		for (int i = 1; i < groupSize; i++) {
			int nextMid = tracker.getNextMessageId();
			assertThat(nextMid, is(not(-1)));
		}
	}
}
