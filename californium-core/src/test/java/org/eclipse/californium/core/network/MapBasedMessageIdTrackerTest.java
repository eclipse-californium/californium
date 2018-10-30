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
 *    Achim Kraus (Bosch Software Innovations GmbH) - relax lifetime tests
 *    Achim Kraus (Bosch Software Innovations GmbH) - use waitForCondition
 *    Achim Kraus (Bosch Software Innovations GmbH) - rename MessageIdTrackerTest
 *                                                    to MapBasedMessageIdTrackerTest.
 ******************************************************************************/
package org.eclipse.californium.core.network;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;
import static org.eclipse.californium.TestTools.inRange;
import static org.eclipse.californium.core.network.MessageIdTracker.TOTAL_NO_OF_MIDS;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.CheckCondition;
import org.eclipse.californium.TestTools;
import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verifies that MessageIdTracker correctly marks MIDs as <em>in use</em>.
 *
 */
@Category(Small.class)
public class MapBasedMessageIdTrackerTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	private static final int INITIAL_MID = 0;

	@Test
	public void testGetNextMessageIdFailsIfAllMidsAreInUse() throws Exception {
		// GIVEN a tracker whose MIDs are all in use
		NetworkConfig config = network.createStandardTestConfig();
		MapBasedMessageIdTracker tracker = new MapBasedMessageIdTracker(INITIAL_MID, 0, TOTAL_NO_OF_MIDS, config);
		for (int i = 0; i < TOTAL_NO_OF_MIDS; i++) {
			tracker.getNextMessageId();
		}

		// WHEN retrieving the next message IDs from the tracker
		int mid = tracker.getNextMessageId();

		// THEN the returned MID is -1
		assertThat(mid, is(-1));
	}

	@Test
	public void testGetNextMessageIdFailsIfAllMidsInRangeAreInUse() throws Exception {
		// GIVEN a tracker whose MIDs are half in use
		NetworkConfig config = network.createStandardTestConfig();
		final int minMid = 1024;
		final int maxMid = 2048;
		final int rangeMid = maxMid - minMid;
		MapBasedMessageIdTracker tracker = new MapBasedMessageIdTracker(INITIAL_MID + minMid, minMid, maxMid, config);
		for (int i = 0; i < rangeMid; i++) {
			int mid = tracker.getNextMessageId();
			assertThat(mid, is(inRange(minMid, maxMid)));
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
		NetworkConfig config = network.createStandardTestConfig();
		config.setInt(NetworkConfig.Keys.EXCHANGE_LIFETIME, exchangeLifetime);
		final MapBasedMessageIdTracker tracker = new MapBasedMessageIdTracker(INITIAL_MID, 0, TOTAL_NO_OF_MIDS, config);

		// WHEN retrieving all message IDs from the tracker
		int firstMid = tracker.getNextMessageId();
		for (int i = 1; i < TOTAL_NO_OF_MIDS; i++) {
			tracker.getNextMessageId();
		}

		// THEN the first message ID is re-used after 
		// EXCHANGE_LIFETIME has expired
		exchangeLifetime += (exchangeLifetime >> 1); // a little longer
		final AtomicInteger mid = new AtomicInteger(-1);
		TestTools.waitForCondition(exchangeLifetime, 10, TimeUnit.MILLISECONDS, new CheckCondition() {

			@Override
			public boolean isFulFilled() throws IllegalStateException {
				mid.set(tracker.getNextMessageId());
				return 0 <= mid.get();
			}
		});
		assertThat(mid.get(), is(firstMid));
	}

	@Test
	public void testGetNextMessageIdRangeRollover() throws Exception {
		assertMessageIdRangeRollover(0, 65000);
		assertMessageIdRangeRollover(1000, 4000);
		assertMessageIdRangeRollover(65000, TOTAL_NO_OF_MIDS);
	}

	@Test
	public void testGetNextMessageIdAlignedRangeRollover() throws Exception {
		assertMessageIdRangeRollover(0, 8192);
		assertMessageIdRangeRollover(2048, 2048 * 3);
		assertMessageIdRangeRollover(TOTAL_NO_OF_MIDS / 2, TOTAL_NO_OF_MIDS);
	}

	public void assertMessageIdRangeRollover(int min, int max) throws Exception {
		// GIVEN a tracker with an EXCHANGE_LIFETIME of -1 (MID always expired)
		NetworkConfig config = network.createStandardTestConfig();
		config.setInt(NetworkConfig.Keys.EXCHANGE_LIFETIME, -1);
		final int range = max - min;
		final MapBasedMessageIdTracker tracker = new MapBasedMessageIdTracker(INITIAL_MID + min, min, max, config);
		final String msg = "not next mid in range[" + min + "..." + max + ") for ";

		// WHEN retrieving all message IDs from the tracker
		int lastMid = -1;
		int minMid = TOTAL_NO_OF_MIDS;
		int maxMid = -1;
		for (int i = 0; i < TOTAL_NO_OF_MIDS * 4; i++) {
			int nextMid = tracker.getNextMessageId();
			assertThat(nextMid, is(inRange(min, max)));
			if (-1 < lastMid) {
				int mid = ((lastMid - min + 1) % range) + min;
				assertThat(msg + lastMid, nextMid, is(mid));
			}
			if (minMid > nextMid) {
				minMid = nextMid;
			}
			if (maxMid < nextMid) {
				maxMid = nextMid;
			}
			lastMid = nextMid;
		}
		assertThat("minimun not reached", minMid, is(min));
		assertThat("maximun not reached", maxMid, is(max - 1));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testInvalidMidRange() throws Exception {
		NetworkConfig config = network.createStandardTestConfig();
		new MapBasedMessageIdTracker(10, 10, 10, config);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testInvalidMidRange2() throws Exception {
		NetworkConfig config = network.createStandardTestConfig();
		new MapBasedMessageIdTracker(10, 10, 9, config);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testInvalidinitialMid() throws Exception {
		NetworkConfig config = network.createStandardTestConfig();
		new MapBasedMessageIdTracker(10, 15, 20, config);
	}
}
