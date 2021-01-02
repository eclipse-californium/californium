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
 *                                 derived from MessageIdTrackerTest
 ******************************************************************************/
package org.eclipse.californium.core.network;

import static org.eclipse.californium.core.network.MessageIdTracker.TOTAL_NO_OF_MIDS;
import static org.eclipse.californium.elements.util.TestConditionTools.inRange;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;

import java.util.concurrent.TimeUnit;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.ExpectedExceptionWrapper;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.ExpectedException;

/**
 * Verifies that GroupedMessageIdTracker correctly marks MIDs as <em>in
 * use</em>.
 */
@Category(Small.class)
public class GroupedMessageIdTrackerTest {

	private static final int INITIAL_MID = 0;

	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public ExpectedException exception = ExpectedExceptionWrapper.none();

	@Test
	public void testGetNextMessageIdFailsIfAllMidsAreInUse() throws Exception {
		// GIVEN a tracker whose MIDs are half in use
		NetworkConfig config = network.createStandardTestConfig();
		GroupedMessageIdTracker tracker = new GroupedMessageIdTracker(INITIAL_MID, 0, TOTAL_NO_OF_MIDS, config);
		for (int i = 0; i < TOTAL_NO_OF_MIDS / 2; i++) {
			int mid = tracker.getNextMessageId();
			assertThat(mid, is(not(-1)));
		}
		// THEN using the complete other half should not be possible
		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("No MID available, all"));

		for (int i = 0; i < TOTAL_NO_OF_MIDS / 2; i++) {
			int mid = tracker.getNextMessageId();
			assertThat(mid, is(inRange(0, TOTAL_NO_OF_MIDS)));
		}
	}

	@Test
	public void testGetNextMessageIdFailsIfAllMidsInRangeAreInUse() throws Exception {
		// GIVEN a tracker whose MIDs are half in use
		NetworkConfig config = network.createStandardTestConfig();
		final int minMid = 1024;
		final int maxMid = 2048;
		final int rangeMid = maxMid - minMid;
		GroupedMessageIdTracker tracker = new GroupedMessageIdTracker(INITIAL_MID + minMid, minMid, maxMid, config);
		for (int i = 0; i < rangeMid / 2; i++) {
			int mid = tracker.getNextMessageId();
			assertThat(mid, is(inRange(minMid, maxMid)));
		}
		// THEN using the complete other half should not be possible
		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("No MID available, all"));

		for (int i = 0; i < rangeMid / 2; i++) {
			int mid = tracker.getNextMessageId();
			assertThat(mid, is(inRange(minMid, maxMid)));
		}
	}

	@Test
	public void testGetNextMessageIdReusesIdAfterExchangeLifetime() throws Exception {
		// GIVEN a tracker with an EXCHANGE_LIFETIME of 100ms
		int exchangeLifetime = 100; // ms
		NetworkConfig config = network.createStandardTestConfig();
		config.setInt(NetworkConfig.Keys.EXCHANGE_LIFETIME, exchangeLifetime);
		final GroupedMessageIdTracker tracker = new GroupedMessageIdTracker(INITIAL_MID, 0, TOTAL_NO_OF_MIDS, config);
		int groupSize = tracker.getGroupSize();

		// WHEN retrieving all message IDs from the tracker
		long start = System.nanoTime();
		try {
			for (int i = 1; i < TOTAL_NO_OF_MIDS; i++) {
				int mid = tracker.getNextMessageId();
				assertThat(mid, is(inRange(0, TOTAL_NO_OF_MIDS)));
			}
			fail("mids expected to run out.");
		} catch (IllegalStateException ex) {
			assertThat(ex.getMessage(), containsString("No MID available, all"));
		}

		// THEN the first message ID is re-used after EXCHANGE_LIFETIME has
		// expired
		exchangeLifetime += (exchangeLifetime >> 1); // a little longer
		long timeLeft = exchangeLifetime - TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
		if (100 > timeLeft) {
			timeLeft = 100;
		}

		int mid = TestTools.waitForNextMID(tracker, inRange(0, TOTAL_NO_OF_MIDS), timeLeft, 50 ,TimeUnit.MILLISECONDS);
		assertThat(mid, is(inRange(0, TOTAL_NO_OF_MIDS)));

		for (int i = 1; i < groupSize; i++) {
			int nextMid = tracker.getNextMessageId();
			assertThat(nextMid, is(inRange(0, TOTAL_NO_OF_MIDS)));
		}
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
		final GroupedMessageIdTracker tracker = new GroupedMessageIdTracker(INITIAL_MID + min, min, max, config);
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
		new GroupedMessageIdTracker(10, 10, 10, config);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testInvalidMidRange2() throws Exception {
		NetworkConfig config = network.createStandardTestConfig();
		new GroupedMessageIdTracker(10, 10, 9, config);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testInvalidinitialMid() throws Exception {
		NetworkConfig config = network.createStandardTestConfig();
		new GroupedMessageIdTracker(10, 15, 20, config);
	}
}
