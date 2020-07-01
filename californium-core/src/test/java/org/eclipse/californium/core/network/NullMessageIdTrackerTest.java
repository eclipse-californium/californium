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
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verifies that NullMessageIdTracker correctly generates MIDs.
 */
@Category(Small.class)
public class NullMessageIdTrackerTest {
	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	private static final int INITIAL_MID = 0;

	@Test
	public void testGetNextMessage() {
		NullMessageIdTracker tracker = new NullMessageIdTracker(INITIAL_MID, 0, TOTAL_NO_OF_MIDS);
		for (int count = 0; count < TOTAL_NO_OF_MIDS * 16; ++count) {
			int mid = tracker.getNextMessageId();
			assertThat(mid, is(count % TOTAL_NO_OF_MIDS));
		}
	}

	@Test
	public void testGetNextMessageInRange() {
		final int minMid = 1024;
		final int maxMid = 2048;
		final int rangeMid = maxMid - minMid;
		NullMessageIdTracker tracker = new NullMessageIdTracker(INITIAL_MID + minMid, minMid, maxMid);
		for (int count = 0; count < rangeMid * 16; ++count) {
			int mid = tracker.getNextMessageId();
			assertThat(mid, is(inRange(minMid, maxMid)));
		}
	}

	@Test
	public void testGetNextMessageOverflow() {
		// GIVEN, a MessageIdTracker initialized with a large initial MID
		NullMessageIdTracker tracker = new NullMessageIdTracker(TOTAL_NO_OF_MIDS - 1, 0, TOTAL_NO_OF_MIDS);
		int mid = tracker.getNextMessageId();
		assertThat(mid, is(TOTAL_NO_OF_MIDS - 1));
		mid = tracker.getNextMessageId();
		assertThat(mid, is(0));
		mid = tracker.getNextMessageId();
		assertThat(mid, is(1));
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
		final int range = max - min;
		final NullMessageIdTracker tracker = new NullMessageIdTracker(INITIAL_MID + min, min, max);
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
		new NullMessageIdTracker(10, 10, 10);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testInvalidMidRange2() throws Exception {
		new NullMessageIdTracker(10, 10, 9);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testInvalidinitialMid() throws Exception {
		new NullMessageIdTracker(10, 15, 20);
	}
}
