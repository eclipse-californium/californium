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
import static org.eclipse.californium.core.network.MessageIdTracker.TOTAL_NO_OF_MIDS;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.CheckCondition;
import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.junit.Test;

/**
 * Verifies that MessageIdTracker correctly marks MIDs as <em>in use</em>.
 *
 */
public class MapBasedMessageIdTrackerTest {

	@Test
	public void testGetNextMessageIdFailsIfAllMidsAreInUse() throws Exception {
		// GIVEN a tracker whose MIDs are all in use
		NetworkConfig config = NetworkConfig.createStandardWithoutFile();
		MapBasedMessageIdTracker tracker = new MapBasedMessageIdTracker(0, config);
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
		NetworkConfig config = NetworkConfig.createStandardWithoutFile().setInt(NetworkConfig.Keys.EXCHANGE_LIFETIME,
				exchangeLifetime);
		final MapBasedMessageIdTracker tracker = new MapBasedMessageIdTracker(0, config);

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
}
