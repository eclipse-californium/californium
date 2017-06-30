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

import org.eclipse.californium.category.Small;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verifies that NullMessageIdTracker correctly generates MIDs.
 */
@Category(Small.class)
public class NullMessageIdTrackerTest {

	@Test
	public void testGetNextMessage() {
		NullMessageIdTracker tracker = new NullMessageIdTracker(0);
		for (int count = 0; count < TOTAL_NO_OF_MIDS * 16; ++count) {
			int mid = tracker.getNextMessageId();
			assertThat(mid, is(count % TOTAL_NO_OF_MIDS));
		}
	}

	@Test
	public void testGetNextMessageOverflow() {
		// GIVEN, a MessageIdTracker initialized with a large initial MID
		NullMessageIdTracker tracker = new NullMessageIdTracker(Integer.MAX_VALUE);
		int mid = tracker.getNextMessageId();
		assertThat(mid, is(TOTAL_NO_OF_MIDS - 1));
		mid = tracker.getNextMessageId();
		assertThat(mid, is(0));
		mid = tracker.getNextMessageId();
		assertThat(mid, is(1));
	}
}
