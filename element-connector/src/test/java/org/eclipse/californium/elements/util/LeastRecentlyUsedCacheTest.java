/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.elements.util.LeastRecentlyUsedCache.EvictionListener;
import org.junit.Test;

/**
 * Verifies behavior of {@code LeastRecentlyUsedCache}.
 *
 */
public class LeastRecentlyUsedCacheTest {

	LeastRecentlyUsedCache<Integer, String> cache;

	@Test
	public void testStoreAddsNewValueIfCapacityNotReached() {
		int capacity = 10;

		givenACacheWithEntries(capacity, 0L, capacity - 1);
		assertThat(cache.remainingCapacity(), is(1));
		String eldest = cache.getEldest();

		String newValue = "50";
		assertTrue(cache.put(50, newValue));
		assertNotNull(cache.get(Integer.valueOf(eldest)));
		assertThat(cache.remainingCapacity(), is(0));
	}

	@Test
	public void testStoreEvictsEldestStaleEntry() {
		int capacity = 10;

		givenACacheWithEntries(capacity, 0L, capacity);
		assertThat(cache.remainingCapacity(), is(0));
		String eldest = cache.getEldest();

		String newValue = "50";
		assertTrue(cache.put(Integer.valueOf(newValue), newValue));
		assertNull(cache.get(Integer.valueOf(eldest)));
	}

	@Test
	public void testStoreFailsIfCapacityReached() {
		long threshold =  10; // seconds
		int capacity = 10;
		int numberOfSessions = 10;

		givenACacheWithEntries(capacity, threshold, numberOfSessions);
		assertThat(cache.remainingCapacity(), is(0));
		String eldest = cache.getEldest();

		String newValue = "50";
		Integer key = Integer.valueOf(newValue);
		assertFalse(cache.put(key, newValue));
		assertNull(cache.get(key));
		assertNotNull(cache.get(Integer.valueOf(eldest)));
	}

	@Test
	public void testContinuousEviction() {
		int capacity = 10;

		givenACacheWithEntries(capacity, 0L, 0);
		assertThat(cache.remainingCapacity(), is(capacity));
		final AtomicInteger evicted = new AtomicInteger(0);

		cache.addEvictionListener(new EvictionListener<String>() {

			@Override
			public void onEviction(String evictedSession) {
				evicted.incrementAndGet();
			}
		});

		int noOfSessions = 1000;
		for (int i = 0; i < noOfSessions; i++) {
			Integer key = i +1000;
			String value = String.valueOf(key);
			assertTrue(cache.put(key, value));
		}
		assertThat(evicted.get(), is(noOfSessions - capacity));
		assertThat(cache.remainingCapacity(), is(0));
	}

	/**
	 * 
	 * @param capacity
	 * @param expirationThreshold
	 * @param noOfEntries
	 */
	private void givenACacheWithEntries(int capacity, long expirationThreshold, int noOfEntries) {
		cache = new LeastRecentlyUsedCache<>(capacity, expirationThreshold);

		for (int i = 0; i < noOfEntries; i++) {
			cache.put(i, String.valueOf(i));
		}
	}
}
