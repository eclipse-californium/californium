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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add test for find and 
 *                                                    evict on access
 *    Achim Kraus (Bosch Software Innovations GmbH) - add test for iterator 
 *                                                    and update last-access time
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.util.Iterator;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.elements.util.LeastRecentlyUsedCache.EvictionListener;
import org.eclipse.californium.elements.util.LeastRecentlyUsedCache.Predicate;
import org.junit.Test;

/**
 * Verifies behavior of {@code LeastRecentlyUsedCache}.
 *
 */
public class LeastRecentlyUsedCacheTest {

	private static final long THRESHOLD_MILLIS = 300;

	LeastRecentlyUsedCache<Integer, String> cache;

	@Test
	public void testGetFailsWhenExpired() throws InterruptedException {
		int capacity = 5;
		int numberOfSessions = 1;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfSessions);
		cache.setEvictingOnReadAccess(true);
		String eldest = cache.getEldest();
		Integer key = Integer.valueOf(eldest);
		assertNotNull(cache.get(key));
		Thread.sleep(THRESHOLD_MILLIS + 100);
		assertNull(cache.get(key));
	}

	@Test
	public void testGetSucceedsEvenExpired() throws InterruptedException {
		int capacity = 5;
		int numberOfSessions = 1;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfSessions);
		cache.setEvictingOnReadAccess(false);
		String eldest = cache.getEldest();
		Integer key = Integer.valueOf(eldest);
		assertNotNull(cache.get(key));
		Thread.sleep(THRESHOLD_MILLIS + 100);
		assertNotNull(cache.get(key));
	}

	@Test
	public void testUpdate() throws InterruptedException {
		int capacity = 5;
		int numberOfSessions = 1;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfSessions);
		cache.setEvictingOnReadAccess(true);
		cache.setUpdatingOnReadAccess(false);
		String eldest = cache.getEldest();
		Integer key = Integer.valueOf(eldest);
		Thread.sleep(THRESHOLD_MILLIS / 2);
		assertNotNull(cache.get(key));
		assertTrue(cache.update(key)); // update last-access time
		Thread.sleep((THRESHOLD_MILLIS / 2) + 100);
		assertNotNull(cache.get(key)); // not expired
		assertTrue(cache.update(key));
		Thread.sleep(THRESHOLD_MILLIS / 2);
		assertNotNull(cache.get(key)); // no update last-access time
		Thread.sleep((THRESHOLD_MILLIS / 2) + 100);
		assertNull(cache.get(key)); // expired!
	}

	@Test
	public void testIteratorWhenExpired() throws InterruptedException {
		int capacity = 5;
		int numberOfSessions = 5;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfSessions);
		cache.setEvictingOnReadAccess(true);
		Thread.sleep(THRESHOLD_MILLIS / 2);
		Iterator<String> valuesIterator = cache.valuesIterator();
		cache.setUpdatingOnReadAccess(true);
		assertNext(valuesIterator);
		cache.setUpdatingOnReadAccess(false);
		assertNext(valuesIterator);
		cache.setUpdatingOnReadAccess(true);
		assertNext(valuesIterator);
		cache.setUpdatingOnReadAccess(false);
		assertNext(valuesIterator);
		cache.setUpdatingOnReadAccess(true);
		assertNext(valuesIterator);
		Thread.sleep((THRESHOLD_MILLIS / 2) + 100);

		valuesIterator = cache.valuesIterator();
		assertNext(valuesIterator);
		assertNext(valuesIterator);
		assertNext(valuesIterator);
		assertFalse(valuesIterator.hasNext());
	}

	private void assertNext(Iterator<String> iterator) {
		String value = iterator.next();
		assertNotNull(value);
	}

	@Test
	public void testFindUniqueFailsWhenExpired() throws InterruptedException {
		int capacity = 5;
		int numberOfSessions = 3;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfSessions);
		cache.setEvictingOnReadAccess(true);
		final String eldest = cache.getEldest();
		Predicate<String> predicate = new Predicate<String>() {

			@Override
			public boolean accept(String value) {
				return eldest.equals(value);
			}

		};
		assertNotNull(cache.find(predicate));
		Thread.sleep(THRESHOLD_MILLIS + 100);
		assertNull(cache.find(predicate));
	}

	@Test
	public void testFindUniqueSucceedsEvenExpired() throws InterruptedException {
		int capacity = 5;
		int numberOfSessions = 3;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfSessions);
		cache.setEvictingOnReadAccess(false);
		final String eldest = cache.getEldest();
		Predicate<String> predicate = new Predicate<String>() {

			@Override
			public boolean accept(String value) {
				return eldest.equals(value);
			}

		};
		assertNotNull(cache.find(predicate));
		Thread.sleep(THRESHOLD_MILLIS + 100);
		assertNotNull(cache.find(predicate));
	}

	@Test
	public void testFindNoneUniqueSucceedsEvenFirstEvicted() throws InterruptedException {
		int capacity = 5;
		int numberOfSessions = 3;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfSessions);
		cache.setEvictingOnReadAccess(true);

		Thread.sleep(THRESHOLD_MILLIS / 2);

		// skip 1., update 2. by read
		SkipFirsts predicate = new SkipFirsts(1);
		String value;
		assertNotNull((value = cache.find(predicate, false)));

		// expires 1.
		Thread.sleep((THRESHOLD_MILLIS / 2) + 100);

		EvictionCounter counter = new EvictionCounter();
		cache.addEvictionListener(counter);
		// evict 1., select the 2.
		predicate = new SkipFirsts(0);
		assertThat(cache.find(predicate, false), is(value));
		assertThat(counter.count, is(1));
	}

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
		int capacity = 10;
		int numberOfSessions = 10;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS * 100, numberOfSessions);
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
			Integer key = i + 1000;
			String value = String.valueOf(key);
			assertTrue(cache.put(key, value));
		}
		assertThat(evicted.get(), is(noOfSessions - capacity));
		assertThat(cache.remainingCapacity(), is(0));
	}

	/**
	 * 
	 * @param capacity
	 * @param expirationThresholdMillis
	 * @param noOfEntries
	 */
	private void givenACacheWithEntries(int capacity, long expirationThresholdMillis, int noOfEntries) {
		cache = new LeastRecentlyUsedCache<>(capacity, 0);
		cache.setExpirationThreshold(expirationThresholdMillis, TimeUnit.MILLISECONDS);
		for (int i = 0; i < noOfEntries; i++) {
			cache.put(i, String.valueOf(i));
		}
	}

	private static class SkipFirsts implements Predicate<String> {

		private int skipCount;

		private SkipFirsts(int skipCount) {
			this.skipCount = skipCount;
		}

		@Override
		public boolean accept(String value) {
			return skipCount-- <= 0;
		}
	};

	private static class EvictionCounter implements EvictionListener<String> {

		private int count;

		@Override
		public void onEviction(String value) {
			++count;
		}
	};

}
