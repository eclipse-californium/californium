/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add test for find and
 *                                                    evict on access
 *    Achim Kraus (Bosch Software Innovations GmbH) - add test for iterator
 *                                                    and update last-access time
 *    Achim Kraus (Bosch Software Innovations GmbH) - use TimeAssume to relax failures
 *                                                    caused by delayed execution
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Iterator;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.elements.assume.TimeAssume;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.rule.TestTimeRule;
import org.eclipse.californium.elements.util.LeastRecentlyUsedCache.EvictionListener;
import org.eclipse.californium.elements.util.LeastRecentlyUsedCache.Predicate;
import org.eclipse.californium.elements.util.LeastRecentlyUsedCache.Timestamped;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verifies behavior of {@code LeastRecentlyUsedCache}.
 * @deprecated
 */
@Category(Small.class)
@Deprecated
public class LeastRecentlyUsedCacheTest {

	private static final long THRESHOLD_MILLIS = 300;

	@Rule
	public TestTimeRule time = new TestTimeRule();

	LeastRecentlyUsedCache<Integer, String> cache;

	@Test
	public void testGetFailsWhenExpired() throws InterruptedException {
		int capacity = 5;
		int numberOfEntries = 1;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfEntries);
		cache.setEvictingOnReadAccess(true);
		String eldest = cache.getEldest();
		Integer key = Integer.valueOf(eldest);
		assertThat(cache.get(key), is(notNullValue()));
		time.setTestTimeShift(THRESHOLD_MILLIS + 100, TimeUnit.MILLISECONDS);
		assertThat(cache.get(key), is(nullValue()));
	}

	@Test
	public void testGetSucceedsEvenExpired() throws InterruptedException {
		int capacity = 5;
		int numberOfEntries = 1;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfEntries);
		cache.setEvictingOnReadAccess(false);
		String eldest = cache.getEldest();
		Integer key = Integer.valueOf(eldest);
		assertThat(cache.get(key), is(notNullValue()));
		assertThat(cache.get(key), is(notNullValue()));
		time.setTestTimeShift(THRESHOLD_MILLIS + 100, TimeUnit.MILLISECONDS);
		assertThat(cache.get(key), is(notNullValue()));
	}

	@Test
	public void testUpdate() throws InterruptedException {
		int capacity = 5;
		int numberOfEntries = 1;
		TimeAssume assume = new TimeAssume(time);

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfEntries);
		cache.setEvictingOnReadAccess(true);
		cache.setUpdatingOnReadAccess(false);
		String eldest = cache.getEldest();
		Integer key = Integer.valueOf(eldest);
		time.setFixedTestTime(true);
		assume.sleep(THRESHOLD_MILLIS / 2);
		assertThat(cache.get(key), assume.inTime(is(notNullValue())));
		// update last-access time
		assertThat(cache.update(key), assume.inTime(is(true)));
		assume.sleep((THRESHOLD_MILLIS / 2) + 50);
		// not expired
		assertThat(cache.get(key), assume.inTime(is(notNullValue())));
		assertThat(cache.update(key), assume.inTime(is(true)));
		assume.sleep(THRESHOLD_MILLIS / 2);
		// no update last-access time
		assertThat(cache.get(key), assume.inTime(is(notNullValue())));
		assume.sleep((THRESHOLD_MILLIS / 2) + 50);
		// expired!
		assertThat(cache.get(key), assume.inTime(is(nullValue())));
	}

	@Test
	public void testRemoveExpiredEntriesWithLimit() throws InterruptedException {
		int capacity = 10;
		int numberOfEntries = 10;
		TimeAssume assume = new TimeAssume(time);

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfEntries);
		cache.setEvictingOnReadAccess(false);
		cache.setUpdatingOnReadAccess(true);
		time.setFixedTestTime(true);
		assume.sleep(THRESHOLD_MILLIS / 2);
		// update some entries
		assertThat(cache.get(2), assume.inTime(is(notNullValue())));
		assertThat(cache.get(8), assume.inTime(is(notNullValue())));
		assertThat(cache.get(5), assume.inTime(is(notNullValue())));

		// expire not updated entries
		assume.sleep((THRESHOLD_MILLIS / 2) + 50);
		// remove with limit
		assertThat(cache.removeExpiredEntries(3), is(3));
		// remove with exceeded limit
		assertThat(cache.removeExpiredEntries(10), is(4));
		// remove without expired entries
		assertThat(cache.removeExpiredEntries(1), is(0));
		// expires all
		assume.sleep((THRESHOLD_MILLIS / 2) + 50);
		// remove with exceeded limit
		assertThat(cache.removeExpiredEntries(10), is(3));
		// remove without expired entries
		assertThat(cache.removeExpiredEntries(1), is(0));
	}

	@Test
	public void testRemoveExpiredEntriesWithoutLimit() throws InterruptedException {
		int capacity = 10;
		int numberOfEntries = 10;
		TimeAssume assume = new TimeAssume(time);

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfEntries);
		cache.setEvictingOnReadAccess(false);
		cache.setUpdatingOnReadAccess(true);
		time.setFixedTestTime(true);
		assume.sleep(THRESHOLD_MILLIS / 2);
		// update some entries
		assertThat(cache.get(2), assume.inTime(is(notNullValue())));
		assertThat(cache.get(8), assume.inTime(is(notNullValue())));
		assertThat(cache.get(5), assume.inTime(is(notNullValue())));

		// expire not updated entries
		assume.sleep((THRESHOLD_MILLIS / 2) + 50);
		// remove all
		assertThat(cache.removeExpiredEntries(0), is(7));
		// remove without expired entries
		assertThat(cache.removeExpiredEntries(0), is(0));
		// expires all
		assume.sleep((THRESHOLD_MILLIS / 2) + 50);
		// remove all
		assertThat(cache.removeExpiredEntries(0), is(3));
		// remove without expired entries
		assertThat(cache.removeExpiredEntries(0), is(0));
	}

	@Test
	public void testIteratorWhenExpired() throws InterruptedException {
		int capacity = 5;
		int numberOfEntries = 5;
		TimeAssume assume = new TimeAssume(time);

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfEntries);
		cache.setEvictingOnReadAccess(true);
		time.setFixedTestTime(true);
		assume.sleep(THRESHOLD_MILLIS / 2);
		Iterator<String> valuesIterator = cache.valuesIterator();
		cache.setUpdatingOnReadAccess(true);
		assertNext(valuesIterator, assume);
		cache.setUpdatingOnReadAccess(false);
		assertNext(valuesIterator, assume);
		cache.setUpdatingOnReadAccess(true);
		assertNext(valuesIterator, assume);
		cache.setUpdatingOnReadAccess(false);
		assertNext(valuesIterator, assume);
		cache.setUpdatingOnReadAccess(true);
		assertNext(valuesIterator, assume);
		assume.sleep((THRESHOLD_MILLIS / 2) + 20, 100);

		valuesIterator = cache.valuesIterator();
		assertNext(valuesIterator, assume);
		assertNext(valuesIterator, assume);
		assertNext(valuesIterator, assume);
		assertFalse(valuesIterator.hasNext());
	}

	@Test
	public void testIteratorOnRemove() throws InterruptedException {
		int capacity = 5;
		int numberOfEntries = 5;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfEntries);
		cache.setEvictingOnReadAccess(false);
		Iterator<String> valuesIterator = cache.valuesIterator();
		cache.remove(2);
		cache.remove(4);
		assertThat(valuesIterator.next(), is(notNullValue()));
		assertThat(valuesIterator.next(), is(notNullValue()));
		assertThat(valuesIterator.next(), is(notNullValue()));
		assertThat(valuesIterator.hasNext(), is(false));
	}

	private void assertNext(Iterator<String> iterator, TimeAssume assume) {
		String value = iterator.hasNext() ? iterator.next() : null;
		assertThat(value, assume.inTime(is(notNullValue())));
	}

	@Test
	public void testIteratorTimestamped() throws InterruptedException {
		int capacity = 5;
		int numberOfEntries = 5;

		LeastRecentlyUsedCache<Integer, String> clone = new LeastRecentlyUsedCache<>(3, 0);

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfEntries);
		cache.setEvictingOnReadAccess(false);
		cache.remove(2);

		assertOrder(cache, true);

		Iterator<LeastRecentlyUsedCache.Timestamped<String>> valuesIterator = cache.timestampedIterator();
		LeastRecentlyUsedCache.Timestamped<String> timestamped = valuesIterator.next();
		assertThat("missing 1.", timestamped, is(notNullValue()));
		LeastRecentlyUsedCache.Timestamped<String> first = timestamped;
		int id = capacity + 1;
		assertTrue(clone.put(id++, timestamped.getValue(), timestamped.getLastUpdate()));
		timestamped = valuesIterator.next();
		assertThat("missing 2.", timestamped, is(notNullValue()));
		assertTrue(clone.put(id++, timestamped.getValue(), timestamped.getLastUpdate()));
		timestamped = valuesIterator.next();
		assertThat("missing 3.", timestamped, is(notNullValue()));
		assertTrue(clone.put(id++, timestamped.getValue(), timestamped.getLastUpdate()));
		timestamped = valuesIterator.next();
		assertThat("missing 4.", timestamped, is(notNullValue()));

		assertThat(clone.size(), is(3));

		assertOrder(clone, false);

		// succeed with earlier time
		assertTrue(clone.put(id++, first.getValue(), first.getLastUpdate()));
		// succeed with newer time
		assertTrue(clone.put(id++, timestamped.getValue(), timestamped.getLastUpdate()));
		// fail with too earlier time
		assertFalse(clone.put(id++, first.getValue(), first.getLastUpdate()));

		assertThat(clone.size(), is(3));

		assertOrder(clone, false);
	}

	@Test
	public void testPutNewTimestamped() throws InterruptedException {
		int capacity = 5;
		int numberOfEntries = 5;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfEntries);
		cache.setEvictingOnReadAccess(false);
		cache.setUpdatingOnReadAccess(false);
		time.addTestTimeShift(THRESHOLD_MILLIS * 2, TimeUnit.MILLISECONDS);
		Timestamped<String> first = cache.getTimestamped(0);
		long time = first.getLastUpdate();
		int id = capacity + 1;

		// replace eldest by same time
		assertTrue(cache.put(id, "new1", time));
		// fails, too old
		assertFalse(cache.put(id + 1, "new2", time - 1));
		// replace eldest by newer
		assertTrue(cache.put(id + 1, "new3", time + 1));
		assertOrder(cache, false);

		assertThat(cache.getTimestamped(0), is(nullValue()));
		assertThat(cache.getTimestamped(id), is(nullValue()));
		assertThat(cache.getTimestamped(id + 1), is(new Timestamped<String>("new3", time + 1)));

		id += 2;
		Timestamped<String> middle = cache.getTimestamped(3);

		assertTrue(cache.put(id, "new4", middle.getLastUpdate()));
		assertOrder(cache, false);
		assertTrue(cache.put(id + 1, "new5", middle.getLastUpdate() - 1));
		assertOrder(cache, false);
		assertTrue(cache.put(id + 2, "new6", middle.getLastUpdate() + 1));
		assertOrder(cache, false);

		assertThat(cache.getTimestamped(id), is(new Timestamped<String>("new4", middle.getLastUpdate())));
		assertThat(cache.getTimestamped(id + 1), is(new Timestamped<String>("new5", middle.getLastUpdate() - 1)));
		assertThat(cache.getTimestamped(id + 2), is(new Timestamped<String>("new6", middle.getLastUpdate() + 1)));

		id += 3;
		Timestamped<String> last = cache.getTimestamped(4);
		assertTrue(cache.put(id, "new7", last.getLastUpdate()));
		assertOrder(cache, false);
		assertTrue(cache.put(id + 1, "new8", last.getLastUpdate() - 1));
		assertOrder(cache, false);
		assertTrue(cache.put(id + 2, "new9", last.getLastUpdate() + 1));
		assertOrder(cache, false);

		assertThat(cache.getTimestamped(id), is(new Timestamped<String>("new7", last.getLastUpdate())));
		assertThat(cache.getTimestamped(id + 1), is(new Timestamped<String>("new8", last.getLastUpdate() - 1)));
		assertThat(cache.getTimestamped(id + 2), is(new Timestamped<String>("new9", last.getLastUpdate() + 1)));

	}

	@Test
	public void testPutUpdatedTimestamped() throws InterruptedException {
		int capacity = 5;
		int numberOfEntries = 5;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfEntries);
		cache.setEvictingOnReadAccess(false);
		cache.setUpdatingOnReadAccess(false);
		time.addTestTimeShift(THRESHOLD_MILLIS * 2, TimeUnit.MILLISECONDS);
		Timestamped<String> first = cache.getTimestamped(0);
		long time = first.getLastUpdate();

		// replace eldest by same time
		assertTrue(cache.put(0, "new1", time));
		// replace eldest by earlier time
		assertTrue(cache.put(0, "new2", time - 1));
		// replace eldest by newer
		assertTrue(cache.put(0, "new3", time + 1));
		assertOrder(cache, false);

		assertThat(cache.getTimestamped(0), is(new Timestamped<String>("new3", time + 1)));

		Timestamped<String> middle = cache.getTimestamped(3);

		assertTrue(cache.put(3, "new4", middle.getLastUpdate()));
		assertOrder(cache, false);
		assertTrue(cache.put(3, "new5", middle.getLastUpdate() - 1));
		assertOrder(cache, false);
		assertTrue(cache.put(3, "new6", middle.getLastUpdate() + 1));
		assertOrder(cache, false);

		assertThat(cache.getTimestamped(3), is(new Timestamped<String>("new6", middle.getLastUpdate() + 1)));

		Timestamped<String> last = cache.getTimestamped(4);
		assertTrue(cache.put(4, "new7", last.getLastUpdate()));
		assertOrder(cache, false);
		assertTrue(cache.put(4, "new8", last.getLastUpdate() - 1));
		assertOrder(cache, false);
		assertTrue(cache.put(4, "new9", last.getLastUpdate() + 1));
		assertOrder(cache, false);

		assertThat(cache.getTimestamped(4), is(new Timestamped<String>("new9", last.getLastUpdate() + 1)));

	}

	@Test
	public void testFindUniqueFailsWhenExpired() throws InterruptedException {
		int capacity = 5;
		int numberOfEntries = 3;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfEntries);
		cache.setEvictingOnReadAccess(true);
		final String eldest = cache.getEldest();
		Predicate<String> predicate = new Predicate<String>() {

			@Override
			public boolean accept(String value) {
				return eldest.equals(value);
			}

		};
		assertThat(cache.find(predicate), is(notNullValue()));
		time.setTestTimeShift(THRESHOLD_MILLIS + 100, TimeUnit.MILLISECONDS);
		assertThat(cache.find(predicate), is(nullValue()));
	}

	@Test
	public void testFindUniqueSucceedsEvenExpired() throws InterruptedException {
		int capacity = 5;
		int numberOfEntries = 3;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfEntries);
		cache.setEvictingOnReadAccess(false);
		final String eldest = cache.getEldest();
		Predicate<String> predicate = new Predicate<String>() {

			@Override
			public boolean accept(String value) {
				return eldest.equals(value);
			}

		};
		assertThat(cache.find(predicate), is(notNullValue()));
		time.setTestTimeShift(THRESHOLD_MILLIS + 100, TimeUnit.MILLISECONDS);
		assertThat(cache.find(predicate), is(notNullValue()));
	}

	@Test
	public void testFindNoneUniqueSucceedsEvenFirstEvicted() throws InterruptedException {
		int capacity = 5;
		int numberOfEntries = 3;
		TimeAssume assume = new TimeAssume(time);

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfEntries);
		cache.setEvictingOnReadAccess(true);
		time.setFixedTestTime(true);

		assume.sleep(THRESHOLD_MILLIS / 2);

		// skip 1., update 2. by read
		SkipFirsts predicate = new SkipFirsts(1);
		String value;
		assertThat((value = cache.find(predicate, false)), assume.inTime(is(notNullValue())));

		// expires 1.
		assume.sleep((THRESHOLD_MILLIS / 2) + 25);

		EvictionCounter counter = new EvictionCounter();
		cache.addEvictionListener(counter);
		// evict 1., select the 2.
		predicate = new SkipFirsts(0);
		assertThat(cache.find(predicate, false), assume.inTime(is(value)));
		assertThat(counter.count, is(1));
	}

	@Test
	public void testStoreAddsNewValueIfCapacityNotReached() {
		int capacity = 10;
		int numberOfEntries = 9;

		givenACacheWithEntries(capacity, 0L, numberOfEntries);
		assertThat(cache.remainingCapacity(), is(1));
		String eldest = cache.getEldest();

		String newValue = "50";
		assertTrue(cache.put(50, newValue));
		assertThat(cache.get(Integer.valueOf(eldest)), is(notNullValue()));
		assertThat(cache.remainingCapacity(), is(0));
	}

	@Test
	public void testStoreEvictsEldestStaleEntry() {
		int capacity = 10;
		int numberOfEntries = 10;

		givenACacheWithEntries(capacity, 0L, numberOfEntries);
		assertThat(cache.remainingCapacity(), is(0));
		String eldest = cache.getEldest();

		String newValue = "50";
		assertTrue(cache.put(Integer.valueOf(newValue), newValue));
		assertThat(cache.get(Integer.valueOf(eldest)), is(nullValue()));
	}

	@Test
	public void testStoreFailsIfCapacityReached() {
		int capacity = 10;
		int numberOfEntries = 10;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS * 100, numberOfEntries);
		assertThat(cache.remainingCapacity(), is(0));
		String eldest = cache.getEldest();

		String newValue = "50";
		Integer key = Integer.valueOf(newValue);
		assertFalse(cache.put(key, newValue));
		assertThat(cache.get(key), is(nullValue()));
		assertThat(cache.get(Integer.valueOf(eldest)), is(notNullValue()));
	}

	@Test
	public void testContinuousEviction() {
		int capacity = 10;
		int numberOfEntries = 0;

		givenACacheWithEntries(capacity, 0L, numberOfEntries);
		assertThat(cache.remainingCapacity(), is(capacity));
		final AtomicInteger evicted = new AtomicInteger(0);

		cache.addEvictionListener(new EvictionListener<String>() {

			@Override
			public void onEviction(String evictedSession) {
				evicted.incrementAndGet();
			}
		});

		numberOfEntries = 1000;
		for (int i = 0; i < numberOfEntries; i++) {
			Integer key = i + 1000;
			String value = String.valueOf(key);
			assertTrue(cache.put(key, value));
		}
		assertThat(evicted.get(), is(numberOfEntries - capacity));
		assertThat(cache.remainingCapacity(), is(0));
	}

	private static void assertOrder(LeastRecentlyUsedCache<Integer, String> cache, boolean print) {
		int index = 0;
		Iterator<Timestamped<String>> valuesIterator = cache.timestampedIterator();
		Long time = null;
		long last = 0;
		while (valuesIterator.hasNext()) {
			Timestamped<String> entry = valuesIterator.next();
			if (time == null) {
				last = entry.getLastUpdate();
				time = last;
				if (print) {
					System.out.println("start: " + time);
				}
			} else {
				if (print) {
					long diff = entry.getLastUpdate() - time;
					System.out.println(entry.getValue() + ": " + diff);
				}
				long now = entry.getLastUpdate();
				assertThat("order violation position " + index + " , value " + entry.getValue(), now,
						is(greaterThanOrEqualTo(last)));
				last = now;
			}
			++index;
		}
	}

	/**
	 * 
	 * @param capacity
	 * @param expirationThresholdMillis
	 * @param numberOfEntries
	 */
	private void givenACacheWithEntries(int capacity, long expirationThresholdMillis, int numberOfEntries) {
		cache = new LeastRecentlyUsedCache<>(capacity, capacity, expirationThresholdMillis, TimeUnit.MILLISECONDS);
		for (int i = 0; i < numberOfEntries; i++) {
			cache.put(i, Integer.toString(i));
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
