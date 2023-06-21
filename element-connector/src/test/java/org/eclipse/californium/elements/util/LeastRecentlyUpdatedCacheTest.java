/*******************************************************************************
 * Copyright (c) 2022 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import static org.eclipse.californium.elements.util.TestConditionTools.inRange;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;

import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.rule.TestTimeRule;
import org.eclipse.californium.elements.util.LeastRecentlyUpdatedCache.Timestamped;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verifies behavior of {@code LeastRecentlyUsedCache}.
 *
 */
@Category(Small.class)
public class LeastRecentlyUpdatedCacheTest {

	private static final long THRESHOLD_MILLIS = 300;

	@Rule
	public TestTimeRule time = new TestTimeRule();

	LeastRecentlyUpdatedCache<Integer, String> cache;

	@Test
	public void testGetFailsWhenExpired() throws InterruptedException {
		int capacity = 5;
		int numberOfEntries = 1;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfEntries);
		cache.setHideStaleValues(true);
		String eldest = cache.getEldest();
		Integer key = Integer.valueOf(eldest);
		assertThat(cache.get(key), is(notNullValue()));
		time.setTestTimeShift(THRESHOLD_MILLIS + 100, TimeUnit.MILLISECONDS);
		assertThat(cache.get(key), is(nullValue()));
	}

	@Test
	public void testUpdateFailsWhenExpired() throws InterruptedException {
		int capacity = 5;
		int numberOfEntries = 1;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfEntries);
		cache.setHideStaleValues(true);
		String eldest = cache.getEldest();
		Integer key = Integer.valueOf(eldest);
		assertThat(cache.update(key), is(notNullValue()));
		time.setTestTimeShift(THRESHOLD_MILLIS + 100, TimeUnit.MILLISECONDS);
		assertThat(cache.update(key), is(nullValue()));
	}

	@Test
	public void testGetSucceedsEvenExpired() throws InterruptedException {
		int capacity = 5;
		int numberOfEntries = 1;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfEntries);
		cache.setHideStaleValues(false);
		String eldest = cache.getEldest();
		Integer key = Integer.valueOf(eldest);
		assertThat(cache.get(key), is(notNullValue()));
		time.setTestTimeShift(THRESHOLD_MILLIS + 100, TimeUnit.MILLISECONDS);
		assertThat(cache.get(key), is(notNullValue()));
	}

	@Test
	public void testUpdateSucceedsEvenExpired() throws InterruptedException {
		int capacity = 5;
		int numberOfEntries = 1;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfEntries);
		cache.setHideStaleValues(false);
		String eldest = cache.getEldest();
		Integer key = Integer.valueOf(eldest);
		assertThat(cache.update(key), is(notNullValue()));
		time.setTestTimeShift(THRESHOLD_MILLIS + 100, TimeUnit.MILLISECONDS);
		assertThat(cache.update(key), is(notNullValue()));
	}

	@Test
	public void testMultipleIteratorsRemove() throws InterruptedException {
		int capacity = 100;
		int numberOfEntries = 100;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfEntries);

		AtomicInteger read = new AtomicInteger();
		AtomicInteger removed = new AtomicInteger();

		execute(10, new IterateJob(read), new RemoveJob(removed, 3));

		assertThat(removed.get(), is(numberOfEntries / 3));
		assertThat(cache.size(), is(numberOfEntries - removed.get()));
		assertThat(read.get(), is(inRange(cache.size() * 9, (numberOfEntries * 9) + 1)));
		assertOrder(cache, false);
	}

	@Test
	public void testMultipleIteratorsAdd() throws InterruptedException {
		int capacity = 1000;
		int numberOfEntries = 100;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfEntries);
		AtomicInteger read = new AtomicInteger();

		execute(10, new IterateJob(read), new PutJob(numberOfEntries, numberOfEntries * 2));

		assertThat(cache.size(), is(numberOfEntries * 3));
		assertThat(read.get(), is(inRange(numberOfEntries * 9, (cache.size() * 9) + 1)));
		assertOrder(cache, false);
	}

	@Test
	public void testMultipleIteratorsPut() throws InterruptedException {
		int capacity = 1000;
		int numberOfEntries = 100;

		givenACacheWithEntries(capacity, THRESHOLD_MILLIS, numberOfEntries);
		AtomicInteger read = new AtomicInteger();

		execute(10, new IterateJob(read), new PutJob(0, numberOfEntries * 2));

		assertThat(cache.size(), is(numberOfEntries * 2));
		assertThat(read.get(), is(inRange(numberOfEntries * 9, (cache.size() * 9) + 1)));
		assertOrder(cache, false);
	}

	private void execute(int numberOfThreads, Runnable... jobs) {
		if (numberOfThreads == 0) {
			numberOfThreads = jobs.length;
		}
		final List<AssertionError> errors = new CopyOnWriteArrayList<>();
		Thread[] threads = new Thread[numberOfThreads];
		for (int index = 0; index < numberOfThreads; ++index) {
			final Runnable job = index < jobs.length ? jobs[index] : jobs[0];
			Runnable junit = new Runnable() {

				@Override
				public void run() {
					try {
						job.run();
					} catch (AssertionError error) {
						errors.add(error);
					} catch (Throwable t) {
						t.printStackTrace(System.err);
						errors.add(new AssertionError("error", t));
					}
				}
			};
			threads[index] = new Thread(junit, "Test#" + index);
		}
		for (Thread thread : threads) {
			thread.start();
		}
		for (Thread thread : threads) {
			try {
				thread.join(TimeUnit.SECONDS.toMillis(10));
			} catch (InterruptedException e) {
			}
		}
		if (!errors.isEmpty()) {
			for (AssertionError error : errors) {
				System.err.println(error.getMessage());
			}
			throw errors.get(0);
		}
	}

	/**
	 * 
	 * @param capacity
	 * @param expirationThresholdMillis
	 * @param numberOfEntries
	 */
	private void givenACacheWithEntries(int capacity, long expirationThresholdMillis, int numberOfEntries) {
		cache = new LeastRecentlyUpdatedCache<>(capacity, capacity, expirationThresholdMillis, TimeUnit.MILLISECONDS);
		for (int i = 0; i < numberOfEntries; i++) {
			cache.put(i, Integer.toString(i));
		}
	}

	private class IterateJob implements Runnable {

		private final AtomicInteger counter;

		public IterateJob(AtomicInteger counter) {
			this.counter = counter;
		}

		@Override
		public void run() {
			Iterator<String> valuesIterator = cache.valuesIterator();
			while (valuesIterator.hasNext()) {
				valuesIterator.next();
				counter.incrementAndGet();
			}
		}

	}

	private class RemoveJob implements Runnable {

		private final int ratio;
		private final AtomicInteger counter;

		public RemoveJob(AtomicInteger counter, int ratio) {
			this.counter = counter;
			this.ratio = ratio;
		}

		@Override
		public void run() {
			int count = 0;
			Iterator<String> valuesIterator = cache.valuesIterator();
			while (valuesIterator.hasNext()) {
				valuesIterator.next();
				if ((++count % ratio) == 0) {
					valuesIterator.remove();
					counter.incrementAndGet();
				}
			}
		}

	}

	private class PutJob implements Runnable {

		private final int start;
		private final int count;

		public PutJob(int start, int count) {
			this.start = start;
			this.count = count;
		}

		@Override
		public void run() {
			for (int index = start; index < start + count; ++index) {
				cache.put(index, Integer.toString(index));
			}
		}

	}

	private static void assertOrder(LeastRecentlyUpdatedCache<Integer, String> cache, boolean print) {
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

}
