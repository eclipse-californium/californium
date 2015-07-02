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
package org.eclipse.californium.scandium.util;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.util.LeastRecentlyUsedCache.EvictionListener;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class LeastRecentlyUsedCacheTest {

	LeastRecentlyUsedCache<InetSocketAddress, DTLSSession> cache;

	@Before
	public void setUp() {
	}

	@Test
	public void testStoreAddsNewValueIfCapacityNotReached() {
		int capacity = 10;
		
		givenACacheWithEntries(capacity, 0L, capacity - 1);
		assertThat(cache.remainingCapacity(), is(1));
		DTLSSession eldest = cache.getEldest();
		
		DTLSSession newSession = newSession(50L);
		assertTrue(cache.put(newSession.getPeer(), newSession));
		assertNotNull(cache.get(eldest.getPeer()));
		assertThat(cache.remainingCapacity(), is(0));
	}
	
	@Test
	public void testStoreEvictsEldestStaleEntry() {
		int capacity = 10;
		
		givenACacheWithEntries(capacity, 0L, capacity);
		assertThat(cache.remainingCapacity(), is(0));
		DTLSSession eldest = cache.getEldest();
		
		DTLSSession newSession = newSession(50L);
		assertTrue(cache.put(newSession.getPeer(), newSession));
		assertNull(cache.get(eldest.getPeer()));
	}

	@Test
	public void testStoreFailsIfCapacityReached() {
		long threshold =  10; // seconds
		int capacity = 10;
		int numberOfSessions = 10;
		
		givenACacheWithEntries(capacity, threshold, numberOfSessions);
		assertThat(cache.remainingCapacity(), is(0));
		DTLSSession eldest = cache.getEldest();
		
		DTLSSession newSession = newSession(50L);
		assertFalse(cache.put(newSession.getPeer(), newSession));
		assertNull(cache.get(newSession.getPeer()));
		assertNotNull(cache.get(eldest.getPeer()));
	}

	@Test
	public void testContinuousEviction() {
		int capacity = 10;
		
		givenACacheWithEntries(capacity, 0L, 0);
		assertThat(cache.remainingCapacity(), is(capacity));
		final AtomicInteger evicted = new AtomicInteger(0);
		
		cache.addEvictionListener(new EvictionListener<DTLSSession>() {
			
			@Override
			public void onEviction(DTLSSession evictedSession) {
				evicted.incrementAndGet();
			}
		});

		int noOfSessions = 50000;
		for (int i = 0; i < noOfSessions; i++) {
			DTLSSession session = newSession(i + 1000L);
			assertTrue(cache.put(session.getPeer(), session));
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
			DTLSSession session = newSession(i + 1000);
			cache.put(session.getPeer(), session);
		}
	}

	private DTLSSession newSession(long ip) {
		DTLSSession result = new DTLSSession(new InetSocketAddress(longToIp(ip), 5050), false);
		return result;
	}
	
	private String longToIp(long ip) {
		StringBuilder sb = new StringBuilder(15);

		for (int i = 0; i < 4; i++) {
			sb.insert(0, Long.toString(ip & 0xff));

			if (i < 3) {
				sb.insert(0, '.');
			}

			ip >>= 8;
		}

		return sb.toString();
	}
}
