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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add support for stale
 *                                                    session expiration (466554)
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.scandium.dtls.InMemorySessionStore.EvictionListener;
import org.junit.Before;
import org.junit.Test;

public class InMemorySessionStoreTest {

	InMemorySessionStore store;

	@Before
	public void setUp() {
	}

	@Test
	public void testStoreAddsNewSessionIfCapacityNotReached() {
		int capacity = 10;
		
		givenAStoreWithSessions(capacity, 0L, capacity - 1);
		assertThat(store.remainingCapacity(), is(1));
		DTLSSession eldest = store.getEldest();
		
		assertTrue(store.put(newSession(50L)));
		assertNotNull(store.get(eldest.getPeer()));
		assertThat(store.remainingCapacity(), is(0));
	}
	
	@Test
	public void testStoreEvictsEldestStaleSession() {
		int capacity = 10;
		
		givenAStoreWithSessions(capacity, 0L, capacity);
		assertThat(store.remainingCapacity(), is(0));
		DTLSSession eldest = store.getEldest();
		
		assertTrue(store.put(newSession(50L)));
		assertNull(store.get(eldest.getPeer()));
	}

	@Test
	public void testStoreFailsIfCapacityReached() {
		long threshold =  10; // seconds
		int capacity = 10;
		int numberOfSessions = 10;
		
		givenAStoreWithSessions(capacity, threshold, numberOfSessions);
		assertThat(store.remainingCapacity(), is(0));
		DTLSSession eldest = store.getEldest();
		
		DTLSSession newSession = newSession(50L);
		assertFalse(store.put(newSession));
		assertNull(store.get(newSession.getPeer()));
		assertNotNull(store.get(eldest.getPeer()));
	}

	@Test
	public void testContinuousEviction() {
		int capacity = 10;
		
		givenAStoreWithSessions(capacity, 0L, 0);
		assertThat(store.remainingCapacity(), is(capacity));
		final AtomicInteger evicted = new AtomicInteger(0);
		
		store.addEvictionListener(new EvictionListener() {
			
			@Override
			public void onEviction(DTLSSession evictedSession) {
				evicted.incrementAndGet();
			}
		});

		int noOfSessions = 50000;
		for (int i = 0; i < noOfSessions; i++) {
			assertTrue(store.put(newSession(i + 1000L)));
		}
		assertThat(evicted.get(), is(noOfSessions - capacity));
		assertThat(store.remainingCapacity(), is(0));
	}

	/**
	 * 
	 * @param capacity
	 * @param expirationThreshold
	 * @param noOfSessions
	 */
	private void givenAStoreWithSessions(int capacity, long expirationThreshold, int noOfSessions) {
		store = new InMemorySessionStore(capacity, expirationThreshold);

		for (int i = 0; i < noOfSessions; i++) {
			DTLSSession session = newSession(i + 1000);
			store.put(session);
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
