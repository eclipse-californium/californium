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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - re-factor LRU cache into separate generic class
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.net.InetSocketAddress;

import org.eclipse.californium.scandium.category.Small;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class InMemorySessionStoreTest {

	InMemorySessionStore store;
	
	@Before
	public void setUp() {
		store = new InMemorySessionStore(10, 1000);
	}

	@Test
	public void testPutAddsSession() {
		DTLSSession session = newSession(50L);
		assertTrue(store.put(session));
		assertThat(store.get(session.getPeer()), notNullValue());
	}

	@Test
	public void testFindRetrievesSession() {
		DTLSSession session = newSession(50L);
		assertTrue(store.put(session));
		assertThat(store.find(session.getSessionIdentifier()), notNullValue());
	}
	
	private DTLSSession newSession(long ip) {
		DTLSSession result = new DTLSSession(new InetSocketAddress(longToIp(ip), 5050), false);
		result.setSessionIdentifier(new SessionId());
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
