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
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.net.InetSocketAddress;

import org.eclipse.californium.scandium.category.Small;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class InMemoryConnectionStoreTest {

	private static final int INITIAL_CAPACITY = 10;
	InMemoryConnectionStore store;
	Connection con;
	SessionId sessionId;

	@Before
	public void setUp() throws HandshakeException {
		store = new InMemoryConnectionStore(INITIAL_CAPACITY, 1000);
		con = newConnection(50L);
		sessionId = con.getEstablishedSession().getSessionIdentifier();
	}

	@Test
	public void testPutAddsConnection() {
		// given an empty connection store
		assertThat(store.remainingCapacity(), is(INITIAL_CAPACITY));

		// when adding a new connection to the store
		assertTrue(store.put(con));

		// assert that the store is not empty
		assertThat(store.remainingCapacity(), is(INITIAL_CAPACITY - 1));
	}

	@Test
	public void testFindRetrievesSession() {
		// given a connection store containing a connection with a peer
		store.put(con);

		// when retrieving the connection for the given peer
		Connection connectionWithPeer = store.find(sessionId);
		assertThat(connectionWithPeer, is(con));
	}

	@Test
	public void testClearRemovesAllConnectionsFromStore() throws HandshakeException {
		// given a non-empty connection store
		store.put(con);
		store.put(newConnection(51L));
		store.put(newConnection(52L));

		// when clearing the store
		store.clear();

		// assert that the store is empty
		assertThat(store.remainingCapacity(), is(INITIAL_CAPACITY));
		assertThat(store.get(con.getPeerAddress()), is(nullValue()));
	}

	private Connection newConnection(long ip) throws HandshakeException {
		InetSocketAddress peerAddress = new InetSocketAddress(longToIp(ip), 0);
		Connection con = new Connection(peerAddress);
		con.sessionEstablished(null, newSession(peerAddress));
		return con;
	}

	private DTLSSession newSession(InetSocketAddress address) {
		DTLSSession result = new DTLSSession(address, false);
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
