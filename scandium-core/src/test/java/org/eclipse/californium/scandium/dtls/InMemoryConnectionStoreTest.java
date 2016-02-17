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

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
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
	public void setUp() throws Exception {
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
	public void testFindRetrievesEstablishedSessionFromSessionCache() {

		// GIVEN an empty connection store with a cached established session with a peer
		SessionCache sessionCache = new InMemorySessionCache();
		sessionCache.put(con.getEstablishedSession());
		store = new InMemoryConnectionStore(INITIAL_CAPACITY, 1000, sessionCache);

		// WHEN retrieving the connection for the given peer
		Connection connectionWithPeer = store.find(sessionId);

		// THEN assert that the retrieved connection contains the established session
		assertThat(connectionWithPeer, is(notNullValue()));
		assertThat(connectionWithPeer.getEstablishedSession(), is(notNullValue()));
		DTLSSessionTest.assertThatSessionsHaveSameRelevantPropertiesForResumption(connectionWithPeer.getEstablishedSession(), con.getEstablishedSession());
	}

	@Test
	public void testFindRemovesStaleSessionFromStore() {

		// GIVEN a connection store with a cached established session with a peer
		// and a connection based on this session
		SessionCache sessionCache = new InMemorySessionCache();
		sessionCache.put(con.getEstablishedSession());
		store = new InMemoryConnectionStore(INITIAL_CAPACITY, 1000, sessionCache);
		store.put(con);

		// WHEN the session is removed from the cache (e.g. because it became stale)
		// a client wants to resume the session
		sessionCache.remove(con.getEstablishedSession().getSessionIdentifier());
		Connection connectionToResume = store.find(sessionId);

		// THEN assert that the connection has been removed from the local cache
		assertThat(connectionToResume, is(nullValue()));
		assertThat(store.get(con.getPeerAddress()), is(nullValue()));
	}

	@Test
	public void testSessionEstablishedPutsSessionToSessionCache() throws Exception {
		// GIVEN a connection store with an empty session cache
		SessionCache sessionCache = new InMemorySessionCache();
		store = new InMemoryConnectionStore(INITIAL_CAPACITY, 1000, sessionCache);

		// WHEN a session is established as part of a successful handshake
		store.sessionEstablished(null, con.getEstablishedSession());

		// THEN assert that the established session has been put to the session cache
		DTLSSession sessionFromCache = sessionCache.get(sessionId);
		assertThat(sessionFromCache, is(notNullValue()));
		DTLSSessionTest.assertThatSessionsHaveSameRelevantPropertiesForResumption(sessionFromCache, con.getEstablishedSession());
	}

	@Test
	public void testClearRemovesAllConnectionsFromStore() throws Exception {
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

	private Connection newConnection(long ip) throws HandshakeException, UnknownHostException {
		InetAddress addr = InetAddress.getByAddress(longToIp(ip));
		InetSocketAddress peerAddress = new InetSocketAddress(addr, 0);
		Connection con = new Connection(peerAddress);
		con.sessionEstablished(null, newSession(peerAddress));
		return con;
	}

	private DTLSSession newSession(InetSocketAddress address) {
		return DTLSSessionTest.newEstablishedServerSession(address, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, true);
	}

	private static byte[] longToIp(long ip) {
		byte[] result = new byte[4];
		result[0] = 10;
		for (int i = 3; i >= 1; i--) {
			result[i] = (byte) (ip & 0xff);
			ip >>= 8;
		}
		return result;
	}

	private class InMemorySessionCache implements SessionCache {

		Map<SessionId, DTLSSession> cache = new HashMap<>();

		@Override
		public void put(final DTLSSession session) {
			cache.put(session.getSessionIdentifier(), session);
		}

		@Override
		public DTLSSession get(final SessionId id) {
			return cache.get(id);
		}

		@Override
		public DTLSSession remove(final SessionId id) {
			return cache.remove(sessionId);
		}
	}
}
