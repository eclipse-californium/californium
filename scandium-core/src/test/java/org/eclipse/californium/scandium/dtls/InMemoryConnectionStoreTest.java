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
 *    Achim Kraus (Bosch Software Innovations GmbH) - redesign connection session listener to
 *                                                    ensure, that the session listener methods
 *                                                    are called via the handshaker.
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.rule.ThreadsRule;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class InMemoryConnectionStoreTest {
	@Rule
	public ThreadsRule cleanup = new ThreadsRule();

	private static final int INITIAL_CAPACITY = 10;
	InMemoryConnectionStore store;
	Connection con;
	SessionId sessionId;

	@Before
	public void setUp() throws Exception {
		store = new InMemoryConnectionStore(INITIAL_CAPACITY, 1000);
		store.attach(null);
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
	public void testGetConnectionIdRetrievesLocalConnection() {
		// given a connection store containing a connection with a peer
		store.put(con);
		// when retrieving the connection for the given peer
		ConnectionId cid = con.getConnectionId();
		Connection connectionWithPeer = store.get(cid);
		assertThat(connectionWithPeer, is(con));
		ConnectionId cid2 = new ConnectionId(cid.getBytes());
		assertThat("hash", cid2.hashCode(), is(cid.hashCode()));
		assertThat("equals", cid2, is(cid));
		connectionWithPeer = store.get(cid2);
		assertThat(connectionWithPeer, is(con));
	}

	@Test
	public void testGetAddressRetrievesLocalConnection() {
		// given a connection store containing a connection with a peer
		store.put(con);
		// when retrieving the connection for the given peer
		Connection connectionWithPeer = store.get(con.getPeerAddress());
		assertThat(connectionWithPeer, is(con));
	}

	@Test
	public void testFindRetrievesLocalConnection() {
		// given a connection store containing a connection with a peer
		store.put(con);
		store.putEstablishedSession(con.getEstablishedSession(), con);
		// when retrieving the connection for the given peer
		Connection connectionWithPeer = store.find(sessionId);
		assertThat(connectionWithPeer, is(con));
	}

	@Test
	public void testFindRetrievesSharedConnection() {

		// GIVEN an empty connection store with a cached session shared by another node
		SessionCache sessionCache = new InMemorySessionCache();
		sessionCache.put(con.getEstablishedSession());
		store = new InMemoryConnectionStore(INITIAL_CAPACITY, 1000, sessionCache);

		// WHEN retrieving the connection for the given peer
		Connection connectionWithPeer = store.find(sessionId);

		// THEN assert that the retrieved connection contains a session ticket
		assertThat(connectionWithPeer, is(notNullValue()));
		SessionTicket ticket = connectionWithPeer.getSessionTicket();
		assertThat(ticket, is(notNullValue()));
		assertThat(ticket.getMasterSecret(), is(con.getEstablishedSession().getMasterSecret()));
	}

	@Test
	public void testFindRemovesStaleConnectionFromStore() {

		// GIVEN a connection store with a cached session shared by another node
		// and a (local) connection based on this session
		SessionCache sessionCache = new InMemorySessionCache();
		sessionCache.put(con.getEstablishedSession());
		store = new InMemoryConnectionStore(INITIAL_CAPACITY, 1000, sessionCache);
		store.attach(null);
		store.put(con);
		store.putEstablishedSession(con.getEstablishedSession(), con);
		InetSocketAddress peerAddress = con.getPeerAddress();

		// WHEN the session is removed from the cache (e.g. because it became stale)
		sessionCache.remove(con.getEstablishedSession().getSessionIdentifier());

		// THEN assert that the connection has been removed from the local cache
		Connection connectionToResume = store.find(sessionId);
		assertThat(connectionToResume, is(nullValue()));
		assertThat(store.get(peerAddress), is(nullValue()));
	}

	@Test
	public void testRemoveShutsdownExecutor() throws Exception {
		// given a non-empty connection store
		store.put(con);

		// when clearing the store
		store.remove(con);

		// assert that the executor is shutdown
		assertThat(con.getExecutor().isShutdown(), is(true));
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

	@Test
	public void testPutSameAddressAddsConnection() throws Exception {
		// given an empty connection store
		assertThat(store.remainingCapacity(), is(INITIAL_CAPACITY));

		// when adding a new connection to the store
		Connection con1 =  newConnection(51L);
		InetSocketAddress addr1 = con1.getPeerAddress();
		assertTrue(store.put(con1));
		Connection con2 =  newConnection(51L);
		InetSocketAddress addr2 = con2.getPeerAddress();
		assertTrue(store.put(con2));

		// assert that the store has two entries
		assertThat(store.remainingCapacity(), is(INITIAL_CAPACITY - 2));

		assertThat(addr1, is(addr2));
		assertThat(con1.getConnectionId(), is(not(con2.getConnectionId())));

		assertThat(store.get(con1.getConnectionId()), is(con1));
		assertThat(store.get(con2.getConnectionId()), is(con2));
		assertThat(con1.getPeerAddress(), is(nullValue()));
		assertThat(store.get(addr1), is(con2));
	}

	@Test
	public void testUpdateAddress() throws Exception {
		// given an empty connection store
		assertThat(store.remainingCapacity(), is(INITIAL_CAPACITY));

		// when adding a new connection to the store
		Connection con1 =  newConnection(51L);
		InetSocketAddress addr1 = con1.getPeerAddress();
		assertTrue(store.put(con1));
		Connection con2 =  newConnection(52L);
		InetSocketAddress addr2 = con2.getPeerAddress();
		assertTrue(store.put(con2));

		assertThat(con1.getConnectionId(), is(not(con2.getConnectionId())));

		// assert that the store has two entries
		assertThat(store.remainingCapacity(), is(INITIAL_CAPACITY - 2));

		store.update(con2, addr1);

		assertThat(store.get(con1.getConnectionId()), is(con1));
		assertThat(store.get(con2.getConnectionId()), is(con2));
		assertThat(con1.getPeerAddress(), is(nullValue()));
		assertThat(store.get(addr1), is(con2));

		store.update(con1, addr2);

		assertThat(store.get(con1.getConnectionId()), is(con1));
		assertThat(store.get(con2.getConnectionId()), is(con2));
		assertThat(con1.getPeerAddress(), is(addr2));
		assertThat(store.get(addr2), is(con1));
	}

	@Test
	public void testPutEstablishedSessionStalesOldConnection() throws Exception {
		// given an empty connection store
		assertThat(store.remainingCapacity(), is(INITIAL_CAPACITY));

		// when adding a new connection to the store
		Connection con1 =  newConnection(51L);
		DTLSSession session = con1.getEstablishedSession();
		InetSocketAddress address = con1.getPeerAddress();
		assertTrue(store.put(con1));
		
		assertThat(store.find(session.getSessionIdentifier()), is(con1));

		Connection con2 =  newConnection(52L);
		con2.resetSession();
		assertTrue(store.put(con2));
		assertThat(store.find(session.getSessionIdentifier()), is(con1));

		// assert that the store has two entries
		assertThat(store.remainingCapacity(), is(INITIAL_CAPACITY - 2));

		// resume session => established
		store.putEstablishedSession(session, con2);

		assertThat(store.find(session.getSessionIdentifier()), is(con2));
		assertThat(store.get(address), is(nullValue()));
		assertThat(con1.getPeerAddress(), is(nullValue()));

		// assert that the store has one entry
		assertThat(store.remainingCapacity(), is(INITIAL_CAPACITY - 1));
	}

	@Test
	public void testPutStalesOldConnection() throws Exception {
		// given an empty connection store
		assertThat(store.remainingCapacity(), is(INITIAL_CAPACITY));

		// when adding a new connection to the store
		Connection con1 =  newConnection(51L);
		DTLSSession session = con1.getEstablishedSession();
		InetSocketAddress address = con1.getPeerAddress();
		assertTrue(store.put(con1));
		
		assertThat(store.find(session.getSessionIdentifier()), is(con1));

		Connection con2 =  newConnection(51L);
		con2.resetSession();
		assertTrue(store.put(con2));

		// assert that the store has two entries
		assertThat(store.remainingCapacity(), is(INITIAL_CAPACITY - 2));

		assertThat(store.find(session.getSessionIdentifier()), is(con1));

		assertThat(store.get(address), is(con2));
		assertThat(con1.getPeerAddress(), is(nullValue()));

		// resume session => established
		store.putEstablishedSession(session, con2);

		// assert that the store has one entry
		assertThat(store.remainingCapacity(), is(INITIAL_CAPACITY - 1));

		assertThat(store.find(session.getSessionIdentifier()), is(con2));
	}

	private Connection newConnection(long ip) throws HandshakeException, UnknownHostException {
		InetAddress addr = InetAddress.getByAddress(longToIp(ip));
		InetSocketAddress peerAddress = new InetSocketAddress(addr, 0);
		Connection con = new Connection(peerAddress, new SyncSerialExecutor());
		con.getSessionListener().sessionEstablished(null, newSession(peerAddress));
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
}
