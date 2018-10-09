/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A simple client session cache that stores {@code ClientSession} in a hash
 * map. On the client side it's required to store also the peer address to
 * resume a session by the peer's address.
 */
public class InMemoryClientSessionCache implements ClientSessionCache {

	/**
	 * Session by peer.
	 */
	private final Map<InetSocketAddress, ClientSession> connectionTickets = new ConcurrentHashMap<>();
	/**
	 * Session by id.
	 */
	private final Map<SessionId, ClientSession> sessionTickets = new ConcurrentHashMap<>();

	@Override
	public String toString() {
		return sessionTickets.size() + " sessions";
	}

	@Override
	public Iterator<InetSocketAddress> iterator() {
		return connectionTickets.keySet().iterator();
	}

	@Override
	public SessionTicket getSessionTicket(InetSocketAddress peer) {
		ClientSession clientSession = connectionTickets.get(peer);
		return clientSession == null ? null : clientSession.ticket;
	}

	@Override
	public SessionId getSessionIdentity(InetSocketAddress peer) {
		ClientSession clientSession = connectionTickets.get(peer);
		return clientSession == null ? null : clientSession.id;
	}

	@Override
	public void put(DTLSSession session) {
		final InetSocketAddress peer = session.getPeer();
		final SessionTicket ticket = session.getSessionTicket();
		final SessionId id = session.getSessionIdentifier();
		final ClientSession clientSession = new ClientSession(peer, id, ticket);
		connectionTickets.put(peer, clientSession);
		sessionTickets.put(id, clientSession);
	}

	@Override
	public SessionTicket get(SessionId id) {
		ClientSession clientSession = sessionTickets.get(id);
		return clientSession == null ? null : clientSession.ticket;
	}

	@Override
	public void remove(SessionId id) {
		final ClientSession session = sessionTickets.remove(id);
		if (session != null) {
			connectionTickets.remove(session.peer);
		}
	}

	private static class ClientSession {

		private final InetSocketAddress peer;
		private final SessionId id;
		private final SessionTicket ticket;

		private ClientSession(final InetSocketAddress peer, final SessionId id, final SessionTicket ticket) {
			this.peer = peer;
			this.id = id;
			this.ticket = ticket;
		}
	}
}
