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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A simple memory based <code>SessionStore</code>.
 * 
 * This implementation uses a session's peer address as key.
 * 
 */
public class InMemorySessionStore implements SessionStore {

	/** Storing sessions according to peer-addresses */
	private Map<InetSocketAddress, DTLSSession> dtlsSessions = new ConcurrentHashMap<>();

	@Override
	public DTLSSession store(DTLSSession session) {
		if (session != null) {
			return dtlsSessions.put(session.getPeer(), session);
		} else {
			return null;
		}
	}

	@Override
	public DTLSSession get(InetSocketAddress peerAddress) {
		if (peerAddress == null) {
			return null;
		}
		return dtlsSessions.get(peerAddress);
	}

	@Override
	public DTLSSession find(SessionId id) {
		if (id == null) {
			return null;
		} else {
			
			for (DTLSSession session:dtlsSessions.values()) {
				if (id.equals(session.getSessionIdentifier())) {
					return session;
				}
			}
			
			return null;
		}
	}

	@Override
	public DTLSSession remove(InetSocketAddress peerAddress) {
		if (peerAddress != null) {
			return dtlsSessions.remove(peerAddress);
		} else {
			return null;
		}
	}

	@Override
	public Collection<DTLSSession> getAll() {
		return Collections.unmodifiableCollection(dtlsSessions.values());
	}

	@Override
	public void update(DTLSSession session) {
		// no need to do anything since this is an in-memory store
	}

}
