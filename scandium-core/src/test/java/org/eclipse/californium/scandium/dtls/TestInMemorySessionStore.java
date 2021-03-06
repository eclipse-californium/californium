/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - use ConcurrentHashMap for
 *                                                    thread-safe implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.util.SecretUtil;

/**
 * A simple session cache that stores {@code SessionTickets} in a hash map.
 *
 */
public class TestInMemorySessionStore implements SessionStore {

	private final Map<SessionId, byte[]> cache = new ConcurrentHashMap<>();

	/**
	 * Count for {@link #put(DTLSSession)} calls.
	 */
	public final AtomicInteger establishedSessionCounter = new AtomicInteger();

	@Override
	public void put(final DTLSSession session) {
		if (session != null && !session.getSessionIdentifier().isEmpty()) {
			DatagramWriter writer = new DatagramWriter(true);
			session.writeTo(writer);
			cache.put(session.getSessionIdentifier(), writer.toByteArray());
			establishedSessionCounter.incrementAndGet();
		}
	}

	@Override
	public DTLSSession get(final SessionId id) {
		byte[] data = cache.get(id);
		if (data == null) {
			return null;
		}
		DTLSSession session = DTLSSession.fromReader(new DatagramReader(data));
		if (session != null && !session.getSessionIdentifier().equals(id)) {
			SecretUtil.destroy(session);
			return null;
		}
		return session;
	}

	@Override
	public void remove(final SessionId id) {
		cache.remove(id);
	}

	public void clear() {
		cache.clear();
		establishedSessionCounter.set(0);
	}

	public int size() {
		return cache.size();
	}
}