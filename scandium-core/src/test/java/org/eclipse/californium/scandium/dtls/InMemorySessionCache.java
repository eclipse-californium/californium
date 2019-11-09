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
public class InMemorySessionCache implements SessionCache {

	private final Map<SessionId, byte[]> cache = new ConcurrentHashMap<>();

	/**
	 * Count for {@link #put(DTLSSession)} calls.
	 */
	public final AtomicInteger establishedSessionCounter = new AtomicInteger();

	/**
	 * Puts a ticket to the cache.
	 * <p>
	 * This method is mainly intended for supporting test cases.
	 * 
	 * @param id
	 * @param ticket
	 */
	public void put(final SessionId id, final SessionTicket ticket) {
		if (id != null && ticket != null) {
			DatagramWriter writer = new DatagramWriter(true);
			ticket.encode(writer);
			cache.put(id, writer.toByteArray());
			writer.close();
		}
	}

	@Override
	public void put(final DTLSSession session) {
		SessionTicket ticket;
		if (session != null && (ticket = session.getSessionTicket()) != null) {
			establishedSessionCounter.incrementAndGet();
			put(session.getSessionIdentifier(), ticket);
			SecretUtil.destroy(ticket);
		}
	}

	@Override
	public SessionTicket get(final SessionId id) {
		byte[] ticket = cache.get(id);
		if (ticket == null) {
			return null;
		} else {
			return SessionTicket.decode(new DatagramReader(ticket));
		}
	}

	@Override
	public void remove(final SessionId id) {
		cache.remove(id);
	}
}