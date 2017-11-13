/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - use ConcurrentHashMap for
 *                                                    thread-safe implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;

/**
 * A simple session cache that stores {@code SessionTickets} in a hash map.
 *
 */
public class InMemorySessionCache implements SessionCache {

	private final Map<SessionId, byte[]> cache = new ConcurrentHashMap<>();

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
			DatagramWriter writer = new DatagramWriter();
			ticket.encode(writer);
			cache.put(id, writer.toByteArray());
		}
	}

	@Override
	public void put(final DTLSSession session) {
		if (session != null) {
			put(session.getSessionIdentifier(), session.getSessionTicket());
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