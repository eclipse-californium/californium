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
 *    Bosch Software Innovations GmbH - Initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.util.Iterator;

/**
 * Client side second level cache for current connection state of DTLS sessions.
 * <p>
 * Connection state can be put to the cache and is retrieved when (re-)constructing the
 * connection store. The provided cache is required to be thread-safe because it
 * will be accessed concurrently.
 * </p>
 */
public interface ClientSessionCache extends SessionCache, Iterable<InetSocketAddress> {

	@Override
	Iterator<InetSocketAddress> iterator();

	/**
	 * Gets a session ticket from the cache.
	 * 
	 * @param peer socket address of peer.
	 * @return The session ticket with the given peer address or {@code null} if
	 *         the cache does not contain a session ticket with the given peer
	 *         address.
	 */
	SessionTicket getSessionTicket(InetSocketAddress peer);

	/**
	 * Gets a session identity from the cache.
	 * 
	 * @param peer socket address of peer.
	 * @return The session identity with the given peer address or {@code null}
	 *         if the cache does not contain a session identity with the given
	 *         peer address.
	 */
	SessionId getSessionIdentity(InetSocketAddress peer);
}
