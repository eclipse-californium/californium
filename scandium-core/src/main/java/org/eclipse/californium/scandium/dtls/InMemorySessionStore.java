/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.util.LeastRecentlyUpdatedCache;
import org.eclipse.californium.scandium.util.SecretUtil;

/**
 * A simple session store that stores {@code DTLSSession} in a LRU cache.
 * 
 * If capacity get exceeded, the least recently used session gets evicted. The
 * usage is based on {@link #put(DTLSSession)}, a {@link #get(SessionId)} is not
 * considered as usage.
 * 
 * Note: this store is not well tested! If used and causing trouble, don't
 * hesitate to create an issue.
 * 
 * Note: since 3.9 the implementation based on the
 * {@link LeastRecentlyUpdatedCache} instead of the deprecated
 * LeastRecentlyUsedCache.
 * 
 * @since 3.0
 */
public class InMemorySessionStore implements SessionStore {

	private final LeastRecentlyUpdatedCache<SessionId, DTLSSession> store;

	/**
	 * Create in memory session store.
	 * 
	 * @param capacity the maximum number of session the store can manage
	 * @param threshold the period of time of inactivity (in seconds) after
	 *            which a session is considered stale and can be evicted from
	 *            the store if a new session is to be added to the store
	 */
	public InMemorySessionStore(int capacity, long threshold) {
		this.store = new LeastRecentlyUpdatedCache<>(capacity, threshold, TimeUnit.SECONDS);
	}

	@Override
	public void put(final DTLSSession session) {
		if (session != null && !session.getSessionIdentifier().isEmpty()) {
			DTLSSession clone = new DTLSSession(session);
			if (!store.put(session.getSessionIdentifier(), clone)) {
				SecretUtil.destroy(clone);
			}
		}
	}

	@Override
	public DTLSSession get(final SessionId id) {
		DTLSSession session = store.update(id);
		return session == null ? null : new DTLSSession(session);
	}

	@Override
	public void remove(final SessionId id) {
		DTLSSession session = store.remove(id);
		SecretUtil.destroy(session);
	}
}
