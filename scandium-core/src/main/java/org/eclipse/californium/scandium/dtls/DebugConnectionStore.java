/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - Initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.util.concurrent.ConcurrentMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An debug <code>ConnectionStore</code> with dump and validate methods.
 * Intended to be used for unit tests.
 */
public final class DebugConnectionStore extends InMemoryConnectionStore {
	private static final Logger LOG = LoggerFactory.getLogger(DebugConnectionStore.class.getName());

	/**
	 * Creates a store based on given configuration parameters.
	 * 
	 * @param capacity the maximum number of connections the store can manage
	 * @param threshold the period of time of inactivity (in seconds) after
	 *            which a connection is considered stale and can be evicted from
	 *            the store if a new connection is to be added to the store
	 * @param sessionCache a second level cache to use for <em>current</em>
	 *            connection state of established DTLS sessions. If implements
	 *            {@link ClientSessionCache}, restore connection from the cache
	 *            and mark them to resume.
	 */
	public DebugConnectionStore(final int capacity, final long threshold, final SessionCache sessionCache) {
		super(capacity, threshold, sessionCache);
	}

	/**
	 * Dump connections to logger. Intended to be used for unit tests.
	 */
	public synchronized void dump() {
		if (connections.size() == 0) {
			LOG.info("  {}connections empty!", tag);
		} else {
			for (Connection connection : connections.values()) {
				if (connection.hasEstablishedSession()) {
					LOG.info("  {}connection: {} - {} : {}", tag, connection.getConnectionId(),
							connection.getPeerAddress(), connection.getSession().getSessionIdentifier());
				} else {
					LOG.info("  {}connection: {} - {}", tag, connection.getConnectionId(),
							connection.getPeerAddress());
				}
			}
		}
	}

	/**
	 * Validate connections. Intended to be used for unit tests.
	 */
	public synchronized void validate() {
		StringBuilder failure = new StringBuilder();
		if (connections.size() == 0) {
			if (!connectionsByAddress.isEmpty()) {
				LOG.warn("  {}connections by address not empty!", tag);
				dump(connectionsByAddress);
				failure.append(" connections by address not empty!");
			}
			if (!connectionsByEstablishedSession.isEmpty()) {
				LOG.warn("  {}connections by session not empty!", tag);
				dump(connectionsByEstablishedSession);
				failure.append(" connections by sessions not empty!");
			}
		} else {
			for (Connection connection : connections.values()) {
				InetSocketAddress peerAddress = connection.getPeerAddress();
				if (peerAddress != null) {
					Connection peerConnection = connectionsByAddress.get(peerAddress);
					if (connection != peerConnection && !peerConnection.equalsPeerAddress(peerAddress)) {
						LOG.warn("  {}connections mixed up peer {} - {} {}", tag, peerAddress, connection,
								peerConnection);
						failure.append(" connections by sessions mixed up!");
					}
				}
			}
			for (InetSocketAddress peerAddress : connectionsByAddress.keySet()) {
				Connection connection = connectionsByAddress.get(peerAddress);
				if (!peerAddress.equals(connection.getPeerAddress())) {
					LOG.warn("  {}connections by address mixed up {} - {}", tag, peerAddress, connection);
					failure.append(" connections by address mixed up!");
				}
				if (connections.get(connection.getConnectionId()) == null) {
					LOG.warn("  {}connections by address not available by cid! {} - {}", tag, peerAddress, connection);
					failure.append(" connections by address mixed up!");
				}
			}
			for (SessionId session : connectionsByEstablishedSession.keySet()) {
				Connection connection = connectionsByEstablishedSession.get(session);
				if (!session.equals(connection.getEstablishedSession().getSessionIdentifier())) {
					LOG.warn("  {}connections by session mixed up {} - {}", tag, session,
							connection.getEstablishedSession().getSessionIdentifier());
					failure.append(" connections by session mixed up!");
				}
				if (connections.get(connection.getConnectionId()) == null) {
					LOG.warn("  {}connections by session not available by cid! {} - {}", tag, session, connection);
					failure.append(" connections by session mixed up!");
				}
			}
		}
		if (failure.length() > 0) {
			throw new IllegalStateException(tag + failure);
		}
	}

	private <K> void dump(ConcurrentMap<K, Connection> map) {
		for (K key : map.keySet()) {
			Connection connection = map.get(key);
			LOG.warn("  {} connection: {} - {}", tag, key, connection);
		}
	}
}
