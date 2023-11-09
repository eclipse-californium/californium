/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - Initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.util.concurrent.ConcurrentMap;

import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An debug {@code ResumptionSupportingConnectionStore} with dump and validate
 * methods.
 * 
 * Intended to be used for unit tests.
 * 
 * @since 3.5
 */
@SuppressWarnings("deprecation")
public final class DebugSynchronizedConnectionStore extends InMemoryConnectionStore implements DebugConnectionStore {

	private static final Logger LOG = LoggerFactory.getLogger(DebugSynchronizedConnectionStore.class);

	/**
	 * Creates a store based on given configuration parameters.
	 * 
	 * @param capacity the maximum number of connections the store can manage
	 * @param threshold the period of time of inactivity (in seconds) after
	 *            which a connection is considered stale and can be evicted from
	 *            the store if a new connection is to be added to the store
	 * @param sessionStore a second level store to use for <em>current</em>
	 *            connection state of established DTLS sessions.
	 */
	public DebugSynchronizedConnectionStore(final int capacity, final long threshold, final SessionStore sessionStore) {
		super(capacity, threshold, sessionStore);
	}

	/**
	 * Dump connections to logger. Intended to be used for unit tests.
	 */
	@Override
	public synchronized void dump() {
		if (connections.size() == 0) {
			LOG.info("  {}connections empty!", tag);
		} else {
			LOG.info("  {}connections: {}", tag, connections.size());
			for (Connection connection : connections.values()) {
				dump(connection);
			}
		}
	}

	/**
	 * Dump connections to logger. Intended to be used for unit tests.
	 * 
	 * @param address address of connection to dump
	 */
	@Override
	public boolean dump(InetSocketAddress address) {
		if (connections.size() == 0) {
			LOG.info("  {}connections empty!", tag);
		} else {
			Connection connection = get(address);
			if (connection == null) {
				LOG.info("  {}connection: {} - not available!", tag, StringUtil.toString(address));
			} else if (connection.equalsPeerAddress(address)) {
				dump(connection);
				return true;
			} else {
				dump(connection);
				LOG.info("  {}connection: {} - wrong assigned!", tag, StringUtil.toString(address));
			}
		}
		return false;
	}

	/**
	 * Dump connection to logger. Intended to be used for unit tests.
	 * 
	 * @param connection connection to dump
	 */
	private void dump(Connection connection) {
		if (connection.hasEstablishedDtlsContext()) {
			LOG.info("  {}connection: {} - {} : {}", tag, connection.getConnectionId(), connection.getPeerAddress(),
					connection.getEstablishedSession().getSessionIdentifier());
		} else {
			LOG.info("  {}connection: {} - {}", tag, connection.getConnectionId(), connection.getPeerAddress());
		}
	}

	/**
	 * Validate connections. Intended to be used for unit tests.
	 */
	@Override
	public synchronized void validate() {
		StringBuilder failure = new StringBuilder();
		if (connections.size() == 0) {
			if (!connectionsByAddress.isEmpty()) {
				LOG.warn("  {}connections by address not empty!", tag);
				dump(connectionsByAddress);
				failure.append(" connections by address not empty!");
			}
			if (connectionsByEstablishedSession != null && !connectionsByEstablishedSession.isEmpty()) {
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
			if (connectionsByEstablishedSession != null) {
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
