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
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.net.InetSocketAddress;

import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.util.LeastRecentlyUsedCache;


/**
 * A provider for message IDs thats keeps track of all message IDs in memory.
 * <p>
 * This provider maintains an instance of {@link MessageIdTracker} for each
 * endpoint identified by IP address and port.
 */
public class InMemoryMessageIdProvider implements MessageIdProvider {

	private final LeastRecentlyUsedCache<InetSocketAddress, MessageIdTracker> trackers;
	private final NetworkConfig config;

	/**
	 * Creates an new provider for configuration values.
	 * 
	 * @param config the configuration to use. In particular, the <em>EXCHANGE_LIFETIME</em>
	 *         configuration parameter is used as the period of time a message ID is marked as
	 *         <em>in use</em> when it is allocated for a message exchange.
	 * @throws NullPointerException if the config is {@code null}.
	 */
	public InMemoryMessageIdProvider(final NetworkConfig config) {
		if (config == null) {
			throw new NullPointerException("Config must not be null");
		}
		this.config = config;
		trackers = new LeastRecentlyUsedCache<>(
				config.getInt(NetworkConfig.Keys.MAX_ACTIVE_PEERS, 500000),
				config.getLong(NetworkConfig.Keys.MAX_PEER_INACTIVITY_PERIOD, 36 * 60 * 60)); // 36h
	}

	@Override
	public synchronized int getNextMessageId(final InetSocketAddress destination) {
		MessageIdTracker tracker = trackers.get(destination);
		if (tracker == null) {
			// create new tracker for destination lazily
			tracker = new MessageIdTracker(config);
			if (!trackers.put(destination, tracker)) {
				// we have reached the maximum number of active peers
				// TODO: throw an exception?
				return -1;
			}
		}
		return tracker.getNextMessageId();
	}
}
