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
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.eclipse.californium.core.network.config.NetworkConfig;


/**
 * A provider for message IDs thats keeps track of all message IDs in memory.
 * <p>
 * This provider maintains an instance of {@link MessageIdTracker} for each
 * endpoint identified by IP address and port.
 */
public class InMemoryMessageIdProvider implements MessageIdProvider {

	private final Map<InetSocketAddress, MessageIdTracker> trackers;
	private final NetworkConfig config;

	/**
	 * Creates an new provider for configuration values.
	 * 
	 * @param config the configuration to use. In particular, the <em>EXCHANGE_LIFETIME</em>
	 *         configuration parameter is used as the period of time a message ID is marked as
	 *         <em>in use</em> when it is allocated for a message exchange.
	 */
	public InMemoryMessageIdProvider(final NetworkConfig config) {
		this.config = config;
		trackers = new ConcurrentHashMap<>(32000);
	}

	@Override
	public int getNextMessageId(final InetSocketAddress destination) {
		MessageIdTracker tracker = trackers.get(destination);
		if (tracker == null) {
			// create new tracker for destination lazily
			tracker = new MessageIdTracker(config);
			MessageIdTracker existingTracker = trackers.putIfAbsent(destination, tracker);
			if (existingTracker != null) {
				tracker = existingTracker;
			}
		}
		return tracker.getNextMessageId();
	}
}
