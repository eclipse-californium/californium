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
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove nested synchronize.
 *                                                    reduce blocking on 
 *                                                    tracker.getNextMessageId()
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce MessageIdTracker
 *                                                    interface and rename old
 *                                                    MessageIdTracker to
 *                                                    MapBasedMessageIdTracker.
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.net.InetSocketAddress;
import java.util.Random;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.util.LeastRecentlyUsedCache;

/**
 * A provider for message IDs thats keeps track of all message IDs in memory.
 * <p>
 * This provider maintains an instance of {@link MessageIdTracker} for each
 * endpoint identified by IP address and port.
 */
public class InMemoryMessageIdProvider implements MessageIdProvider {

	enum TrackerMode {
		NULL, GROUPED, MAPBASED
	}

	private final LeastRecentlyUsedCache<InetSocketAddress, MessageIdTracker> trackers;
	private final TrackerMode mode;
	private final Random random;
	private final NetworkConfig config;

	/**
	 * Creates an new provider for configuration values.
	 * 
	 * The following configuration values are used direct or indirect:
	 * <ul>
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#MID_TRACKER}
	 * - determine the tracker mode. Supported values are "NULL" (for
	 * {@link NullMessageIdTracker}), "GROUPED" (for
	 * {@link GroupedMessageIdTracker}), and "MAPBASED" (for
	 * {@link MapBasedMessageIdTracker}).</li>
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#MID_TRACKER_GROUPS}
	 * - determine the group size for the message IDs, if the grouped tracker is
	 * used. Each group is marked as <em>in use</em>, if a MID within the group
	 * is used.</li>
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#EXCHANGE_LIFETIME}
	 * - each (group of a) message ID returned by <em>getNextMessageId</em> is
	 * marked as <em>in use</em> for this amount of time (ms).</li>
	 * <li>{@link org.eclipse.californium.core.network.config.NetworkConfig.Keys#USE_RANDOM_MID_START}
	 * - if this value is {@code true} then the message IDs returned by
	 * <em>getNextMessageId</em> will start at a random index. Otherwise the
	 * first message ID returned will be {@code 0}.</li>
	 * </ul>
	 * 
	 * @param config the configuration to use.
	 * @throws NullPointerException if the config is {@code null}.
	 * @throws IllegalArgumentException if the config contains no value tracker
	 *             mode.
	 */
	public InMemoryMessageIdProvider(final NetworkConfig config) {
		if (config == null) {
			throw new NullPointerException("Config must not be null");
		}
		String textualMode = null;
		TrackerMode mode = TrackerMode.GROUPED;
		try {
			textualMode = config.getString(NetworkConfig.Keys.MID_TRACKER);
			mode = TrackerMode.valueOf(textualMode);
		} catch (IllegalArgumentException e) {
			throw new IllegalArgumentException("Tracker mode '" + textualMode + "' not supported!");
		} catch (NullPointerException e) {
			throw new IllegalArgumentException("Tracker mode not provided/configured!");
		}
		this.config = config;
		this.mode = mode;
		if (config.getBoolean(NetworkConfig.Keys.USE_RANDOM_MID_START)) {
			random = new Random(System.currentTimeMillis());
		} else {
			random = null;
		}
		// 10 minutes
		trackers = new LeastRecentlyUsedCache<>(config.getInt(NetworkConfig.Keys.MAX_ACTIVE_PEERS, 150000),
				config.getLong(NetworkConfig.Keys.MAX_PEER_INACTIVITY_PERIOD, 10 * 60));
	}

	@Override
	public int getNextMessageId(final InetSocketAddress destination) {
		MessageIdTracker tracker = getTracker(destination);
		if (tracker == null) {
			// we have reached the maximum number of active peers
			// TODO: throw an exception?
			return Message.NONE;
		} else {
			return tracker.getNextMessageId();
		}
	}

	private synchronized MessageIdTracker getTracker(final InetSocketAddress destination) {
		MessageIdTracker tracker = trackers.get(destination);
		if (tracker == null && 0 < trackers.remainingCapacity()) {
			// create new tracker for destination lazily
			int mid = null == random ? 0 : random.nextInt(MessageIdTracker.TOTAL_NO_OF_MIDS);
			switch (mode) {
			case NULL:
				tracker = new NullMessageIdTracker(mid);
				break;
			case MAPBASED:
				tracker = new MapBasedMessageIdTracker(mid, config);
				break;
			case GROUPED:
			default:
				tracker = new GroupedMessageIdTracker(mid, config);
				break;
			}
			trackers.put(destination, tracker);
		}
		return tracker;
	}
}
