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
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove nested synchronize.
 *                                                    reduce blocking on 
 *                                                    tracker.getNextMessageId()
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce MessageIdTracker
 *                                                    interface and rename old
 *                                                    MessageIdTracker to
 *                                                    MapBasedMessageIdTracker.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add multicast mid tracker.
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.net.InetSocketAddress;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.config.CoapConfig.TrackerMode;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.LeastRecentlyUpdatedCache;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A provider for message IDs thats keeps track of all message IDs in memory.
 * <p>
 * This provider maintains an instance of {@link MessageIdTracker} for each
 * endpoint identified by IP address and port.
 */
public class InMemoryMessageIdProvider implements MessageIdProvider {

	private static final Logger LOG = LoggerFactory.getLogger(InMemoryMessageIdProvider.class);

	private final LeastRecentlyUpdatedCache<InetSocketAddress, MessageIdTracker> trackers;
	private final MessageIdTracker multicastTracker;
	private final TrackerMode mode;
	private final Random random;
	private final Configuration config;
	private final int multicastBaseMid;

	/**
	 * Creates an new provider for configuration values.
	 * 
	 * The following configuration values are used direct or indirect:
	 * <ul>
	 * <li>{@link CoapConfig#MID_TRACKER} - determine the tracker mode.
	 * Supported values are "NULL" (for {@link NullMessageIdTracker}), "GROUPED"
	 * (for {@link GroupedMessageIdTracker}), and "MAPBASED" (for
	 * {@link MapBasedMessageIdTracker}).</li>
	 * <li>{@link CoapConfig#MID_TRACKER_GROUPS} - determine the group size for
	 * the message IDs, if the grouped tracker is used. Each group is marked as
	 * <em>in use</em>, if a MID within the group is used.</li>
	 * <li>{@link CoapConfig#EXCHANGE_LIFETIME} - each (group of a) message ID
	 * returned by <em>getNextMessageId</em> is marked as <em>in use</em> for
	 * this amount of time (ms).</li>
	 * <li>{@link CoapConfig#USE_RANDOM_MID_START} - if this value is
	 * {@code true} then the message IDs returned by <em>getNextMessageId</em>
	 * will start at a random index. Otherwise the first message ID returned
	 * will be {@code 0}.</li>
	 * </ul>
	 * 
	 * @param config the configuration to use.
	 * @throws NullPointerException if the config is {@code null}.
	 * @throws IllegalArgumentException if the config contains no value tracker
	 *             mode.
	 * @since 3.0 (changed parameter to Configuration)
	 */
	public InMemoryMessageIdProvider(final Configuration config) {
		if (config == null) {
			throw new NullPointerException("Config must not be null");
		}
		TrackerMode mode = config.get(CoapConfig.MID_TRACKER);
		this.mode = mode;
		this.config = config;
		if (config.get(CoapConfig.USE_RANDOM_MID_START)) {
			random = new Random(ClockUtil.nanoRealtime());
		} else {
			random = null;
		}
		// 10 minutes
		trackers = new LeastRecentlyUpdatedCache<>(config.get(CoapConfig.MAX_ACTIVE_PEERS),
				config.get(CoapConfig.MAX_PEER_INACTIVITY_PERIOD, TimeUnit.SECONDS), TimeUnit.SECONDS);
		int multicastBaseMid = config.get(CoapConfig.MULTICAST_BASE_MID);
		if (0 < multicastBaseMid) {
			this.multicastBaseMid = multicastBaseMid;
			int max = MessageIdTracker.TOTAL_NO_OF_MIDS;
			int mid = null == random ? multicastBaseMid : random.nextInt(max - multicastBaseMid) + multicastBaseMid;
			multicastTracker = createTracker(mid, multicastBaseMid, max, config);
		} else {
			this.multicastBaseMid = MessageIdTracker.TOTAL_NO_OF_MIDS;
			multicastTracker = null;
		}
	}

	@Override
	public int getNextMessageId(final InetSocketAddress destination) {
		MessageIdTracker tracker = getTracker(destination);
		if (tracker == null) {
			// we have reached the maximum number of active peers
			String time = trackers.getExpirationThreshold(TimeUnit.SECONDS) + "s";
			throw new IllegalStateException(
					"No MID available, max. peers " + trackers.size() + " exhausted! (Timeout " + time + ".)");
		} else {
			return tracker.getNextMessageId();
		}
	}

	private MessageIdTracker getTracker(final InetSocketAddress destination) {
		// destination mc
		// => use special range 65001-65535
		// destination sp
		// => use special range 0 - 65000

		if (NetworkInterfacesUtil.isMultiAddress(destination.getAddress())) {
			if (multicastTracker == null) {
				LOG.warn(
						"Destination address {} is a multicast address, please configure NetworkConfig to support multicast messaging",
						destination);
			}
			return multicastTracker;
		}

		MessageIdTracker tracker = trackers.get(destination);
		if (tracker == null) {
			// create new tracker for destination lazily
			int mid = null == random ? 0 : random.nextInt(multicastBaseMid);
			MessageIdTracker newTracker = createTracker(mid, 0, multicastBaseMid, config);
			trackers.writeLock().lock();
			try {
				tracker = trackers.get(destination);
				if (tracker == null) {
					if (trackers.put(destination, newTracker)) {
						return newTracker;
					} else {
						return null;
					}
				}
			} finally {
				trackers.writeLock().unlock();
			}
		}
		if (tracker != null) {
			trackers.update(destination);
		}
		return tracker;
	}

	/**
	 * Create message-id-tracker based on the provided parameters.
	 * 
	 * @param initialMid initial value of MID
	 * @param minMid minimum value of MID (inclusive)
	 * @param maxMid maximum value of MID (exclusive)
	 * @param config configuration
	 * @return create message-id-tracker
	 * @since 3.5
	 */
	private MessageIdTracker createTracker(int initialMid, int minMid, int maxMid, Configuration config) {
		MessageIdTracker tracker;
		switch (mode) {
		case NULL:
			tracker = new NullMessageIdTracker(initialMid, minMid, maxMid);
			break;
		case MAPBASED:
			tracker = new MapBasedMessageIdTracker(initialMid, minMid, maxMid, config);
			break;
		case GROUPED:
		default:
			tracker = new GroupedMessageIdTracker(initialMid, minMid, maxMid, config);
			break;
		}
		return tracker;
	}
}
