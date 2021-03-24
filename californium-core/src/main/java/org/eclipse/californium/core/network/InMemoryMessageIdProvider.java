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

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.LeastRecentlyUsedCache;
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

	public enum TrackerMode {
		NULL, GROUPED, MAPBASED
	}

	private final LeastRecentlyUsedCache<InetSocketAddress, MessageIdTracker> trackers;
	private final MessageIdTracker multicastTracker;
	private final TrackerMode mode;
	private final Random random;
	private final NetworkConfig config;
	private final int multicastBaseMid;

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
		TrackerMode mode;
		try {
			textualMode = config.getString(NetworkConfig.Keys.MID_TRACKER);
			mode = TrackerMode.valueOf(textualMode);
		} catch (IllegalArgumentException e) {
			throw new IllegalArgumentException("Tracker mode '" + textualMode + "' not supported!");
		} catch (NullPointerException e) {
			throw new IllegalArgumentException("Tracker mode not provided/configured!");
		}
		this.mode = mode;
		this.config = config;
		if (config.getBoolean(NetworkConfig.Keys.USE_RANDOM_MID_START)) {
			random = new Random(ClockUtil.nanoRealtime());
		} else {
			random = null;
		}
		// 10 minutes
		trackers = new LeastRecentlyUsedCache<>(config.getInt(NetworkConfig.Keys.MAX_ACTIVE_PEERS, 150000),
				config.getLong(NetworkConfig.Keys.MAX_PEER_INACTIVITY_PERIOD, 10 * 60));
		trackers.setEvictingOnReadAccess(false);
		int multicastBaseMid = config.getInt(NetworkConfig.Keys.MULTICAST_BASE_MID);
		if (0 < multicastBaseMid) {
			this.multicastBaseMid = multicastBaseMid;
			int max = MessageIdTracker.TOTAL_NO_OF_MIDS;
			int mid = null == random ? multicastBaseMid : random.nextInt(max - multicastBaseMid) + multicastBaseMid;
			switch (mode) {
			case NULL:
				multicastTracker = new NullMessageIdTracker(mid, multicastBaseMid, max);
				break;
			case MAPBASED:
				multicastTracker = new MapBasedMessageIdTracker(mid, multicastBaseMid, max, config);
				break;
			case GROUPED:
			default:
				multicastTracker = new GroupedMessageIdTracker(mid, multicastBaseMid, max, config);
				break;
			}
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
			// TODO: throw an exception?
			return Message.NONE;
		} else {
			return tracker.getNextMessageId();
		}
	}

	private synchronized MessageIdTracker getTracker(final InetSocketAddress destination) {
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
			switch (mode) {
			case NULL:
				tracker = new NullMessageIdTracker(mid, 0, multicastBaseMid);
				break;
			case MAPBASED:
				tracker = new MapBasedMessageIdTracker(mid, 0, multicastBaseMid, config);
				break;
			case GROUPED:
			default:
				tracker = new GroupedMessageIdTracker(mid, 0, multicastBaseMid, config);
				break;
			}
			if (trackers.put(destination, tracker)) {
				return tracker;
			} else {
				return null;
			}
		}
		return tracker;
	}
}
