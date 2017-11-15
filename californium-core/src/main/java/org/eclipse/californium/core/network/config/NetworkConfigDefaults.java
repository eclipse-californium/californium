/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Bosch Software Innovations GmbH - don't use strict request/response matching by default 
 *    Achim Kraus (Bosch Software Innovations GmbH) - add defaults for
 *                                                    DEFAULT_MID_TRACKER,
 *                                                    DEFAULT_MID_TRACKER_GROUPS, and
 *                                                    DEFAULT_EXCHANGE_LIFETIME
 ******************************************************************************/
package org.eclipse.californium.core.network.config;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.GroupedMessageIdTracker;
import org.eclipse.californium.elements.UDPConnector;

/**
 * Default values for the properties of {@code NetworkConfig}.
 *
 */
public class NetworkConfigDefaults {


	/**
	 * The default number of active peers to support.
	 */
	public static final int DEFAULT_MAX_ACTIVE_PEERS = 150000;

	/**
	 * The default timeout after which a peer is considered inactive (in seconds).
	 */
	public static final long DEFAULT_MAX_PEER_INACTIVITY_PERIOD = 10 * 60; // 10 minutes

	/**
	 * The default maximum resource body size that can be transparently transferred
	 * in a blockwise transfer.
	 */
	public static final int DEFAULT_MAX_RESOURCE_BODY_SIZE = 2048; // bytes

	/**
	 * The default maximum amount of time (in milliseconds) between transfers of individual
	 * blocks in a blockwise transfer before the blockwise transfer state is discarded.
	 */
	public static final int DEFAULT_BLOCKWISE_STATUS_LIFETIME = 30 * 1000; // 30 secs

	/**
	 * The default MID tracker.
	 * 
	 * Supported values are {@code NULL}, {@code GROUPED}, or {@code MAPBASED}.
	 * <p>
	 * The default value is {@code GROUPED}.
	 */
	public static final String DEFAULT_MID_TRACKER = "GROUPED";

	/**
	 * The default number of MID groups.
	 * <p>
	 * Used for {@link GroupedMessageIdTracker}. The default value is 16.
	 */
	public static final int DEFAULT_MID_TRACKER_GROUPS = 16;

	/**
	 * The default exchange lifetime in milliseconds.
	 * <p>
	 * The default value is 247s.
	 */
	public static final long DEFAULT_EXCHANGE_LIFETIME = 247 * 1000;

	/*
	 * Accept other message versions than 1
	 * Refuse unknown options
	 * Disable dedupl for GET/..
	 */

	public static void setDefaults(final NetworkConfig config) {

		final int CORES = Runtime.getRuntime().availableProcessors();
		final String OS = System.getProperty("os.name");
		final boolean WINDOWS = OS.startsWith("Windows");

		config.setInt(NetworkConfig.Keys.MAX_ACTIVE_PEERS, DEFAULT_MAX_ACTIVE_PEERS);
		config.setLong(NetworkConfig.Keys.MAX_PEER_INACTIVITY_PERIOD, DEFAULT_MAX_PEER_INACTIVITY_PERIOD);

		config.setInt(NetworkConfig.Keys.COAP_PORT, CoAP.DEFAULT_COAP_PORT);
		config.setInt(NetworkConfig.Keys.COAP_SECURE_PORT, CoAP.DEFAULT_COAP_SECURE_PORT);

		config.setInt(NetworkConfig.Keys.ACK_TIMEOUT, 2000);
		config.setFloat(NetworkConfig.Keys.ACK_RANDOM_FACTOR, 1.5f);
		config.setFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE, 2f);
		config.setInt(NetworkConfig.Keys.MAX_RETRANSMIT, 4);
		config.setLong(NetworkConfig.Keys.EXCHANGE_LIFETIME, DEFAULT_EXCHANGE_LIFETIME); // ms
		config.setLong(NetworkConfig.Keys.NON_LIFETIME, 145 * 1000); // ms
		config.setLong(NetworkConfig.Keys.MAX_TRANSMIT_WAIT, 93 * 1000);
		config.setInt(NetworkConfig.Keys.NSTART, 1);
		config.setInt(NetworkConfig.Keys.LEISURE, 5000);
		config.setFloat(NetworkConfig.Keys.PROBING_RATE, 1f);

		config.setBoolean(NetworkConfig.Keys.USE_RANDOM_MID_START, true);
		config.setString(NetworkConfig.Keys.MID_TRACKER, DEFAULT_MID_TRACKER);
		config.setInt(NetworkConfig.Keys.MID_TRACKER_GROUPS, DEFAULT_MID_TRACKER_GROUPS);
		config.setInt(NetworkConfig.Keys.TOKEN_SIZE_LIMIT, 8);

		config.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 512);
		config.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 1024);
		config.setInt(NetworkConfig.Keys.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_BODY_SIZE);
		config.setInt(NetworkConfig.Keys.BLOCKWISE_STATUS_LIFETIME, DEFAULT_BLOCKWISE_STATUS_LIFETIME); // ms

		config.setLong(NetworkConfig.Keys.NOTIFICATION_CHECK_INTERVAL_TIME, 24 * 60 * 60 * 1000); // ms
		config.setInt(NetworkConfig.Keys.NOTIFICATION_CHECK_INTERVAL_COUNT, 100);
		config.setLong(NetworkConfig.Keys.NOTIFICATION_REREGISTRATION_BACKOFF, 2000); // ms

		config.setBoolean(NetworkConfig.Keys.USE_CONGESTION_CONTROL, false);
		config.setString(NetworkConfig.Keys.CONGESTION_CONTROL_ALGORITHM, "Cocoa"); // see org.eclipse.californium.core.network.stack.congestioncontrol

		config.setInt(NetworkConfig.Keys.PROTOCOL_STAGE_THREAD_COUNT, CORES);
		config.setInt(NetworkConfig.Keys.NETWORK_STAGE_RECEIVER_THREAD_COUNT, WINDOWS ? CORES : 1);
		config.setInt(NetworkConfig.Keys.NETWORK_STAGE_SENDER_THREAD_COUNT, WINDOWS ? CORES : 1);

		config.setInt(NetworkConfig.Keys.UDP_CONNECTOR_DATAGRAM_SIZE, 2048);
		config.setInt(NetworkConfig.Keys.UDP_CONNECTOR_RECEIVE_BUFFER, UDPConnector.UNDEFINED);
		config.setInt(NetworkConfig.Keys.UDP_CONNECTOR_SEND_BUFFER, UDPConnector.UNDEFINED);
		config.setInt(NetworkConfig.Keys.UDP_CONNECTOR_OUT_CAPACITY, Integer.MAX_VALUE); // unbounded

		config.setString(NetworkConfig.Keys.DEDUPLICATOR, NetworkConfig.Keys.DEDUPLICATOR_MARK_AND_SWEEP);
		config.setLong(NetworkConfig.Keys.MARK_AND_SWEEP_INTERVAL, 10 * 1000); // 10 secs
		config.setInt(NetworkConfig.Keys.CROP_ROTATION_PERIOD, 2000);
		config.setBoolean(NetworkConfig.Keys.USE_STRICT_RESPONSE_MATCHING, false);

		config.setInt(NetworkConfig.Keys.HTTP_PORT, 8080);
		config.setInt(NetworkConfig.Keys.HTTP_SERVER_SOCKET_TIMEOUT, 100000);
		config.setInt(NetworkConfig.Keys.HTTP_SERVER_SOCKET_BUFFER_SIZE, 8192);
		config.setInt(NetworkConfig.Keys.HTTP_CACHE_RESPONSE_MAX_AGE, 86400);
		config.setInt(NetworkConfig.Keys.HTTP_CACHE_SIZE, 32);

		config.setString(NetworkConfig.Keys.HEALTH_STATUS_PRINT_LEVEL, "FINEST");
		config.setInt(NetworkConfig.Keys.HEALTH_STATUS_INTERVAL, 60); // s

		config.setInt(NetworkConfig.Keys.TCP_CONNECTION_IDLE_TIMEOUT, 10); // s
		config.setInt(NetworkConfig.Keys.TCP_WORKER_THREADS, 1);
		config.setInt(NetworkConfig.Keys.TCP_CONNECT_TIMEOUT, 10000); // ms
	}

	// prevent instantiation
	private NetworkConfigDefaults() { }
}
