/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - increase DEFAULT_MAX_RESOURCE_BODY_SIZE
 *                                                    to 8192.
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace USE_STRICT_RESPONSE_MATCHING
 *                                                    by DTLS_RESPONSE_MATCHING
 ******************************************************************************/
package org.eclipse.californium.core.network.config;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.GroupedMessageIdTracker;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
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
	public static final int DEFAULT_MAX_RESOURCE_BODY_SIZE = 8192; // bytes

	/**
	 * The default maximum amount of time (in milliseconds) between transfers of individual
	 * blocks in a blockwise transfer before the blockwise transfer state is discarded.
	 * <p>
	 * The default value of 5 minutes is chosen to be a little more than the default
	 * EXCHANGE_LIFETIME of 247s.
	 */
	public static final int DEFAULT_BLOCKWISE_STATUS_LIFETIME = 5 * 60 * 1000; // 5 mins [ms]
	
	/**
	 * The default mode used to respond for early bockwise negociation when response can be sent on one packet.
	 * <p>
	 * The default value is false, which indicate that the server will not include the Block2 option.
	 */
	public static final boolean DEFAULT_BLOCKWISE_STRICT_BLOCK2_OPTION = false;
	
	/**
	 * The default value for {@link Keys#PREFERRED_BLOCK_SIZE}
	 */
	public static final int DEFAULT_PREFERRED_BLOCK_SIZE = 512;
	
	/**
	 * The default value for {@link Keys#MAX_MESSAGE_SIZE}
	 */
	public static final int DEFAULT_MAX_MESSAGE_SIZE = 1024;

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

	public static final String DEFAULT_DEDUPLICATOR =  Keys.DEDUPLICATOR_MARK_AND_SWEEP;

	/**
	 * Default for message per peers mark and sweep.
	 * @since 2.3 
	 */
	public static final int DEFAULT_PEERS_MARK_AND_SWEEP_MESSAGES = 64;

	public static final long DEFAULT_MARK_AND_SWEEP_INTERVAL =  10 * 1000; // 10 secs

	public static final int DEFAULT_CROP_ROTATION_PERIOD = (int) DEFAULT_EXCHANGE_LIFETIME;

	public static final boolean DEFAULT_DEDUPLICATOR_AUTO_REPLACE = true;

	/**
	 * The default DTLS response matcher.
	 * 
	 * Supported values are {@code STRICT}, {@code RELAXED}, or {@code PRINCIPAL}.
	 * <p>
	 * The default value is {@code STRICT}.
	 */
	public static final String DEFAULT_RESPONSE_MATCHING = "STRICT";

	/**
	 * The default tcp connection idle timeout in seconds.
	 * <p>
	 * The default value is 10s.
	 */
	public static final int DEFAULT_TCP_CONNECTION_IDLE_TIMEOUT = 10; // 10s [s]

	/**
	 * The default tcp connect timeout in milliseconds.
	 * <p>
	 * The default value is 10s.
	 */
	public static final int DEFAULT_TCP_CONNECT_TIMEOUT = 10000; // 10s [ms]

	/**
	 * The default tls handshake timeout in milliseconds.
	 * <p>
	 * The default value is 10s.
	 */
	public static final int DEFAULT_TLS_HANDSHAKE_TIMEOUT = 10000; // 10s [ms]

	/**
	 * The default secure session timeout in seconds.
	 * <p>
	 * The default value is 24h.
	 */
	public static final int DEFAULT_SECURE_SESSION_TIMEOUT = 60 * 60 * 24; // 24h [s]

	/**
	 * The default dtls auto resumption timeout in milliseconds.
	 * <p>
	 * The default value is 30s.
	 */
	public static final int DEFAULT_DTLS_AUTO_RESUME_TIMEOUT = 30000; // 30s [ms]

	/**
	 * The default health status interval in seconds.
	 */
	public static final int DEFAULT_HEALTH_STATUS_INTERVAL = 0; // 0s
	/**
	 * The default multicast mid range.
	 * Enable multicast, and MID reserve range of 65000..65335 for multicast.
	 * 0 to disable multicast.
	 */
	public static final int DEFAULT_MULTICAST_BASE_MID = 65000;

	/**
	 * The default dtls connection id length.
	 * <p>
	 * The default value is "" for disabled.
	 */
	public static final String DEFAULT_DTLS_CONNECTION_ID_LENGTH = ""; // disabled
	public static final String DEFAULT_DTLS_CONNECTION_ID_NODE_ID = ""; // disabled

	public static void setDefaults(final NetworkConfig config) {

		final int CORES = Runtime.getRuntime().availableProcessors();
		final String OS = System.getProperty("os.name");
		final boolean WINDOWS = OS.startsWith("Windows");

		config.setInt(Keys.MAX_ACTIVE_PEERS, DEFAULT_MAX_ACTIVE_PEERS);
		config.setLong(Keys.MAX_PEER_INACTIVITY_PERIOD, DEFAULT_MAX_PEER_INACTIVITY_PERIOD);

		config.setInt(Keys.COAP_PORT, CoAP.DEFAULT_COAP_PORT);
		config.setInt(Keys.COAP_SECURE_PORT, CoAP.DEFAULT_COAP_SECURE_PORT);

		config.setInt(Keys.ACK_TIMEOUT, 2000);
		config.setFloat(Keys.ACK_RANDOM_FACTOR, 1.5f);
		config.setFloat(Keys.ACK_TIMEOUT_SCALE, 2f);
		config.setInt(Keys.MAX_RETRANSMIT, 4);
		config.setLong(Keys.EXCHANGE_LIFETIME, DEFAULT_EXCHANGE_LIFETIME); // ms
		config.setLong(Keys.NON_LIFETIME, 145 * 1000); // ms
		config.setLong(Keys.MAX_TRANSMIT_WAIT, 93 * 1000);
		config.setInt(Keys.NSTART, 1);
		config.setInt(Keys.LEISURE, 5000);
		config.setFloat(Keys.PROBING_RATE, 1f);
		config.setBoolean(Keys.USE_MESSAGE_OFFLOADING, false);

		config.setInt(Keys.MAX_LATENCY, 100 * 1000); //ms
		config.setInt(Keys.MAX_SERVER_RESPONSE_DELAY, 250 * 1000); //ms

		config.setBoolean(Keys.USE_RANDOM_MID_START, true);
		config.setString(Keys.MID_TRACKER, DEFAULT_MID_TRACKER);
		config.setInt(Keys.MID_TRACKER_GROUPS, DEFAULT_MID_TRACKER_GROUPS);
		config.setInt(Keys.TOKEN_SIZE_LIMIT, 8);

		config.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_PREFERRED_BLOCK_SIZE);
		config.setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_MAX_MESSAGE_SIZE);
		config.setInt(Keys.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_BODY_SIZE);
		config.setInt(Keys.BLOCKWISE_STATUS_LIFETIME, DEFAULT_BLOCKWISE_STATUS_LIFETIME); // [ms]
		config.setBoolean(Keys.BLOCKWISE_STRICT_BLOCK2_OPTION, DEFAULT_BLOCKWISE_STRICT_BLOCK2_OPTION);

		
		config.setLong(Keys.NOTIFICATION_CHECK_INTERVAL_TIME, 24 * 60 * 60 * 1000); //24 [ms]
		config.setInt(Keys.NOTIFICATION_CHECK_INTERVAL_COUNT, 100);
		config.setLong(Keys.NOTIFICATION_REREGISTRATION_BACKOFF, 2000); // [ms]

		config.setBoolean(Keys.USE_CONGESTION_CONTROL, false);
		config.setString(Keys.CONGESTION_CONTROL_ALGORITHM, "Cocoa"); // see org.eclipse.californium.core.network.stack.congestioncontrol

		config.setInt(Keys.PROTOCOL_STAGE_THREAD_COUNT, CORES);
		config.setInt(Keys.NETWORK_STAGE_RECEIVER_THREAD_COUNT, WINDOWS ? CORES : 1);
		config.setInt(Keys.NETWORK_STAGE_SENDER_THREAD_COUNT, WINDOWS ? CORES : 1);

		config.setInt(Keys.UDP_CONNECTOR_DATAGRAM_SIZE, 2048);
		config.setInt(Keys.UDP_CONNECTOR_RECEIVE_BUFFER, UDPConnector.UNDEFINED);
		config.setInt(Keys.UDP_CONNECTOR_SEND_BUFFER, UDPConnector.UNDEFINED);
		config.setInt(Keys.UDP_CONNECTOR_OUT_CAPACITY, Integer.MAX_VALUE); // unbounded

		config.setString(Keys.DEDUPLICATOR, DEFAULT_DEDUPLICATOR);
		config.setLong(Keys.MARK_AND_SWEEP_INTERVAL, DEFAULT_MARK_AND_SWEEP_INTERVAL);
		config.setInt(Keys.PEERS_MARK_AND_SWEEP_MESSAGES, DEFAULT_PEERS_MARK_AND_SWEEP_MESSAGES);
		config.setInt(Keys.CROP_ROTATION_PERIOD, DEFAULT_CROP_ROTATION_PERIOD);
		config.setBoolean(Keys.DEDUPLICATOR_AUTO_REPLACE, DEFAULT_DEDUPLICATOR_AUTO_REPLACE);
		config.setString(Keys.RESPONSE_MATCHING, DEFAULT_RESPONSE_MATCHING);

		config.setInt(Keys.HTTP_PORT, 8080);
		config.setInt(Keys.HTTP_SERVER_SOCKET_TIMEOUT, 100000);
		config.setInt(Keys.HTTP_SERVER_SOCKET_BUFFER_SIZE, 8192);
		config.setInt(Keys.HTTP_CACHE_RESPONSE_MAX_AGE, 86400);
		config.setInt(Keys.HTTP_CACHE_SIZE, 32);

		config.setInt(Keys.HEALTH_STATUS_INTERVAL, DEFAULT_HEALTH_STATUS_INTERVAL); // s, 0 for disable

		config.setInt(Keys.TCP_CONNECTION_IDLE_TIMEOUT, DEFAULT_TCP_CONNECTION_IDLE_TIMEOUT); // s
		config.setInt(Keys.TCP_WORKER_THREADS, 1);
		config.setInt(Keys.TCP_CONNECT_TIMEOUT, DEFAULT_TCP_CONNECT_TIMEOUT); // ms
		config.setInt(Keys.TLS_HANDSHAKE_TIMEOUT, DEFAULT_TLS_HANDSHAKE_TIMEOUT); // ms

		config.setLong(Keys.SECURE_SESSION_TIMEOUT, DEFAULT_SECURE_SESSION_TIMEOUT);
		config.setLong(Keys.DTLS_AUTO_RESUME_TIMEOUT, DEFAULT_DTLS_AUTO_RESUME_TIMEOUT);
		config.setString(Keys.DTLS_CONNECTION_ID_LENGTH, DEFAULT_DTLS_CONNECTION_ID_LENGTH);
		config.setString(Keys.DTLS_CONNECTION_ID_NODE_ID, DEFAULT_DTLS_CONNECTION_ID_NODE_ID);

		config.setInt(Keys.MULTICAST_BASE_MID, DEFAULT_MULTICAST_BASE_MID);
	}

	// prevent instantiation
	private NetworkConfigDefaults() { }
}
