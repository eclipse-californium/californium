/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.core.network.config;

import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.elements.UDPConnector;


public class NetworkConfigDefaults {

	/*
	 * Accept other message versions than 1
	 * Refuse unknown options
	 * Disable dedupl for GET/..
	 */
	
	/**
	 * TODO: These property names should be defined in class NetworkConfig instead, since this
	 * class' concern is only providing default values for them.
	 * The constants should then also all be renamed to bear a prefix like PROPERTY_ in order
	 * to distinguish them from the default values for which constants should be introduced
	 * bearing a prefix like VALUE_ ...
	 */
	public static final String DEFAULT_COAP_PORT = "DEFAULT_COAP_PORT";
	public static final String PROPERTY_DEFAULT_COAPS_PORT = "DEFAULT_COAPS_PORT";
	public static final String ACK_TIMEOUT = "ACK_TIMEOUT";
	public static final String ACK_RANDOM_FACTOR = "ACK_RANDOM_FACTOR";
	public static final String ACK_TIMEOUT_SCALE = "ACK_TIMEOUT_SCALE";
	public static final String NSTART = "NSTART";
	public static final String DEFAULT_LEISURE = "DEFAULT_LEISURE";
	public static final String PROBING_RATE = "PROBING_RATE";
	public static final String MAX_MESSAGE_SIZE = "MAX_MESSAGE_SIZE";
	public static final String DEFAULT_BLOCK_SIZE = "DEFAULT_BLOCK_SIZE";
	public static final String NOTIFICATION_MAX_AGE = "NOTIFICATION_MAX_AGE";
	public static final String NOTIFICATION_CHECK_INTERVAL_TIME = "NOTIFICATION_CHECK_INTERVAL";
	public static final String NOTIFICATION_CHECK_INTERVAL_COUNT = "NOTIFICATION_CHECK_INTERVAL_COUNT";
	public static final String NOTIFICATION_REREGISTRATION_BACKOFF = "NOTIFICATION_REREGISTRATION_BACKOFF";
	public static final String DEDUPLICATOR = "DEDUPLICATOR";
	public static final String DEDUPLICATOR_MARK_AND_SWEEP = "DEDUPLICATOR_MARK_AND_SWEEP";
	public static final String DEDUPLICATOR_CROP_ROTATION = "DEDUPLICATOR_CROP_ROTATIO";
	public static final String NO_DEDUPLICATOR = "NO_DEDUPLICATOR";
	public static final String MARK_AND_SWEEP_INTERVAL = "MARK_AND_SWEEP_INTERVAL";
	public static final String CROP_ROTATION_PERIOD = "CROP_ROTATION_PERIOD";
	public static final String EXCHANGE_LIFECYCLE = "EXCHANGE_LIFECYCLE";
	public static final String MAX_RETRANSMIT = "MAX_RETRANSMIT";
	public static final String DEFAULT_ENDPOINT_THREAD_COUNT = "DEFAULT_ENDPOINT_THREAD_COUNT";
	public static final String SERVER_THRESD_NUMER = "SERVER_THRESD_NUMER";
	
	public static final String USE_COCOA = "USE_COCOA";
	public static final String USE_RANDOM_TOKEN_START = "USE_RANDOM_TOKEN_START";
	public static final String USE_RANDOM_MID_START = "USE_RANDOM_MID_START";
	
	public static final String UDP_CONNECTOR_RECEIVE_BUFFER = "UDP_CONNECTOR_RECEIVE_BUFFER";
	public static final String UDP_CONNECTOR_SEND_BUFFER = "UDP_CONNECTOR_SEND_BUFFER";
	public static final String UDP_CONNECTOR_RECEIVER_THREAD_COUNT = "UDP_CONNECTOR_RECEIVER_THREAD_COUNT";
	public static final String UDP_CONNECTOR_SENDER_THREAD_COUNT = "UDP_CONNECTOR_SENDER_THREAD_COUNT";
	public static final String UDP_CONNECTOR_DATAGRAM_SIZE = "UDP_CONNECTOR_DATAGRAM_SIZE";
	public static final String UDP_CONNECTOR_OUT_CAPACITY = "UDP_CONNECTOR_OUT_CAPACITY";
	public static final String UDP_CONNECTOR_LOG_PACKETS = "UDP_CONNECTOR_LOG_PACKETS";
	
	public static final String HTTP_PORT = "HTTP_PORT";
	public static final String HTTP_SERVER_SOCKET_TIMEOUT = "HTTP_SERVER_SOCKET_TIMEOUT";
	public static final String HTTP_SERVER_SOCKET_BUFFER_SIZE = "HTTP_SERVER_SOCKET_BUFFER_SIZE";
	public static final String HTTP_CACHE_RESPONSE_MAX_AGE = "HTTP_CACHE_RESPONSE_MAX_AGE";
	public static final String HTTP_CACHE_SIZE = "HTTP_CACHE_SIZE";
	
	public static final String MAX_TRANSMIT_WAIT = "MAX_TRANSMIT_WAIT";
	
	public static void setDefaults(NetworkConfig config) {
		config.setInt(DEFAULT_COAP_PORT, EndpointManager.DEFAULT_COAP_PORT);
		config.setInt(ACK_TIMEOUT, 2000);
		config.setFloat(ACK_RANDOM_FACTOR, 1.5f);
		config.setInt(ACK_TIMEOUT_SCALE, 2);
		config.setInt(NSTART, 1);
		config.setInt(DEFAULT_LEISURE, 5000);
		config.setFloat(PROBING_RATE, 1f);
		config.setInt(MAX_RETRANSMIT, 4);
		config.setLong(EXCHANGE_LIFECYCLE, 247 * 1000); // in ms
		config.setBoolean(USE_COCOA, false);
		config.setBoolean(USE_RANDOM_TOKEN_START, true);
		config.setBoolean(USE_RANDOM_MID_START, true);
		
		config.setInt(MAX_MESSAGE_SIZE, 1024);
		config.setInt(DEFAULT_BLOCK_SIZE, 512);
		config.setInt(SERVER_THRESD_NUMER, Runtime.getRuntime().availableProcessors());
		
		config.setLong(NOTIFICATION_MAX_AGE, 128 * 1000); // ms
		config.setLong(NOTIFICATION_CHECK_INTERVAL_TIME, 24 * 60 * 60 * 1000); // ms
		config.setInt(NOTIFICATION_CHECK_INTERVAL_COUNT, 100);
		config.setLong(NOTIFICATION_REREGISTRATION_BACKOFF, 2000); // ms
		config.setString(DEDUPLICATOR, DEDUPLICATOR_MARK_AND_SWEEP);
		config.setLong(MARK_AND_SWEEP_INTERVAL, 10 * 1000);
		config.setInt(CROP_ROTATION_PERIOD, 2000);
		config.setInt(DEFAULT_ENDPOINT_THREAD_COUNT, 1);
		
		config.setInt(UDP_CONNECTOR_RECEIVE_BUFFER, UDPConnector.UNDEFINED);
		config.setInt(UDP_CONNECTOR_SEND_BUFFER, UDPConnector.UNDEFINED);
		config.setInt(UDP_CONNECTOR_RECEIVER_THREAD_COUNT, 1);
		config.setInt(UDP_CONNECTOR_SENDER_THREAD_COUNT, 1);
		config.setInt(UDP_CONNECTOR_DATAGRAM_SIZE, 2000);
		config.setInt(UDP_CONNECTOR_OUT_CAPACITY, Integer.MAX_VALUE); // unbounded
		config.setBoolean(UDP_CONNECTOR_LOG_PACKETS, false);
		
		config.setInt(HTTP_PORT, 8080);
		config.setInt(HTTP_SERVER_SOCKET_TIMEOUT, 100000);
		config.setInt(HTTP_SERVER_SOCKET_BUFFER_SIZE, 8192);
		config.setInt(HTTP_CACHE_RESPONSE_MAX_AGE, 86400);
		config.setInt(HTTP_CACHE_SIZE, 32);
		
		config.setLong(MAX_TRANSMIT_WAIT, 93 * 1000);
	}
	
	// prevent instantiation
	private NetworkConfigDefaults() { }
	
	// Defining logging properties in this configuration leads to a bootstrap
	// problem: The NetworkConfig wants to write a log when loading the
	// properties and the log wants to know the logging properties when writing
	// that log.
	//	public static final String LOG_LEVEL = "LOG_LEVEL";
	//	public static final String LOG_SHOW_THREAD_ID = "LOG_SHOW_THREAD_ID";
	//	public static final String LOG_SHOW_LEVEL = "LOG_SHOW_LEVEL";
	//	public static final String LOG_SHOW_CLASS = "LOG_SHOW_CLASS";
	//	public static final String LOG_SHOW_MESSAGE = "LOG_SHOW_MESSAGE";
	//	public static final String LOG_SHOW_SOURCE = "LOG_SHOW_SOURCE";
	//	public static final String LOG_SHOW_METHOD = "LOG_SHOW_METHOD";
	//	public static final String LOG_SHOW_THREAD = "LOG_SHOW_THREAD";
	//	public static final String LOG_SHOW_DATE = "LOG_SHOW_DATE";
	//	public static final String LOG_SHOW_TIME = "LOG_SHOW_TIME";
}
