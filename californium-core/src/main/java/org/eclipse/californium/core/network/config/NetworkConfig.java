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
 *    Bosch Software Innovations GmbH - add key for selecting strict request/response matching
 *    Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add InputStream support for environments
 *                                                    without file access.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add new keys for MID tracker
 ******************************************************************************/
package org.eclipse.californium.core.network.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The configuration for a Californium server, endpoint and/or connector.
 */
public final class NetworkConfig {

	private static final Logger LOGGER = Logger.getLogger(NetworkConfig.class.getName());

	/** The default name for the configuration. */
	public static final String DEFAULT_FILE_NAME = "Californium.properties";

	/** The default header for a configuration file. */
	public static final String DEFAULT_HEADER = "Californium CoAP Properties file";

	/** The standard configuration that is used if none is defined. */
	private static NetworkConfig standard;

	/** The properties. */
	private Properties properties;

	/** The list of config observers. */
	private List<NetworkConfigObserver> observers = new LinkedList<NetworkConfigObserver>();

	/**
	 * Network configuration key names
	 */
	public class Keys {

		/**
		 * The maximum number of active peers supported.
		 * <p>
		 * An active peer is a node with which we exchange CoAP messages. For
		 * each active peer we need to maintain some state, e.g. we need to keep
		 * track of MIDs and tokens in use with the peer. It therefore is
		 * reasonable to limit the number of peers so that memory consumption
		 * can be better predicted.
		 * <p>
		 * The default value of this property is
		 * {@link NetworkConfigDefaults#DEFAULT_MAX_ACTIVE_PEERS}.
		 * <p>
		 * For clients this value can safely be set to a small one or two digit
		 * number as most clients will only communicate with a small set of
		 * peers (servers).
		 */
		public static final String MAX_ACTIVE_PEERS = "MAX_ACTIVE_PEERS";
		/**
		 * The maximum number of seconds a peer may be inactive for before it is
		 * considered stale and all state associated with it can be discarded.
		 */
		public static final String MAX_PEER_INACTIVITY_PERIOD = "MAX_PEER_INACTIVITY_PERIOD";

		public static final String COAP_PORT = "COAP_PORT";
		public static final String COAP_SECURE_PORT = "COAP_SECURE_PORT";
		public static final String ACK_TIMEOUT = "ACK_TIMEOUT";
		public static final String ACK_RANDOM_FACTOR = "ACK_RANDOM_FACTOR";
		public static final String ACK_TIMEOUT_SCALE = "ACK_TIMEOUT_SCALE";
		public static final String MAX_RETRANSMIT = "MAX_RETRANSMIT";
		/**
		 * The EXCHANGE_LIFETIME as defined by the CoAP spec in MILLISECONDS.
		 */
		public static final String EXCHANGE_LIFETIME = "EXCHANGE_LIFETIME";
		public static final String NON_LIFETIME = "NON_LIFETIME";
		public static final String MAX_TRANSMIT_WAIT = "MAX_TRANSMIT_WAIT";
		public static final String NSTART = "NSTART";
		public static final String LEISURE = "LEISURE";
		public static final String PROBING_RATE = "PROBING_RATE";

		public static final String USE_RANDOM_MID_START = "USE_RANDOM_MID_START";
		public static final String MID_TRACKER = "MID_TACKER";
		public static final String MID_TRACKER_GROUPS = "MID_TRACKER_GROUPS";
		public static final String TOKEN_SIZE_LIMIT = "TOKEN_SIZE_LIMIT";

		/**
		 * The block size (number of bytes) to use when doing a blockwise
		 * transfer. This value serves as the upper limit for block size in
		 * blockwise transfers.
		 */
		public static final String PREFERRED_BLOCK_SIZE = "PREFERRED_BLOCK_SIZE";
		/**
		 * The maximum payload size (in bytes) that can be transferred in a
		 * single message, i.e. without requiring a blockwise transfer.
		 * 
		 * NB: this value MUST be adapted to the maximum message size supported
		 * by the transport layer. In particular, this value cannot exceed the
		 * network's MTU if UDP is used as the transport protocol.
		 */
		public static final String MAX_MESSAGE_SIZE = "MAX_MESSAGE_SIZE";
		/**
		 * The maximum size of a resource body (in bytes) that will be accepted
		 * as the payload of a POST/PUT or the response to a GET request in a
		 * <em>transparent</em> blockwise transfer.
		 * <p>
		 * This option serves as a safeguard against excessive memory
		 * consumption when many resources contain large bodies that cannot be
		 * transferred in a single CoAP message. This option has no impact on
		 * *manually* managed blockwise transfers in which the blocks are
		 * handled individually.
		 * <p>
		 * Note that this option does not prevent local clients or resource
		 * implementations from sending large bodies as part of a request or
		 * response to a peer.
		 * <p>
		 * The default value of this property is
		 * {@link NetworkConfigDefaults#DEFAULT_MAX_RESOURCE_BODY_SIZE}.
		 * <p>
		 * A value of {@code 0} turns off transparent handling of blockwise
		 * transfers altogether.
		 */
		public static final String MAX_RESOURCE_BODY_SIZE = "MAX_RESOURCE_BODY_SIZE";
		/**
		 * The maximum amount of time (in milliseconds) allowed between
		 * transfers of individual blocks in a blockwise transfer before the
		 * blockwise transfer state is discarded.
		 * <p>
		 * The default value of this property is
		 * {@link NetworkConfigDefaults#DEFAULT_BLOCKWISE_STATUS_LIFETIME}.
		 */
		public static final String BLOCKWISE_STATUS_LIFETIME = "BLOCKWISE_STATUS_LIFETIME";

		public static final String NOTIFICATION_CHECK_INTERVAL_TIME = "NOTIFICATION_CHECK_INTERVAL";
		public static final String NOTIFICATION_CHECK_INTERVAL_COUNT = "NOTIFICATION_CHECK_INTERVAL_COUNT";
		public static final String NOTIFICATION_REREGISTRATION_BACKOFF = "NOTIFICATION_REREGISTRATION_BACKOFF";

		public static final String USE_CONGESTION_CONTROL = "USE_CONGESTION_CONTROL";
		public static final String CONGESTION_CONTROL_ALGORITHM = "CONGESTION_CONTROL_ALGORITHM";

		public static final String PROTOCOL_STAGE_THREAD_COUNT = "PROTOCOL_STAGE_THREAD_COUNT";
		public static final String NETWORK_STAGE_RECEIVER_THREAD_COUNT = "NETWORK_STAGE_RECEIVER_THREAD_COUNT";
		public static final String NETWORK_STAGE_SENDER_THREAD_COUNT = "NETWORK_STAGE_SENDER_THREAD_COUNT";

		public static final String UDP_CONNECTOR_DATAGRAM_SIZE = "UDP_CONNECTOR_DATAGRAM_SIZE";
		public static final String UDP_CONNECTOR_RECEIVE_BUFFER = "UDP_CONNECTOR_RECEIVE_BUFFER";
		public static final String UDP_CONNECTOR_SEND_BUFFER = "UDP_CONNECTOR_SEND_BUFFER";
		public static final String UDP_CONNECTOR_OUT_CAPACITY = "UDP_CONNECTOR_OUT_CAPACITY";

		public static final String DEDUPLICATOR = "DEDUPLICATOR";
		public static final String DEDUPLICATOR_MARK_AND_SWEEP = "DEDUPLICATOR_MARK_AND_SWEEP";
		/**
		 * The interval after which the next sweep run should occur (in
		 * MILLISECONDS).
		 */
		public static final String MARK_AND_SWEEP_INTERVAL = "MARK_AND_SWEEP_INTERVAL";
		public static final String DEDUPLICATOR_CROP_ROTATION = "DEDUPLICATOR_CROP_ROTATION";
		public static final String CROP_ROTATION_PERIOD = "CROP_ROTATION_PERIOD";
		public static final String NO_DEDUPLICATOR = "NO_DEDUPLICATOR";
		public static final String USE_STRICT_RESPONSE_MATCHING = "USE_STRICT_RESPONSE_MATCHING";

		public static final String HTTP_PORT = "HTTP_PORT";
		public static final String HTTP_SERVER_SOCKET_TIMEOUT = "HTTP_SERVER_SOCKET_TIMEOUT";
		public static final String HTTP_SERVER_SOCKET_BUFFER_SIZE = "HTTP_SERVER_SOCKET_BUFFER_SIZE";
		public static final String HTTP_CACHE_RESPONSE_MAX_AGE = "HTTP_CACHE_RESPONSE_MAX_AGE";
		public static final String HTTP_CACHE_SIZE = "HTTP_CACHE_SIZE";

		public static final String HEALTH_STATUS_PRINT_LEVEL = "HEALTH_STATUS_PRINT_LEVEL";
		public static final String HEALTH_STATUS_INTERVAL = "HEALTH_STATUS_INTERVAL";

		/** Properties for TCP connector. */
		public static final String TCP_CONNECTION_IDLE_TIMEOUT = "TCP_CONNECTION_IDLE_TIMEOUT";
		public static final String TCP_CONNECT_TIMEOUT = "TCP_CONNECT_TIMEOUT";
		public static final String TCP_WORKER_THREADS = "TCP_WORKER_THREADS";
	}

	/**
	 * Gives access to the standard network configuration. When a new endpoint
	 * or server is created without a specific network configuration, it will
	 * use this standard configuration.
	 * 
	 * @return the standard configuration
	 */
	public static NetworkConfig getStandard() {
		synchronized (NetworkConfig.class) {
			if (standard == null)
				createStandardWithFile(new File(DEFAULT_FILE_NAME));
		}
		return standard;
	}

	/**
	 * Sets the standard configuration.
	 *
	 * @param standard the new standard
	 */
	public static void setStandard(final NetworkConfig standard) {
		NetworkConfig.standard = standard;
	}

	/**
	 * Creates the standard without reading it or writing it to a file.
	 *
	 * @return the configuration
	 */
	public static NetworkConfig createStandardWithoutFile() {
		LOGGER.config("Creating standard network configuration properties without a file");
		return standard = new NetworkConfig();
	}

	/**
	 * Creates the standard from stream.
	 *
	 * Support environments without file access.
	 * 
	 * @param inStream input stream to read properties.
	 * @return the configuration
	 */
	public static NetworkConfig createStandardFromStream(InputStream inStream) {
		LOGGER.config("Creating standard network configuration properties from stream");
		standard = new NetworkConfig();
		try {
			standard.load(inStream);
		} catch (IOException e) {
			LOGGER.log(Level.WARNING, "cannot load properties from stream: {0}", e.getMessage());
		}
		return standard;
	}

	/**
	 * Creates the standard with a file. If the file with the name
	 * {@link #DEFAULT_FILE_NAME} exists, the configuration reads the properties
	 * from this file. Otherwise it creates the file.
	 * 
	 * @param file the configuration file
	 * @return the network configuration
	 */
	public static NetworkConfig createStandardWithFile(final File file) {
		standard = new NetworkConfig();
		if (file.exists()) {
			standard.load(file);
		} else {
			standard.store(file);
		}
		return standard;
	}

	/**
	 * Instantiates a new network configuration and sets the default values
	 * defined in {@link NetworkConfigDefaults}.
	 */
	public NetworkConfig() {
		this.properties = new Properties();
		NetworkConfigDefaults.setDefaults(this);
	}

	/**
	 * Loads properties from a file.
	 *
	 * @param file the file
	 * @throws NullPointerException if the file is {@code null}.
	 */
	public void load(final File file) {
		if (file == null) {
			throw new NullPointerException("file must not be null");
		} else {
			LOGGER.log(Level.INFO, "loading properties from file {0}", file.getAbsolutePath());
			try (InputStream inStream = new FileInputStream(file)) {
				load(inStream);
			} catch (IOException e) {
				LOGGER.log(Level.WARNING, "cannot load properties from file {0}: {1}",
						new Object[] { file.getAbsolutePath(), e.getMessage() });
			}
		}
	}

	/**
	 * Loads properties from a input stream.
	 *
	 * @param inStream the input stream
	 * @throws NullPointerException if the inStream is {@code null}.
	 */
	public void load(final InputStream inStream) throws IOException {
		if (inStream == null) {
			throw new NullPointerException("input stream must not be null");
		}
		properties.load(inStream);
	}

	/**
	 * Stores the configuration to a file.
	 *
	 * @param file The file to write to.
	 * @throws NullPointerException if the file is {@code null}.
	 */
	public void store(final File file) {
		store(file, DEFAULT_HEADER);
	}

	/**
	 * Stores the configuration to a file using a given header.
	 * 
	 * @param file The file to write to.
	 * @param header The header to write to the top of the file.
	 * @throws NullPointerException if the file is {@code null}.
	 */
	public void store(File file, String header) {
		if (file == null) {
			throw new NullPointerException("file must not be null");
		} else {
			LOGGER.log(Level.INFO, "writing properties to file {0}", file.getAbsolutePath());
			try (FileWriter writer = new FileWriter(file)) {
				properties.store(writer, header);
			} catch (IOException e) {
				LOGGER.log(Level.WARNING, "cannot write properties to file {0}: {1}",
						new Object[] { file.getAbsolutePath(), e.getMessage() });
			}
		}
	}

	/**
	 * Gets the string value for a key.
	 *
	 * @param key the key to look up.
	 * @return the value or {@code null} if this configuration does not contain
	 *         the given key.
	 */
	public String getString(final String key) {
		return properties.getProperty(key);
	}

	/**
	 * Gets the string value for a key.
	 *
	 * @param key the key the key to look up.
	 * @param defaultValue the default value.
	 * @return the value for the key if this configuration contains a value for
	 *         the key, otherwise the default value.
	 */
	public String getString(final String key, final String defaultValue) {
		String result = properties.getProperty(key);
		return result != null ? result : defaultValue;
	}

	/**
	 * Gets the integer value for a key.
	 *
	 * @param key the key to look up.
	 * @return the value for the key or {@code 0} if this configuration does not
	 *         contain a value for the given key or the value is not an integer.
	 */
	public int getInt(final String key) {
		return getInt(key, 0);
	}

	/**
	 * Gets the integer value for a key.
	 *
	 * @param key the key to look up.
	 * @param defaultValue the default value to return if there is no value
	 *            registered for the key.
	 * @return the value for the key if this configuration contains a value for
	 *         the key and the value is an integer, otherwise the default value.
	 */
	public int getInt(final String key, final int defaultValue) {
		return getNumberValue(new PropertyParser<Integer>() {

			@Override
			public Integer parseValue(String value) {
				return Integer.parseInt(value);
			}
		}, key, defaultValue);
	}

	/**
	 * Gets the long value for a key.
	 *
	 * @param key the key to look up.
	 * @return the value for the key or {@code 0} if this configuration does not
	 *         contain a value for the given key or the value is not a long.
	 */
	public long getLong(final String key) {
		return getLong(key, 0L);
	}

	/**
	 * Gets the long value for a key.
	 *
	 * @param key the key to look up.
	 * @param defaultValue the default value to return if there is no value
	 *            registered for the key.
	 * @return the value for the key if this configuration contains a value for
	 *         the key and the value is a long, otherwise the default value.
	 */
	public long getLong(final String key, final long defaultValue) {
		return getNumberValue(new PropertyParser<Long>() {

			@Override
			public Long parseValue(String value) {
				return Long.parseLong(value);
			}
		}, key, defaultValue);
	}

	/**
	 * Gets the float value for a key.
	 *
	 * @param key the key to look up.
	 * @return the value for the key or {@code 0.0} if this configuration does
	 *         not contain a value for the given key or the value is not a
	 *         float.
	 */
	public float getFloat(final String key) {
		return getFloat(key, 0.0F);
	}

	/**
	 * Gets the float value for a key.
	 *
	 * @param key the key to look up.
	 * @param defaultValue the default value to return if there is no value
	 *            registered for the key.
	 * @return the value for the key if this configuration contains a value for
	 *         the key and the value is a float, otherwise the default value.
	 */
	public float getFloat(final String key, final float defaultValue) {
		return getNumberValue(new PropertyParser<Float>() {

			@Override
			public Float parseValue(String value) {
				return Float.parseFloat(value);
			}
		}, key, defaultValue);
	}

	/**
	 * Gets the double value for a key.
	 *
	 * @param key the key to look up.
	 * @return the value for the key or {@code 0.0} if this configuration does
	 *         not contain a value for the given key or the value is not a
	 *         double.
	 */
	public double getDouble(final String key) {
		return getDouble(key, 0.0D);
	}

	/**
	 * Gets the double value for a key.
	 *
	 * @param key the key to look up.
	 * @param defaultValue the default value to return if there is no value
	 *            registered for the key.
	 * @return the value for the key if this configuration contains the key and
	 *         the value is an double, otherwise the default value.
	 */
	public double getDouble(final String key, final double defaultValue) {
		return getNumberValue(new PropertyParser<Double>() {

			@Override
			public Double parseValue(String value) {
				return Double.parseDouble(value);
			}
		}, key, defaultValue);
	}

	private <T> T getNumberValue(final PropertyParser<T> parser, final String key, final T defaultValue) {
		T result = defaultValue;
		String value = properties.getProperty(key);
		if (value != null) {
			try {
				result = parser.parseValue(value);
			} catch (NumberFormatException e) {
				LOGGER.log(Level.WARNING, "value for key [{0}] is not a {1}, returning default value",
						new Object[] { key, defaultValue.getClass() });
			}
		} else {
			LOGGER.log(Level.WARNING, "key [{0}] is undefined, returning default value", key);
		}
		return result;
	}

	/**
	 * Gets the value for the specified key as boolean or false if not found.
	 *
	 * @param key the key
	 * @return the boolean
	 */
	public boolean getBoolean(String key) {
		String value = properties.getProperty(key);
		if (value != null) {
			return Boolean.parseBoolean(value);
		} else {
			LOGGER.log(Level.WARNING, "Key [{0}] is undefined", key);
			return false;
		}
	}

	private interface PropertyParser<T> {

		T parseValue(String value);
	}

	/**
	 * Associates the specified value with the specified key.
	 *
	 * @param key the key
	 * @param value the value
	 * @return the network configuration
	 */
	public NetworkConfig set(String key, Object value) {
		if (key == null) {
			throw new NullPointerException("key must not be null");
		} else if (value == null) {
			throw new NullPointerException("value must not be null");
		} else {
			properties.put(key, String.valueOf(value));
			for (NetworkConfigObserver obs : observers) {
				obs.changed(key, value);
			}
			return this;
		}
	}

	/**
	 * Associates the specified value with the specified key.
	 *
	 * @param key the key
	 * @param value the value
	 * @return the network configuration
	 */
	public NetworkConfig setString(String key, String value) {
		return set(key, value);
	}

	/**
	 * Associates the specified value with the specified key.
	 *
	 * @param key the key
	 * @param value the value
	 * @return the network configuration
	 */
	public NetworkConfig setInt(String key, int value) {
		return set(key, String.valueOf(value));
	}

	/**
	 * Associates the specified value with the specified key.
	 *
	 * @param key the key
	 * @param value the value
	 * @return the network configuration
	 */
	public NetworkConfig setLong(String key, long value) {
		return set(key, String.valueOf(value));
	}

	/**
	 * Associates the specified value with the specified key.
	 *
	 * @param key the key
	 * @param value the value
	 * @return the network configuration
	 */
	public NetworkConfig setFloat(String key, float value) {
		return set(key, String.valueOf(value));
	}

	/**
	 * Associates the specified value with the specified key.
	 *
	 * @param key the key
	 * @param value the value
	 * @return the network configuration
	 */
	public NetworkConfig setDouble(String key, double value) {
		return set(key, String.valueOf(value));
	}

	/**
	 * Associates the specified value with the specified key.
	 *
	 * @param key the key
	 * @param value the value
	 * @return the network configuration
	 */
	public NetworkConfig setBoolean(String key, boolean value) {
		return set(key, String.valueOf(value));
	}

	public NetworkConfig addConfigObserver(NetworkConfigObserver observer) {
		observers.add(observer);
		return this;
	}

	public NetworkConfig removeConfigObserver(NetworkConfigObserver observer) {
		observers.remove(observer);
		return this;
	}
}
