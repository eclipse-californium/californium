/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add InputStream support for environments
 *                                                    without file access.
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
public class NetworkConfig {

	/** The logger. */
	private static final Logger LOGGER = Logger.getLogger(NetworkConfig.class.getCanonicalName());

	/** The default name for the configuration. */
	public static final String DEFAULT = "Californium.properties";

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

		public static final String COAP_PORT = "COAP_PORT";
		public static final String COAP_SECURE_PORT = "COAP_SECURE_PORT";
		public static final String ACK_TIMEOUT = "ACK_TIMEOUT";
		public static final String ACK_RANDOM_FACTOR = "ACK_RANDOM_FACTOR";
		public static final String ACK_TIMEOUT_SCALE = "ACK_TIMEOUT_SCALE";
		public static final String MAX_RETRANSMIT = "MAX_RETRANSMIT";
		public static final String EXCHANGE_LIFETIME = "EXCHANGE_LIFETIME";
		public static final String NON_LIFETIME = "NON_LIFETIME";
		public static final String MAX_TRANSMIT_WAIT = "MAX_TRANSMIT_WAIT";
		public static final String MAX_LATENCY = "MAX_LATENCY";
		public static final String MAX_SERVER_RESPONSE_DELAY = "MAX_SERVER_RESPONSE_DELAY";
		public static final String NSTART = "NSTART";
		public static final String LEISURE = "LEISURE";
		public static final String PROBING_RATE = "PROBING_RATE";

		public static final String USE_RANDOM_MID_START = "USE_RANDOM_MID_START";
		public static final String TOKEN_SIZE_LIMIT = "TOKEN_SIZE_LIMIT";

		public static final String PREFERRED_BLOCK_SIZE = "PREFERRED_BLOCK_SIZE";
		public static final String MAX_MESSAGE_SIZE = "MAX_MESSAGE_SIZE";
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
		public static final String MARK_AND_SWEEP_INTERVAL = "MARK_AND_SWEEP_INTERVAL";
		public static final String DEDUPLICATOR_CROP_ROTATION = "DEDUPLICATOR_CROP_ROTATION";
		public static final String CROP_ROTATION_PERIOD = "CROP_ROTATION_PERIOD";
		public static final String NO_DEDUPLICATOR = "NO_DEDUPLICATOR";

		public static final String HTTP_PORT = "HTTP_PORT";
		public static final String HTTP_SERVER_SOCKET_TIMEOUT = "HTTP_SERVER_SOCKET_TIMEOUT";
		public static final String HTTP_SERVER_SOCKET_BUFFER_SIZE = "HTTP_SERVER_SOCKET_BUFFER_SIZE";
		public static final String HTTP_CACHE_RESPONSE_MAX_AGE = "HTTP_CACHE_RESPONSE_MAX_AGE";
		public static final String HTTP_CACHE_SIZE = "HTTP_CACHE_SIZE";

		public static final String HEALTH_STATUS_PRINT_LEVEL = "HEALTH_STATUS_PRINT_LEVEL";
		public static final String HEALTH_STATUS_INTERVAL = "HEALTH_STATUS_INTERVAL";
	}

	/**
	 * Gives access to the standard network configuration. When a new endpoint
	 * or server is created without a specific network configuration, it will
	 * use this standard configuration.
	 * 
	 * @return the standard configuration
	 */
	public static NetworkConfig getStandard() {
		if (standard == null) {
			synchronized (NetworkConfig.class) {
				if (standard == null)
					createStandardWithFile(new File(DEFAULT));
			}
		}
		return standard;
	}

	/**
	 * Sets the standard configuration.
	 *
	 * @param standard the new standard
	 */
	public static void setStandard(NetworkConfig standard) {
		NetworkConfig.standard = standard;
	}

	/**
	 * Creates the standard without reading it or writing it to a file.
	 *
	 * @return the configuration
	 */
	public static NetworkConfig createStandardWithoutFile() {
		LOGGER.info("Creating standard network configuration properties without a file");
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
			LOGGER.log(Level.WARNING, "cannot load properties from stream", e);
		}
		return standard;
	}

	/**
	 * Creates the standard with a file. If the file with the name
	 * {@link #DEFAULT} exists, the configuration reads the properties from this
	 * file. Otherwise it creates the file.
	 * 
	 * @param file the configuration file
	 * @return the network configuration
	 */
	public static NetworkConfig createStandardWithFile(File file) {
		standard = new NetworkConfig();
		if (file.exists()) {
			LOGGER.info("Loading standard properties from file " + file);
			try {
				standard.load(file);
			} catch (IOException e) {
				LOGGER.log(Level.WARNING, "Error while loading properties from " + file.getAbsolutePath(), e);
			}
		} else {
			LOGGER.info("Storing standard properties in file " + file);
			try {
				standard.store(file);
			} catch (IOException e) {
				LOGGER.log(Level.WARNING, "Error while storing properties to " + file.getAbsolutePath(), e);
			}
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
	 * Load the properties from the specified configuration file.
	 *
	 * @param file the file
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public void load(File file) throws IOException {
		InputStream inStream = new FileInputStream(file);
		properties.load(inStream);
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
	 * Store the configuration in the specified file.
	 *
	 * @param file the file
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public void store(File file) throws IOException {
		store(file, DEFAULT_HEADER);
	}

	/**
	 * Store the configuration in the specified file with the specified header.
	 * 
	 * @param file the file
	 * @param header the header
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public void store(File file, String header) throws IOException {
		if (file == null)
			throw new NullPointerException();
		properties.store(new FileWriter(file), header);
	}

	/**
	 * Gets the value for the specified key as String or null if not found.
	 *
	 * @param key the key
	 * @return the string
	 */
	public String getString(String key) {
		return properties.getProperty(key);
	}

	/**
	 * Gets the value for the specified key as int or 0 if not found.
	 *
	 * @param key the key
	 * @return the int
	 */
	public int getInt(String key) {
		String value = properties.getProperty(key);
		if (value != null) {
			try {
				return Integer.parseInt(value);
			} catch (NumberFormatException e) {
				LOGGER.log(Level.WARNING,
						"Could not convert property \"" + key + "\" with value \"" + value + "\" to integer", e);
			}
		} else {
			LOGGER.warning("Property \"" + key + "\" is undefined");
		}
		return 0;
	}

	/**
	 * Gets the value for the specified key as long or 0 if not found.
	 *
	 * @param key the key
	 * @return the long
	 */
	public long getLong(String key) {
		String value = properties.getProperty(key);
		if (value != null) {
			try {
				return Long.parseLong(value);
			} catch (NumberFormatException e) {
				LOGGER.log(Level.WARNING,
						"Could not convert property \"" + key + "\" with value \"" + value + "\" to long", e);
				return 0;
			}
		} else {
			LOGGER.warning("Property \"" + key + "\" is undefined");
		}
		return 0;
	}

	/**
	 * Gets the value for the specified key as float or 0.0 if not found.
	 *
	 * @param key the key
	 * @return the float
	 */
	public float getFloat(String key) {
		String value = properties.getProperty(key);
		if (value != null) {
			try {
				return Float.parseFloat(value);
			} catch (NumberFormatException e) {
				LOGGER.log(Level.WARNING,
						"Could not convert property \"" + key + "\" with value \"" + value + "\" to float", e);
				return 0;
			}
		} else {
			LOGGER.warning("Property \"" + key + "\" is undefined");
		}
		return 0;
	}

	/**
	 * Gets the value for the specified key as double or 0.0 if not found.
	 *
	 * @param key the key
	 * @return the double
	 */
	public double getDouble(String key) {
		String value = properties.getProperty(key);
		if (value != null) {
			try {
				return Double.parseDouble(value);
			} catch (NumberFormatException e) {
				LOGGER.log(Level.WARNING,
						"Could not convert property \"" + key + "\" with value \"" + value + "\" to double", e);
				return 0;
			}
		} else {
			LOGGER.warning("Property \"" + key + "\" is undefined");
		}
		return 0;
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
			try {
				return Boolean.parseBoolean(value);
			} catch (NumberFormatException e) {
				LOGGER.log(Level.WARNING,
						"Could not convert property \"" + key + "\" with value \"" + value + "\" to boolean", e);
				return false;
			}
		} else {
			LOGGER.warning("Property \"" + key + "\" is undefined");
		}
		return false;
	}

	/**
	 * Associates the specified value with the specified key.
	 *
	 * @param key the key
	 * @param value the value
	 * @return the network configuration
	 */
	public NetworkConfig set(String key, Object value) {
		properties.put(key, String.valueOf(value));
		for (NetworkConfigObserver obs : observers)
			obs.changed(key, value);
		return this;
	}

	/**
	 * Associates the specified value with the specified key.
	 *
	 * @param key the key
	 * @param value the value
	 * @return the network configuration
	 */
	public NetworkConfig setString(String key, String value) {
		properties.put(key, String.valueOf(value));
		for (NetworkConfigObserver obs : observers)
			obs.changed(key, value);
		return this;
	}

	/**
	 * Associates the specified value with the specified key.
	 *
	 * @param key the key
	 * @param value the value
	 * @return the network configuration
	 */
	public NetworkConfig setInt(String key, int value) {
		properties.put(key, String.valueOf(value));
		for (NetworkConfigObserver obs : observers)
			obs.changed(key, value);
		return this;
	}

	/**
	 * Associates the specified value with the specified key.
	 *
	 * @param key the key
	 * @param value the value
	 * @return the network configuration
	 */
	public NetworkConfig setLong(String key, long value) {
		properties.put(key, String.valueOf(value));
		for (NetworkConfigObserver obs : observers)
			obs.changed(key, value);
		return this;
	}

	/**
	 * Associates the specified value with the specified key.
	 *
	 * @param key the key
	 * @param value the value
	 * @return the network configuration
	 */
	public NetworkConfig setFloat(String key, float value) {
		properties.put(key, String.valueOf(value));
		for (NetworkConfigObserver obs : observers)
			obs.changed(key, value);
		return this;
	}

	/**
	 * Associates the specified value with the specified key.
	 *
	 * @param key the key
	 * @param value the value
	 * @return the network configuration
	 */
	public NetworkConfig setDouble(String key, double value) {
		properties.put(key, String.valueOf(value));
		for (NetworkConfigObserver obs : observers)
			obs.changed(key, value);
		return this;
	}

	/**
	 * Associates the specified value with the specified key.
	 *
	 * @param key the key
	 * @param value the value
	 * @return the network configuration
	 */
	public NetworkConfig setBoolean(String key, boolean value) {
		properties.put(key, String.valueOf(value));
		for (NetworkConfigObserver obs : observers)
			obs.changed(key, value);
		return this;
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
