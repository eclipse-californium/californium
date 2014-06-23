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
 *    Stefan Jucker - DTLS implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.util;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.logging.Logger;

import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;


/**
 * This class implements Californium's property registry.
 * 
 * It is used to manage CoAP- and Californium-specific constants in a central
 * place. The properties are initialized in the init() section and can be
 * overridden by a user-defined .properties file. If the file does not exist
 * upon initialization, it will be created so that a valid configuration always
 * exists.
 */
public class ScProperties extends java.util.Properties {

	private static final Logger LOG = Logger.getLogger(ScProperties.class.getCanonicalName());

	/**
	 * auto-generated to eliminate warning
	 */
	private static final long serialVersionUID = 8499865907306466190L;

	/** The header for Californium property files. */
	private static final String HEADER = "Scandium Properties file";

	/** The name of the default properties file. */
	private static final String DEFAULT_FILENAME = "Scandium.properties";

	// default properties used by the library
	public static final ScProperties std = new ScProperties(DEFAULT_FILENAME);
	
	// Constructors ////////////////////////////////////////////////////////////
	
	public ScProperties(String fileName) {
		init();
		initUserDefined(fileName);
	}
	
	public Double getDbl(String key) {
		String value = getProperty(key);
		if (value != null) {
			try {
				return Double.parseDouble(value);
			} catch (NumberFormatException e) {
				LOG.severe(String.format("Invalid double property: %s=%s", key, value));
			}
		} else {
			LOG.severe(String.format("Undefined double property: %s", key));
		}
		return 0.0;
	}

	public int getInt(String key) {
		String value = getProperty(key);
		if (value != null) {
			try {
				return Integer.parseInt(value.trim());
			} catch (NumberFormatException e) {
				LOG.severe(String.format("Invalid integer property: %s=%s", key, value));
			}
		} else {
			LOG.severe(String.format("Undefined integer property: %s", key));
		}
		return 0;
	}

	public String getStr(String key) {
		String value = getProperty(key);
		if (value == null) {
			LOG.severe(String.format("Undefined string property: %s", key));
		}
		return value;
	}

	public boolean getBool(String key) {
		String value = getProperty(key);
		if (value != null) {
			try {
				return Boolean.parseBoolean(value);
			} catch (NumberFormatException e) {
				LOG.severe(String.format("Invalid boolean property: %s=%s", key, value));
			}
		} else {
			LOG.severe(String.format("Undefined boolean property: %s", key));
		}
		return false;
	}
	
	public void load(String fileName) throws IOException {
		InputStream in = new FileInputStream(fileName);
		load(in);
	}

	public void set(String key, double value) {
		setProperty(key, String.valueOf(value));
	}

	public void set(String key, int value) {
		setProperty(key, String.valueOf(value));
	}

	public void set(String key, String value) {
		setProperty(key, value);
	}
	
	public void set(String key, boolean value) {
		setProperty(key, String.valueOf(value));
	}

	public void store(String fileName) throws IOException {
		OutputStream out = new FileOutputStream(fileName);
		store(out, HEADER);
	}

	private void init() {

		/* DTLS constants */
		set("DEFAULT_PORT", 5683);

		// the location of the key store (contains private key and corresponding
		// certificate chain)
		set("KEY_STORE_LOCATION", "certs/keyStore.jks");

		// the location of the trust store (contains all trusted certificate
		// authorities)
		set("TRUST_STORE_LOCATION", "certs/trustStore.jks");

		// the preferred cipher suite
		// SSL_NULL_WITH_NULL_NULL
		// TLS_PSK_WITH_AES_128_CCM_8
		// TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
		set("PREFERRED_CIPHER_SUITE", CipherSuite.TLS_PSK_WITH_AES_128_CCM_8.toString());

		// the identity hint when using the pre-shared key mode
		set("PSK_IDENTITY", "PSK_Identity");

		// whether the certificate message should only contain the peer's public
		// key or the full X.509 certificate
		set("USE_RAW_PUBLIC_KEY", true);

		// whether the server requires mutual authentication
		set("CLIENT_AUTHENTICATION", false);

		// the initial timer value for retransmission; rfc6347, section: 4.2.4.1
		set("RETRANSMISSION_TIMEOUT", 1000); // [milliseconds]

		// maximal number of retransmissions before the attempt to transmit a message is canceled
		set("MAX_RETRANSMIT", 4);

		// the maximum fragment size before DTLS fragmentation must be applied
		set("MAX_FRAGMENT_LENGTH", 4096); // [bytes]
	}

	private void initUserDefined(String fileName) {
		try {
			load(fileName);
		} catch (IOException e) {
			// file does not exist:
			// write default properties
			try {
				store(fileName);
			} catch (IOException e1) {
				LOG.warning(String.format("Failed to create configuration file: %s", e1.getMessage()));
			}
		}
	}

}
