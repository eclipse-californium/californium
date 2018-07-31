/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/

package org.eclipse.californium.core.network.interceptors;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.util.LeastRecentlyUsedCache;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Origin tracer with anonymized inet addresses.
 * 
 * Filter InetSocketAddress to log at most one message per client every
 * {@link #DEFAULT_MESSAGE_FILTER_TIMEOUT_IN_SECONDS}. The InetAddress is hashed
 * and only the first {@link #ID_LENGTH} resulting bytes are written as address.
 * Though the hash function is initialized with a random value, which is
 * generated at startup, the addresses will only match to the same values
 * between restarts.
 */
public final class AnonymizedOriginTracer extends MessageInterceptorAdapter {

	private static final Logger LOGGER = LoggerFactory.getLogger(AnonymizedOriginTracer.class);
	/**
	 * Length of anonymized address.
	 */
	private static final int ID_LENGTH = 6;
	/**
	 * Initial capacity for filter- and address-caches.
	 */
	private static final int INITIAL_CAPACITY = 1000;
	/**
	 * Maximum capacity for filter- and address-caches.
	 */
	private static final int MAX_CAPACITY = 10000;
	/**
	 * Message filter timeout. Value in seconds.
	 */
	private static final long DEFAULT_MESSAGE_FILTER_TIMEOUT_IN_SECONDS = 60; // 60s
	/**
	 * Timeout for clients cache. Value in seconds.
	 */
	private static final long HOST_TIMEOUT_IN_SECONDS = 60 * 60 * 24; // 24h

	/**
	 * Cache for hashed client addresses.
	 */
	private static final LeastRecentlyUsedCache<InetAddress, String> CLIENT_CACHE = new LeastRecentlyUsedCache<InetAddress, String>(
			INITIAL_CAPACITY, MAX_CAPACITY, HOST_TIMEOUT_IN_SECONDS);

	/**
	 * Hmac to anonymize the client address.
	 */
	private static final Mac HMAC;
	/**
	 * Random key to anonymize the client address. Initialized at startup.
	 */
	private static final SecretKeySpec KEY;

	static {
		SecureRandom rng = new SecureRandom();
		byte[] rd = new byte[32];
		rng.nextBytes(rd);
		KEY = new SecretKeySpec(rd, "MAC");
		Mac mac = null;
		try {
			mac = Mac.getInstance("HmacSHA256");
		} catch (NoSuchAlgorithmException e) {
		}
		HMAC = mac;
		CLIENT_CACHE.setEvictingOnReadAccess(true);
	}

	/**
	 * Cache for filter message based on inet socket address.
	 */
	private final LeastRecentlyUsedCache<InetSocketAddress, String> currentTests = new LeastRecentlyUsedCache<InetSocketAddress, String>(
			INITIAL_CAPACITY, MAX_CAPACITY, DEFAULT_MESSAGE_FILTER_TIMEOUT_IN_SECONDS);

	/**
	 * Schema name. Added to log message.
	 */
	private final String scheme;

	/**
	 * Create tracer.
	 * 
	 * @param scheme scheme to be added to log. {@code null}, if no scheme
	 *            should be added to the log.
	 */
	public AnonymizedOriginTracer(String scheme) {
		this(scheme, DEFAULT_MESSAGE_FILTER_TIMEOUT_IN_SECONDS);
	}

	/**
	 * Create tracer.
	 * 
	 * @param scheme scheme to be added to log. {@code null}, if no scheme
	 *            should be added to the log.
	 * @param filterTimeout timeout to filter messages based on their inet
	 *            socket address. Value in seconds.
	 */
	public AnonymizedOriginTracer(String scheme, long filterTimeout) {
		this.scheme = scheme;
		currentTests.setExpirationThreshold(filterTimeout);
	}

	@Override
	public void receiveRequest(Request request) {
		log(request);
	}

	@Override
	public void receiveEmptyMessage(EmptyMessage message) {
		// only log pings
		if (message.getType() == Type.CON) {
			log(message);
		}
	}

	/**
	 * Log anonymized message origin.
	 * 
	 * The logging is filtered by the messages inet socket address, suppressing
	 * additional messages for the same inet socket address until the timeout
	 * expires.
	 * 
	 * @param message message to log.
	 * @return {@code true}, if log was written, {@code false}, otherwise.
	 */
	public boolean log(Message message) {
		InetSocketAddress address = message.getSourceContext().getPeerAddress();
		synchronized (currentTests) {
			if (currentTests.get(address) != null) {
				// already logged in the past REQUEST_TIMEOUT
				return false;
			}
			currentTests.put(address, scheme);
		}
		String id = getAnonymizedOrigin(address.getAddress());
		if (id != null) {
			if (scheme == null) {
				LOGGER.trace("{}:{}", id, address.getPort());
			} else {
				LOGGER.trace("{}://{}:{}", scheme, id, address.getPort());
			}
			return true;
		}
		return false;
	}

	/**
	 * Anonymize the provided address.
	 * 
	 * Calculate hash of address bytes using an initial random created at start
	 * time. Only the first {@link #ID_LENGTH} bytes are then used to build the
	 * identifier using a hexadecimal encoding. The result is cached for faster
	 * reuse.
	 * 
	 * @param address address to be hashed.
	 * @return hash of address.
	 */
	public static String getAnonymizedOrigin(InetAddress address) {
		synchronized (CLIENT_CACHE) {
			String id = CLIENT_CACHE.get(address);
			if (id == null) {
				byte[] raw = address.getAddress().clone();
				try {
					if (HMAC == null) {
						byte[] mask = KEY.getEncoded();
						for (int index = 0; index < raw.length; ++index) {
							raw[index] ^= mask[index];
						}
					} else {
						HMAC.init(KEY);
						raw = HMAC.doFinal(raw);
					}
				} catch (InvalidKeyException e) {
				}
				id = StringUtil.byteArray2HexString(raw, StringUtil.NO_SEPARATOR, ID_LENGTH);
				CLIENT_CACHE.put(address, id);
			}
			return id;
		}
	}

}
