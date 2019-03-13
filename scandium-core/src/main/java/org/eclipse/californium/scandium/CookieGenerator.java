/*******************************************************************************
 * Copyright (c) 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Simon Bernard (Sierra Wireless)               - initial implementation
 *    Achim Kraus (Bosch Software Innovations GmbH) - recreate hmac, if clone fails.
 *                                                    Support for android (4.4),
 *                                                    which fails to clone hmac.
 *                                                    Use nanoTime instead of 
 *                                                    currentTimeMillis.
 *    Achim Kraus (Bosch Software Innovations GmbH) - use binary address instead of
 *                                                    string
 */
package org.eclipse.californium.scandium;

import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.scandium.dtls.ClientHello;
import org.eclipse.californium.scandium.dtls.CompressionMethod;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

/**
 * Generates a cookie in such a way that they can be verified without retaining
 * any per-client state on the server.
 *
 * <pre>
 * Cookie = HMAC(Secret, Client - IP, Client - Parameters)
 * </pre>
 *
 * as suggested
 * <a href="http://tools.ietf.org/html/rfc6347#section-4.2.1">here</a>.
 *
 */
public class CookieGenerator {

	/**
	 * Key lifetime in nanos.
	 */
	private static final long KEY_LIFE_TIME = TimeUnit.MINUTES.toNanos(5);

	/**
	 * Nanos of next key generation.
	 */
	private long nextKeyGenerationNanos;
	/**
	 * Last generated key.
	 */
	private SecretKeySpec lastSecretKey;
	/**
	 * Lock to protect {@link #hmac}, {@link #lastSecretKey} and
	 * {@link #nextKeyGenerationNanos}
	 */
	private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
	/**
	 * Mac initialized with {@link #lastSecretKey}, if clonable.
	 */
	private Mac hmac;

	// attributes used for random byte generation
	private final SecureRandom rng = new SecureRandom();
	byte[] rd = new byte[32];

	/**
	 * Create HMAC.
	 * 
	 * Create HMAC cloning the master {@link #hmac}, if cloning is supported, or
	 * create a new HAMC initialized with {@link #lastSecretKey}, if cloning is
	 * not supported.
	 * 
	 * MUST be called in read or write scope of {@link #lock}!
	 * 
	 * @return new HMAC
	 * @throws GeneralSecurityException if an security related exception occurs
	 *             when creating the HMAC.
	 */
	private final Mac createHMAC() throws GeneralSecurityException {
		if (hmac != null) {
			// clone is supported
			try {
				return (Mac) hmac.clone();
			} catch (CloneNotSupportedException e) {
				throw new IllegalStateException("hmac doesn't support clone and MUST therefore be null!");
			}
		} else {
			// clone is not supported
			Mac hmac = Mac.getInstance("HmacSHA256");
			hmac.init(lastSecretKey);
			return hmac;
		}
	}

	/**
	 * Return a fresh HMAC algorithm instance.
	 * 
	 * @return fresh HMAC
	 * @throws GeneralSecurityException if an security related exception occurs
	 *             when refreshing the HMAC.
	 */
	private Mac getHMAC() throws GeneralSecurityException {

		lock.readLock().lock();
		try {
			// check, if a secret key is already created and not expired
			if (lastSecretKey != null && !isKeyExpired()) {
				return createHMAC();
			}
		} finally {
			lock.readLock().unlock();
		}

		// if key expired or secret key not initialized;
		lock.writeLock().lock();
		try {
			// Recheck state because another thread might have acquired
			// write lock and changed state before we did.
			if (lastSecretKey == null) {
				// initialize
				generateSecretKey();
				hmac = Mac.getInstance("HmacSHA256");
				hmac.init(lastSecretKey);
				return (Mac) hmac.clone();
			} else if (isKeyExpired()) {
				generateSecretKey();
			}
			return createHMAC();
		} catch (CloneNotSupportedException ex) {
			// catch, if MacSpi is not cloneable (android)!
			Mac hmac = this.hmac;
			this.hmac = null;
			return hmac;
		} finally {
			lock.writeLock().unlock();
		}
	}

	/**
	 * check, if {@link #lastSecretKey} has expired.
	 * 
	 * MUST be called in read or write scope of {@link #lock}!
	 * 
	 * @return {@code true}, if key is expired, {@code false} otherwise.
	 */
	private boolean isKeyExpired() {
		// consider sign wrap in longs (very optimistic about the uptime :-) )
		return (ClockUtil.nanoRealtime() - nextKeyGenerationNanos) >= 0;
	}

	/**
	 * Generate a new secret key for MAC algorithm.
	 * 
	 * MUST be called in write scope of {@link #lock}!
	 */
	private void generateSecretKey() {
		nextKeyGenerationNanos = ClockUtil.nanoRealtime() + KEY_LIFE_TIME;
		rng.nextBytes(rd);
		lastSecretKey = new SecretKeySpec(rd, "MAC");
	}

	/**
	 * Generates a cookie in such a way that they can be verified without
	 * retaining any per-client state on the server.
	 *
	 * <pre>
	 * Cookie = HMAC(Secret, Client - IP, Client - Parameters)
	 * </pre>
	 *
	 * as suggested
	 * <a href="http://tools.ietf.org/html/rfc6347#section-4.2.1">here</a>.
	 *
	 * @param clientHello received client hello to generate a cookie for
	 * @return the cookie generated from the client's parameters
	 * @throws GeneralSecurityException if the cookie cannot be computed
	 */
	public byte[] generateCookie(final ClientHello clientHello) throws GeneralSecurityException {
		// Cookie = HMAC(Secret, Client-IP, Client-Parameters)
		final Mac hmac = getHMAC();
		// Client-IP
		InetSocketAddress peer = clientHello.getPeer();
		hmac.update(peer.getAddress().getAddress());
		int port = peer.getPort();
		hmac.update((byte) (port >>> 8));
		hmac.update((byte) port);
		// Client-Parameters
		hmac.update((byte) clientHello.getClientVersion().getMajor());
		hmac.update((byte) clientHello.getClientVersion().getMinor());
		hmac.update(clientHello.getRandom().getRandomBytes());
		hmac.update(clientHello.getSessionId().getBytes());
		hmac.update(CipherSuite.listToByteArray(clientHello.getCipherSuites()));
		hmac.update(CompressionMethod.listToByteArray(clientHello.getCompressionMethods()));
		return hmac.doFinal();
	}
}
