/*******************************************************************************
 * Copyright (c) 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
import javax.crypto.SecretKey;

import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.scandium.dtls.ClientHello;
import org.eclipse.californium.scandium.dtls.CompressionMethod;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalMac;
import org.eclipse.californium.scandium.util.SecretUtil;

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
 * Note: redesigned in 2.3 to use {@link ThreadLocalMac} instead of
 * {@link Mac#clone()}.
 */
public class CookieGenerator {

	/**
	 * Key lifetime in nanos.
	 */
	public static final long COOKIE_LIFE_TIME = TimeUnit.MINUTES.toNanos(5);

	/**
	 * Nanos of next key generation.
	 */
	private long nextKeyGenerationNanos;
	/**
	 * Current secret key.
	 */
	private SecretKey currentSecretKey;
	/**
	 * Past secret key.
	 */
	private SecretKey pastSecretKey;
	/**
	 * Lock to protect access to {@link #secretKeys}, {@link #randomBytes} and
	 * {@link #randomGenerator}.
	 */
	private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

	// attributes used for random byte generation
	private final SecureRandom randomGenerator = new SecureRandom();
	private final byte[] randomBytes = new byte[32];

	/**
	 * Return the secret key for cookie generation.
	 * 
	 * Secret key is refreshed every {@link #KEY_LIFE_TIME} nanoseconds.
	 * 
	 * @return secret key
	 * @since 2.3
	 */
	private SecretKey getSecretKey() {

		lock.readLock().lock();
		long now = ClockUtil.nanoRealtime();
		try {
			// check, if a secret key is already created and not expired
			if (currentSecretKey != null && (now - nextKeyGenerationNanos) < 0) {
				return currentSecretKey;
			}
		} finally {
			lock.readLock().unlock();
		}

		// if key expired or secret key not initialized;
		lock.writeLock().lock();
		try {
			// re-check, if a secret key is already created and not expired
			if (currentSecretKey != null && (now - nextKeyGenerationNanos) < 0) {
				return currentSecretKey;
			}
			randomGenerator.nextBytes(randomBytes);
			nextKeyGenerationNanos = now + COOKIE_LIFE_TIME;
			// shift secret keys
			pastSecretKey = currentSecretKey;
			currentSecretKey = SecretUtil.create(randomBytes, "MAC");
			return currentSecretKey;
		} finally {
			lock.writeLock().unlock();
		}
	}

	/**
	 * Return the secret key of the past period.
	 * 
	 * @return past secret key
	 * @since 2.3
	 */
	private SecretKey getPastSecretKey() {

		lock.readLock().lock();
		try {
			return pastSecretKey;
		} finally {
			lock.readLock().unlock();
		}
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
	 * @param secretKey to generate a cookie for
	 * @return the cookie generated from the client's parameters
	 * @throws GeneralSecurityException if the cookie cannot be computed
	 * @since 2.3
	 */
	private byte[] generateCookie(final ClientHello clientHello, SecretKey secretKey) throws GeneralSecurityException {
		// Cookie = HMAC(Secret, Client-IP, Client-Parameters)
		final Mac hmac = CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256.getThreadLocalMac();
		hmac.init(secretKey);
		// Client-IP
		InetSocketAddress peer = clientHello.getPeer();
		hmac.update(peer.getAddress().getAddress());
		int port = peer.getPort();
		hmac.update((byte) (port >>> 8));
		hmac.update((byte) port);
		// Client-Parameters
		hmac.update((byte) clientHello.getClientVersion().getMajor());
		hmac.update((byte) clientHello.getClientVersion().getMinor());
		hmac.update(clientHello.getRandom().getBytes());
		hmac.update(clientHello.getSessionId().getBytes());
		hmac.update(CipherSuite.listToByteArray(clientHello.getCipherSuites()));
		hmac.update(CompressionMethod.listToByteArray(clientHello.getCompressionMethods()));
		return hmac.doFinal();
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
		return generateCookie(clientHello, getSecretKey());
	}

	/**
	 * Generates the cookie using the secret key of the past period.
	 * 
	 * @param clientHello received client hello to generate a cookie for
	 * @return the cookie generated from the client's parameters. {@code null},
	 *         if no secret key of the past period is available.
	 * @throws GeneralSecurityException if the cookie cannot be computed
	 * @since 2.3
	 */
	public byte[] generatePastCookie(final ClientHello clientHello) throws GeneralSecurityException {
		SecretKey secretKey = getPastSecretKey();
		if (secretKey != null) {
			return generateCookie(clientHello, secretKey);
		} else {
			return null;
		}
	}
}
