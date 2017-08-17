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
 */
package org.eclipse.californium.scandium;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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

	// guard access to cookieMacKey
	private Object cookieMacKeyLock = new Object();
	// last time when the master key was generated
	private long lastGenerationDate = System.currentTimeMillis();
	private SecretKey cookieMacKey = new SecretKeySpec(randomBytes(), "MAC");

	/** generate a random byte[] of length 32 **/
	private static byte[] randomBytes() {
		SecureRandom rng = new SecureRandom();
		byte[] result = new byte[32];
		rng.nextBytes(result);
		return result;
	}

	private SecretKey getMacKeyForCookies() {
		synchronized (cookieMacKeyLock) {
			// if the last generation was more than 5 minute ago, let's generate
			// a new key
			if (System.currentTimeMillis() - lastGenerationDate > TimeUnit.MINUTES.toMillis(5)) {
				cookieMacKey = new SecretKeySpec(randomBytes(), "MAC");
				lastGenerationDate = System.currentTimeMillis();
			}
			return cookieMacKey;
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
	 * @return the cookie generated from the client's parameters
	 * @throws GeneralSecurityException if the cookie cannot be computed
	 */
	public byte[] generateCookie(ClientHello clientHello) throws GeneralSecurityException {
		// Cookie = HMAC(Secret, Client-IP, Client-Parameters)
		Mac hmac = Mac.getInstance("HmacSHA256");
		hmac.init(getMacKeyForCookies());
		// Client-IP
		hmac.update(clientHello.getPeer().toString().getBytes());

		// Client-Parameters
		hmac.update((byte) clientHello.getClientVersion().getMajor());
		hmac.update((byte) clientHello.getClientVersion().getMinor());
		hmac.update(clientHello.getRandom().getRandomBytes());
		hmac.update(clientHello.getSessionId().getId());
		hmac.update(CipherSuite.listToByteArray(clientHello.getCipherSuites()));
		hmac.update(CompressionMethod.listToByteArray(clientHello.getCompressionMethods()));
		return hmac.doFinal();
	}
}
