/*******************************************************************************
 * Copyright (c) 2017, 2018 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation.
 ******************************************************************************/

package org.eclipse.californium.integration.test;

import java.net.InetSocketAddress;

import javax.crypto.SecretKey;

import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.dtls.pskstore.StringPskStore;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * Simple {@link PskStore} implementation with exchangeable credentials.
 */
public class TestUtilPskStore extends StringPskStore {

	private final long delay;
	/**
	 * PSK identity.
	 */
	private String identity;
	/**
	 * PSK secret key.
	 */
	private SecretKey key;

	/**
	 * Create simple store with initial credentials.
	 * 
	 * @param identity PSK identity
	 * @param key PSK secret key
	 */
	public TestUtilPskStore(String identity, byte[] key) {
		this(identity, key, 0);
	}

	/**
	 * Create simple store with initial credentials and delay.
	 * 
	 * @param identity PSK identity
	 * @param key PSK secret key
	 * @param delay delay for {@link #getKey(String)} in milliseconds
	 */
	public TestUtilPskStore(String identity, byte[] key, int delay) {
		set(identity, key);
		this.delay = delay;
	}

	/**
	 * Exchange credentials.
	 * 
	 * @param identity PSK identity
	 * @param key PSK secret key
	 */
	public synchronized void set(String identity, byte[] key) {
		this.identity = identity;
		this.key = SecretUtil.create(key, "PSK");
	}

	@Override
	public SecretKey getKey(String identity) {
		if (0 < delay) {
			try {
				Thread.sleep(delay);
			} catch (InterruptedException e) {
			}
		}
		synchronized (this) {
			return SecretUtil.create(key);
		}
	}

	@Override
	public SecretKey getKey(ServerNames serverNames, String identity) {
		return getKey(identity);
	}

	@Override
	public synchronized String getIdentityAsString(InetSocketAddress inetAddress) {
		return identity;
	}

	@Override
	public String getIdentityAsString(InetSocketAddress peerAddress, ServerNames virtualHost) {
		return getIdentityAsString(peerAddress);
	}
}
