/*******************************************************************************
 * Copyright (c) 2017, 2018 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation.
 ******************************************************************************/

package org.eclipse.californium.integration.test;

import java.net.InetSocketAddress;
import java.util.Arrays;

import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * Simple {@link PskStore} implementation with exchangeable credentials.
 */
public class TestUtilPskStore implements PskStore {

	/**
	 * PSK identity.
	 */
	private String identity;
	/**
	 * PSK secret key.
	 */
	private byte[] key;

	/**
	 * Create simple store with initial credentials.
	 * 
	 * @param identity PSK identity
	 * @param key PSK secret key
	 */
	public TestUtilPskStore(String identity, byte[] key) {
		set(identity, key);
	}

	/**
	 * Exchange credentials.
	 * 
	 * @param identity PSK identity
	 * @param key PSK secret key
	 */
	public synchronized void set(String identity, byte[] key) {
		this.identity = identity;
		this.key = Arrays.copyOf(key, key.length);
	}

	@Override
	public synchronized byte[] getKey(String identity) {
		return key;
	}

	@Override
	public synchronized byte[] getKey(ServerNames serverNames, String identity) {
		return getKey(identity);
	}

	@Override
	public synchronized String getIdentity(InetSocketAddress inetAddress) {
		return identity;
	}

	@Override
	public synchronized String getIdentity(InetSocketAddress peerAddress, ServerNames virtualHost) {
		return getIdentity(peerAddress);
	}
}
