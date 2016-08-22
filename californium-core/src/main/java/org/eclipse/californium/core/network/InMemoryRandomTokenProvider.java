/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *     Daniel Maier (Bosch Software Innovations GmbH)
 *                                - initial API and implementation
 *******************************************************************************/
package org.eclipse.californium.core.network;

import java.util.Collections;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;

import org.eclipse.californium.core.network.Exchange.KeyToken;
import org.eclipse.californium.core.network.config.NetworkConfig;

/**
 * {@link TokenProvider} that uses random tokens and stores them in memory. 
 * 
 * Note: This {@link TokenProvider} is not sufficient if persistence is in use.
 *
 * This implementation is thread-safe.
 */
public class InMemoryRandomTokenProvider implements TokenProvider {

	private final Set<KeyToken> usedTokens = Collections.newSetFromMap(new ConcurrentHashMap<KeyToken, Boolean>());
	private final int tokenSizeLimit;

	/**
	 * Creates a new {@link InMemoryRandomTokenProvider}.
	 * 
	 * @param networkConfig used to obtain the configured token size
	 */
	public InMemoryRandomTokenProvider(NetworkConfig networkConfig) {
		this.tokenSizeLimit = networkConfig.getInt(NetworkConfig.Keys.TOKEN_SIZE_LIMIT);
	}

	@Override
	public byte[] getUnusedToken() {
		return createUnusedToken();
	}

	@Override
	public void releaseToken(byte[] token) {
		usedTokens.remove(new KeyToken(token));
	}

	@Override
	public boolean isTokenInUse(byte[] token) {
		return usedTokens.contains(new KeyToken(token));
	}

	private byte[] createUnusedToken() {
		final Random random = ThreadLocalRandom.current();
		byte[] token;
		KeyToken result;
		// TODO what to do when there are no more unused tokens left?
		do {
			token = new byte[tokenSizeLimit];
			random.nextBytes(token);
			result = new KeyToken(token);
		} while (!usedTokens.add(result));
		return result.token;
	}
}
