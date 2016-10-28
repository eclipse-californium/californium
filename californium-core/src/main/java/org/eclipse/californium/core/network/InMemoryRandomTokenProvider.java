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

import org.eclipse.californium.core.coap.Message;
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
	private static final int MAX_TOKEN_LENGTH = 8; // bytes
	private final int tokenSizeLimit;

	/**
	 * Creates a new {@link InMemoryRandomTokenProvider}.
	 * 
	 * @param networkConfig used to obtain the configured token size
	 */
	public InMemoryRandomTokenProvider(NetworkConfig networkConfig) {
		this.tokenSizeLimit = networkConfig.getInt(NetworkConfig.Keys.TOKEN_SIZE_LIMIT, MAX_TOKEN_LENGTH);
	}

	@Override
	public KeyToken getUnusedToken(Message message) {
		return createUnusedToken(message);
	}

	@Override
	public void releaseToken(KeyToken keyToken) {
		usedTokens.remove(keyToken);
	}

	@Override
	public boolean isTokenInUse(KeyToken keyToken) {
		return usedTokens.contains(keyToken);
	}

	private KeyToken createUnusedToken(Message message) {
		final Random random = ThreadLocalRandom.current();
		byte[] token;
		KeyToken result;
		// TODO what to do when there are no more unused tokens left?
		do {
			token = new byte[tokenSizeLimit];
			random.nextBytes(token);
			result =  KeyToken.fromValues(token, message.getDestination().getAddress(), message.getDestinationPort());
		} while (!usedTokens.add(result));
		return result;
	}
}
