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
 *     Achim Kraus (Bosch Software Innovations GmbH) - cleanup
 *******************************************************************************/
package org.eclipse.californium.core.network;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

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

	private static final Logger LOGGER = Logger.getLogger(InMemoryRandomTokenProvider.class.getName());
	private static final int MAX_TOKEN_LENGTH = 8; // bytes
	
	private final Set<KeyToken> usedTokens = Collections.newSetFromMap(new ConcurrentHashMap<KeyToken, Boolean>());
	private final int tokenSizeLimit;
	private final SecureRandom rng;

	/**
	 * Creates a new {@link InMemoryRandomTokenProvider}.
	 * 
	 * @param networkConfig used to obtain the configured token size
	 */
	public InMemoryRandomTokenProvider(final NetworkConfig networkConfig) {

		if (networkConfig == null) {
			throw new NullPointerException("NetworkConfig must not be null");
		}
		this.rng = new SecureRandom();
		this.rng.nextInt(10);  // trigger self-seeding of the PRNG, may "take a while"
		this.tokenSizeLimit = networkConfig.getInt(NetworkConfig.Keys.TOKEN_SIZE_LIMIT, MAX_TOKEN_LENGTH);
		LOGGER.log(Level.CONFIG, "using tokens of {0} bytes in length", this.tokenSizeLimit);
	}

	@Override
	public KeyToken getUnusedToken(final Message message) {
		return createUnusedToken(message);
	}

	@Override
	public void releaseToken(final KeyToken keyToken) {
		usedTokens.remove(keyToken);
	}

	@Override
	public boolean isTokenInUse(final KeyToken keyToken) {
		return usedTokens.contains(keyToken);
	}

	private KeyToken createUnusedToken(final Message message) {
		byte[] address = message.getDestination().getAddress();
		byte[] token = new byte[tokenSizeLimit];
		KeyToken result;
		// TODO what to do when there are no more unused tokens left?
		do {
			rng.nextBytes(token);
			result =  KeyToken.fromValues(token, address, message.getDestinationPort());
		} while (!usedTokens.add(result));
		return result;
	}
}
