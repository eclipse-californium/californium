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
 *     Achim Kraus (Bosch Software Innovations GmbH) - initial API and implementation
 *                                                     derived from former 
 *                                                     InMemoryRandomTokenProvider
 *******************************************************************************/
package org.eclipse.californium.core.network;

import java.security.SecureRandom;

import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.elements.EndpointContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link TokenGenerator} that uses random tokens and set bit 0 of byte
 * according the required scope of the provided request.
 *
 * This implementation is thread-safe.
 */
public class RandomTokenGenerator implements TokenGenerator {

	private static final Logger LOGGER = LoggerFactory.getLogger(RandomTokenGenerator.class.getName());
	private static final int DEFAULT_TOKEN_LENGTH = 8; // bytes

	private final int tokenSize;
	private final SecureRandom rng;

	/**
	 * Creates a new {@link RandomTokenGenerator}.
	 * 
	 * @param networkConfig used to obtain the configured token size
	 */
	public RandomTokenGenerator(final NetworkConfig networkConfig) {

		if (networkConfig == null) {
			throw new NullPointerException("NetworkConfig must not be null");
		}
		this.rng = new SecureRandom();
		// trigger self-seeding of the PRNG, may "take a while"
		this.rng.nextInt(10);
		this.tokenSize = networkConfig.getInt(Keys.TOKEN_SIZE_LIMIT, DEFAULT_TOKEN_LENGTH);
		LOGGER.info("using tokens of {} bytes in length", this.tokenSize);
	}

	@Override
	public Token createToken(Scope scope) {
		byte[] token = new byte[tokenSize];
		rng.nextBytes(token);
		switch (scope) {
		case LONG_TERM:
			// set bit 0 to 1
			token[0] |= 0b1;
			break;
		case SHORT_TERM:
			// set bit 1-0 to 0b10
			token[0] &= 0b11111100;
			token[0] |= 0b10;
			break;
		case SHORT_TERM_CLIENT_LOCAL:
			// set bit 1-0 to 0b00
			token[0] &= 0b11111100;
			break;
		}
		return Token.fromProvider(token);
	}

	@Override
	public Scope getScope(Token token) {
		if (token.length() != tokenSize) {
			return Scope.SHORT_TERM_CLIENT_LOCAL;
		}
		int scope = token.getBytes()[0] & 0b11;
		switch (scope) {
		case 0b00:
			return Scope.SHORT_TERM_CLIENT_LOCAL;
		case 0b10:
			return Scope.SHORT_TERM;
		}
		return Scope.LONG_TERM;
	}

	@Override
	public KeyToken getKeyToken(Token token, EndpointContext peer) {
		if (getScope(token) == Scope.SHORT_TERM_CLIENT_LOCAL) {
			if (peer == null) {
				throw new IllegalArgumentException("client-local token requires not null peer context!");
			}
			return new KeyToken(peer.getPeerAddress(), token);
		} else {
			return new KeyToken(null, token);
		}
	}

}
