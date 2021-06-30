/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *     Achim Kraus (Bosch Software Innovations GmbH) - initial API and implementation
 *                                                     derived from former 
 *                                                     InMemoryRandomTokenProvider
 *******************************************************************************/
package org.eclipse.californium.core.network;

import java.security.SecureRandom;

import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.elements.config.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TokenGenerator using random tokens and encodes the scope in the first two
 * bits of the first byte.
 * 
 * <pre>
 * 0b???????1 {@link Scope#LONG_TERM}, for observe tokens
 * 0b??????10 {@link Scope#SHORT_TERM}, for multicast tokens
 * 0b??????00 {@link Scope#SHORT_TERM_CLIENT_LOCAL}, for standard tokens
 * </pre>
 * 
 * All generated tokens will have the configured {@link CoapConfig#TOKEN_SIZE_LIMIT}.
 * tokens with different size will be treated as
 * {@link Scope#SHORT_TERM_CLIENT_LOCAL}.
 *
 * This implementation is thread-safe.
 */
public class RandomTokenGenerator implements TokenGenerator {

	private static final Logger LOGGER = LoggerFactory.getLogger(RandomTokenGenerator.class);

	private final int tokenSize;
	private final SecureRandom rng;

	/**
	 * Creates a new {@link RandomTokenGenerator}.
	 * 
	 * @param config used to obtain the configured token size
	 * @since 3.0 (changed parameter to Configuration)
	 */
	public RandomTokenGenerator(final Configuration config) {

		if (config == null) {
			throw new NullPointerException("NetworkConfig must not be null");
		}
		this.rng = new SecureRandom();
		// trigger self-seeding of the PRNG, may "take a while"
		this.rng.nextInt(10);
		this.tokenSize = config.get(CoapConfig.TOKEN_SIZE_LIMIT);
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

	/**
	 * {@inheritDoc}
	 * 
	 * This generator encodes the scope in the first two bits of the first byte.
	 * 
	 * <pre>
	 * 0b???????1 {@link Scope#LONG_TERM}, for observe tokens
	 * 0b??????10 {@link Scope#SHORT_TERM}, for multicast tokens
	 * 0b??????00 {@link Scope#SHORT_TERM_CLIENT_LOCAL}, for standard tokens
	 * </pre>
	 * 
	 * All generated tokens will have the configured
	 * {@link CoapConfig#TOKEN_SIZE_LIMIT}. Tokens with different size will be treated
	 * as {@link Scope#SHORT_TERM_CLIENT_LOCAL}.
	 * 
	 */
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
	public KeyToken getKeyToken(Token token, Object peer) {
		if (getScope(token) == Scope.SHORT_TERM_CLIENT_LOCAL) {
			if (peer == null) {
				throw new IllegalArgumentException("client-local token requires peer!");
			}
			return new KeyToken(token, peer);
		} else {
			return new KeyToken(token, null);
		}
	}

}
