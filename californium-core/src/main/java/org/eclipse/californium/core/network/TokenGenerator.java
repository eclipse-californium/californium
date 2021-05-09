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
 *                                                     derived from former TokenProvider
 *******************************************************************************/
package org.eclipse.californium.core.network;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Token;

/**
 * Token generator.
 *
 * Implementations of {@link TokenGenerator} MUST be thread-safe.
 */
public interface TokenGenerator {

	/**
	 * Scope of token.
	 */
	public enum Scope {
		LONG_TERM, SHORT_TERM, SHORT_TERM_CLIENT_LOCAL
	}

	/**
	 * Creates a token for the provided request.
	 * 
	 * Intended to generate tokens with separate scopes for standard-,
	 * multicast- and observe requests. Due to the nature of multicast tokens,
	 * these tokens must be unique not only per remote peer. And due to the
	 * potential long term nature of observe tokens, these tokens are required
	 * to be maintained separated. Therefore the tokens must be generated in
	 * way, which ensures, that they have different values as the other tokens
	 * for standard-requests.
	 * 
	 * One idea of implementation would therefore be to set the token length
	 * different or to set bit 0 of byte 0 fix to 0 for standard and 1 for
	 * observe requests.
	 * 
	 * The caller must take care to use only unique tokens within the provided
	 * scope. In cases where the generated token is already in use, it's
	 * intended to create a next token calling this method again.
	 * 
	 * Note: the application may provide own tokens by calling
	 * {@link Request#setToken(Token)}. Such tokens must also obey the scope
	 * rules of this generator. And it must be ensured, that these tokens are
	 * also unique according their scope.
	 * 
	 * @param scope {@code LONG_TERM} for observe request within the long-term
	 *            scope, {@code SHORT_TERM} for multicast request with
	 *            short-term scope, and {@code SHORT_TERM_CLIENT_LOCAL} for
	 *            normal requests.
	 * @return the generated token
	 */
	Token createToken(Scope scope);

	/**
	 * Get scope of token.
	 * 
	 * @param token token to determine the scope of
	 * @return scope of the provided token
	 */
	Scope getScope(Token token);

	/**
	 * Create a key token.
	 * 
	 * @param token the message token
	 * @param peer peer identity. May be {@code null},
	 *            if the token has a none client-local scope
	 * @return key token
	 * @throws IllegalArgumentException if the token has a client-local scope
	 *             and no peer is provided.
	 */
	KeyToken getKeyToken(Token token, Object peer);
}
