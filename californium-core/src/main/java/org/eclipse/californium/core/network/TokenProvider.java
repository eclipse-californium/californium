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
 *    Achim Kraus (Bosch Software Innovations GmbH) - adjust to use Token
 *******************************************************************************/
package org.eclipse.californium.core.network;

import org.eclipse.californium.core.coap.Token;

/**
 * A {@link TokenProvider} provides CoAP tokens that are guaranteed to be not in
 * use. To not run out of unused tokens, used tokens MUST be released with
 * {@link #releaseToken(Token)} after usage.
 *
 * Implementations of {@link TokenProvider} MUST be thread-safe.
 */
public interface TokenProvider {

	/**
	 * Returns a token that is not in use. After this token is not in use
	 * anymore it must be released with {@link #releaseToken(Token)}.
	 * 
	 * @return a token that is not in use
	 */
	Token getUnusedToken();

	/**
	 * Releases the given token to be used again.
	 * 
	 * @param token the token to be released
	 */
	void releaseToken(Token token);

	/**
	 * Indicates if the given token is in use, i.e. was returned by
	 * {@link #getUnusedToken()} but not yet released by
	 * {@link #releaseToken(Token)}.
	 * 
	 * @param token the token to be checked
	 * @return {@code true}, if the given token is still in use, {@code false}, otherwise
	 */
	boolean isTokenInUse(Token token);
}
