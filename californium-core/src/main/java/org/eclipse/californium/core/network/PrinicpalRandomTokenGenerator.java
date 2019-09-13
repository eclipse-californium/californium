/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *******************************************************************************/
package org.eclipse.californium.core.network;

import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.EndpointContext;

/**
 * {@link TokenGenerator} that uses random tokens and set bit 0 of byte
 * according the required scope of the provided request.
 *
 * This implementation is thread-safe.
 */
public class PrinicpalRandomTokenGenerator extends RandomTokenGenerator {

	/**
	 * Creates a new {@link PrinicpalRandomTokenGenerator}.
	 * 
	 * @param networkConfig used to obtain the configured token size
	 */
	public PrinicpalRandomTokenGenerator(final NetworkConfig networkConfig) {
		super(networkConfig);
	}

	@Override
	public KeyToken getKeyToken(Token token, EndpointContext peer) {
		if (getScope(token) == Scope.SHORT_TERM_CLIENT_LOCAL) {
			if (peer == null) {
				throw new IllegalArgumentException("client-local token requires not null peer context!");
			}
			return new KeyToken(peer.getPeerIdentity(), token);
		} else {
			return new KeyToken(null, token);
		}
	}

}
