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
 *    Bosch Software Innovations GmbH - initial API
 *******************************************************************************/
package org.eclipse.californium.core.network;

import java.security.Principal;

import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.KeyToken;
import org.eclipse.californium.core.network.KeyTokenFactory;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.UserInfo;

/**
 * Principal and token based key token factory.
 * 
 * Create key token based on {@link Principal} and {@link Token}.
 */
public class PrincipalKeyTokenFactory implements KeyTokenFactory {

	/**
	 * Create new instance. "Private", though the only {@link #INSTANCE} is
	 * intended.
	 */
	private PrincipalKeyTokenFactory() {

	}

	@Override
	public KeyToken create(final Token token, final EndpointContext context) {
		if (token == null) {
			throw new NullPointerException("token must not be null!");
		}
		if (context == null) {
			throw new NullPointerException("context must not be null!");
		}
		if (context.getPeerIdentity() == null) {
			throw new IllegalArgumentException("context must contain a valid pricipal!");
		}

		return new PrincipalKeyToken(token, context.getPeerIdentity());
	}

	/**
	 * Singleton of this key token factory.
	 */
	public static final KeyTokenFactory INSTANCE = new PrincipalKeyTokenFactory();

	/**
	 * KeyToken based on principal and token.
	 */
	public static class PrincipalKeyToken implements KeyToken {

		private final Token token;
		private final Principal principal;
		private final int hashCode;

		private PrincipalKeyToken(Token token, Principal principal) {
			final int prime = 31;
			this.token = token;
			this.principal = principal;
			this.hashCode = prime * token.hashCode() + principal.hashCode();
		}

		@Override
		public int hashCode() {
			return hashCode;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			PrincipalKeyToken other = (PrincipalKeyToken) obj;
			if (!token.equals(other.token))
				return false;
			if (principal.equals(other.principal))
				return true;

			if (principal instanceof UserInfo || other.principal instanceof UserInfo) {
				// if the UserInfo is provided in the URI, check only the names
				return principal.getName().equals(other.principal.getName());
			}

			return false;
		}

		@Override
		public Token getToken() {
			return token;
		}

	}
}
