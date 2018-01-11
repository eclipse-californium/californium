package org.eclipse.californium.core.network;

import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.elements.EndpointContext;

/**
 * Key token factory using key tokens only based on {@link Token}.
 */
public class TokenOnlyKeyTokenFactory implements KeyTokenFactory {

	/**
	 * Create new instance. "Private", though the only {@link #INSTANCE} is
	 * intended.
	 */
	private TokenOnlyKeyTokenFactory() {

	}

	@Override
	public KeyToken create(final Token token, EndpointContext context) {
		if (token == null) {
			throw new NullPointerException("token must be provided!");
		}

		return new KeyToken() {

			@Override
			public int hashCode() {
				return token.hashCode();
			}

			@Override
			public boolean equals(Object obj) {
				if (this == obj)
					return true;
				if (obj == null)
					return false;
				if (getClass() != obj.getClass())
					return false;
				KeyToken other = (KeyToken) obj;
				return token.equals(other.getToken());
			}

			@Override
			public Token getToken() {
				return token;
			}
		};
	}

	/**
	 * Singleton of this key token factory.
	 */
	public static final KeyTokenFactory INSTANCE = new TokenOnlyKeyTokenFactory();
}
