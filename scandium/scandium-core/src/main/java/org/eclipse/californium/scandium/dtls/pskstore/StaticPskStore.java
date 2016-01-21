package org.eclipse.californium.scandium.dtls.pskstore;

import java.net.InetSocketAddress;
import java.util.Arrays;

/**
 * A simple in-memory pre-shared-key store.
 * Used when we always use the same identity/Key for all peers
 * we will connect to. 
 * 
 * To be used only for testing and evaluation. 
 * You are supposed to store your key in a secure way: 
 * keeping them in-memory is not a good idea.
 */
public class StaticPskStore implements PskStore {

	private final byte[] key;
	private final String identity;

	public StaticPskStore(final String identity, final byte[] key) {
		this.identity = identity;
		this.key = Arrays.copyOf(key, key.length);
	}

	@Override
	public String getIdentity(InetSocketAddress inetAddress) {
		return identity;
	}

	@Override
	public byte[] getKey(String identity) {
		return key;
	}
}
