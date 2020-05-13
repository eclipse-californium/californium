package org.eclipse.californium.scandium.dtls.pskstore;

import java.net.InetSocketAddress;
import java.util.Arrays;

import javax.crypto.SecretKey;

import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.dtls.PskSecretResultHandler;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalCryptoMap;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalMac;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalCryptoMap.Factory;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;

public abstract class AbstractAsyncPskStore implements AdvancedPskStore {

	protected static final ThreadLocalCryptoMap<ThreadLocalMac> MAC = new ThreadLocalCryptoMap<>(
			new Factory<ThreadLocalMac>() {
				@Override
				public ThreadLocalMac getInstance(String algorithm) {
					return new ThreadLocalMac(algorithm);
				}
			});

	@Override
	public PskSecretResult requestMasterSecret(ConnectionId cid, ServerNames serverName, PskPublicInformation identity,
			final String hmacAlgorithm, SecretKey otherSecret,  byte[] seed, final PskSecretResultHandler callback) {
		
		final byte[] localSeed = Arrays.copyOf(seed, seed.length);
		final SecretKey localOtherSecret = SecretUtil.create(otherSecret);
		requestPSKSecret(serverName, identity, new PskSecretResultHandler() {
			@Override
			public void apply(PskSecretResult secretResult) {
				// no psk for this identity.
				if (secretResult == null || secretResult.getSecret() == null) {
					callback.apply(null);
					return;
				}
				
				// psk is found generate master secret
				SecretKey masterSecret = generateMasterSecret(hmacAlgorithm, secretResult.getSecret(), localOtherSecret, localSeed);
				SecretUtil.destroy(secretResult.getSecret());
				callback.apply(new PskSecretResult(secretResult.getConnectionId(), secretResult.getPskPublicInformation(), masterSecret));
			}
		});
		return null;
	}

	protected abstract void requestPSKSecret(ServerNames serverName, PskPublicInformation identity,
			PskSecretResultHandler callback);

	protected SecretKey generateMasterSecret(String hmacAlgorithm, SecretKey pskSecret, SecretKey otherSecret,
			byte[] seed) {
		ThreadLocalMac hmac = MAC.get(hmacAlgorithm);
		SecretKey premasterSecret = PseudoRandomFunction.generatePremasterSecretFromPSK(otherSecret, pskSecret);
		SecretKey masterSecret = PseudoRandomFunction.generateMasterSecret(hmac.current(), premasterSecret, seed);
		SecretUtil.destroy(premasterSecret);
		return masterSecret;
	}
}
