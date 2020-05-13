package org.eclipse.californium.scandium.dtls.pskstore;

import java.net.InetSocketAddress;

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

public abstract class AbstractSyncPskStore implements AdvancedPskStore {

	protected static final ThreadLocalCryptoMap<ThreadLocalMac> MAC = new ThreadLocalCryptoMap<>(
			new Factory<ThreadLocalMac>() {

				@Override
				public ThreadLocalMac getInstance(String algorithm) {
					return new ThreadLocalMac(algorithm);
				}
			});

	@Override
	public PskSecretResult requestMasterSecret(ConnectionId cid, ServerNames serverNames, PskPublicInformation identity,
			String hmacAlgorithm, SecretKey otherSecret, byte[] seed, PskSecretResultHandler callback) {
		SecretKey masterSecret = getMasterSecret(cid, serverNames, identity, hmacAlgorithm, otherSecret, seed);
		if (masterSecret == null)
			return null;

		return new PskSecretResult(cid, identity, masterSecret);
	}

	public SecretKey getMasterSecret(ConnectionId cid, ServerNames serverNames, PskPublicInformation identity,
			String hmacAlgorithm, SecretKey otherSecret, byte[] seed) {
		SecretKey pskSecret = getPSKSecret(serverNames, identity);
		if (pskSecret == null)
			return null;

		SecretKey generateMasterSecret = generateMasterSecret(hmacAlgorithm, pskSecret, otherSecret, seed);
		SecretUtil.destroy(pskSecret);

		return generateMasterSecret;
	}

	protected abstract SecretKey getPSKSecret(ServerNames serverNames, PskPublicInformation identity);

	protected SecretKey generateMasterSecret(String hmacAlgorithm, SecretKey pskSecret, SecretKey otherSecret,
			byte[] seed) {
		ThreadLocalMac hmac = MAC.get(hmacAlgorithm);
		SecretKey premasterSecret = PseudoRandomFunction.generatePremasterSecretFromPSK(otherSecret, pskSecret);
		SecretKey masterSecret = PseudoRandomFunction.generateMasterSecret(hmac.current(), premasterSecret, seed);
		SecretUtil.destroy(premasterSecret);
		return masterSecret;
	}
}
