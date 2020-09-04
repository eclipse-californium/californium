/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.pskstore;

import java.util.Arrays;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.dtls.PskSecretResultHandler;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simple asynchronous test implementation of {@link AdvancedPskStore}.
 * 
 * Use {@code 0} or negative delays for test with synchronous blocking
 * behaviour. And positive delays for test with asynchronous none-blocking
 * behaviour.
 * 
 * @since 2.3
 */
public class AsyncInMemoryPskStore extends AdvancedInMemoryPskStore {

	private static final Logger LOGGER = LoggerFactory.getLogger(AsyncInMemoryPskStore.class);

	/**
	 * Thread factory.
	 */
	private static final NamedThreadFactory THREAD_FACTORY = new DaemonThreadFactory("AsyncPskStoreTimer#");
	/**
	 * Delay for psk result. {@code 0} or negative delays for test with
	 * synchronous blocking behaviour. Positive delays for test with
	 * asynchronous none-blocking behaviour.
	 */
	private volatile int delayMillis = 1;
	/**
	 * {@code true} to return generated master secret, {@code false} for PSK
	 * secret key.
	 */
	private volatile boolean generateMasterSecret;
	/**
	 * Executor for asynchronous behaviour.
	 */
	private final ScheduledExecutorService executorService;
	/**
	 * Result handler set during initialization.
	 * 
	 * @see #setResultHandler(PskSecretResultHandler)
	 */
	private PskSecretResultHandler resultHandler;

	/**
	 * Create an advanced pskstore from {@link PskStore}.
	 * 
	 * A call to {@link #shutdown()} is required to cleanup the used resources
	 * (executor).
	 * 
	 * @param pskStore psk store
	 * @throws NullPointerException if store is {@code null}
	 */
	public AsyncInMemoryPskStore(PskStore pskStore) {
		super(pskStore);
		executorService = ExecutorsUtil.newSingleThreadScheduledExecutor(THREAD_FACTORY); // $NON-NLS-1$
	}

	/**
	 * Set secret mode.
	 * 
	 * @param enableGenerateMasterSecret {@code true} to return generated master
	 *            secret, {@code false} for PSK secret key.
	 * @return this psk store for command chaining
	 */
	public AsyncInMemoryPskStore setSecretMode(boolean enableGenerateMasterSecret) {
		this.generateMasterSecret = generateMasterSecret;
		return this;
	}

	/**
	 * Set delay.
	 * 
	 * @param delayMillis delay in milliseconds to report result. {@code 0} or
	 *            negative delays using synchronous blocking behaviour. Positive
	 *            delays using asynchronous none-blocking behaviour.
	 * @return this psk store for command chaining
	 */
	public AsyncInMemoryPskStore setDelay(int delayMillis) {
		this.delayMillis = delayMillis;
		if (delayMillis > 0) {
			LOGGER.info("Asynchronous delayed PSK store {}ms.", delayMillis);
		} else if (delayMillis < 0) {
			LOGGER.info("Synchronous delayed PSK store {}ms.", -delayMillis);
		} else {
			LOGGER.info("Synchronous PSK store.");
		}
		return this;
	}

	/**
	 * Shutdown. Cleanup resources.
	 */
	public void shutdown() {
		executorService.shutdown();
	}

	@Override
	public PskSecretResult requestPskSecretResult(final ConnectionId cid, final ServerNames serverNames,
			final PskPublicInformation identity, final String hmacAlgorithm, SecretKey otherSecret, byte[] seed) {
		if (delayMillis <= 0) {
			if (delayMillis < 0) {
				try {
					Thread.sleep(-delayMillis);
				} catch (InterruptedException e) {
				}
			}
			return getPskSecretResult(cid, serverNames, identity, hmacAlgorithm, otherSecret, seed);
		} else {
			final byte[] randomSeed = Arrays.copyOf(seed, seed.length);
			final SecretKey other = SecretUtil.create(otherSecret);
			executorService.schedule(new Runnable() {

				@Override
				public void run() {
					getSecretAsynchronous(cid, serverNames, identity, hmacAlgorithm, other, randomSeed);
				}
			}, delayMillis, TimeUnit.MILLISECONDS);
			return null;
		}
	}

	/**
	 * Get secret asynchronous and forward it to the {@link #resultHandler}.
	 * 
	 * @param cid connection id for stateless asynchronous implementations.
	 * @param serverName server names. Maybe {@code null}, if SNI is not enabled
	 *            or not used by the client.
	 * @param identity psk identity. Maybe normalized
	 * @param hmacAlgorithm HMAC algorithm name for PRF.
	 * @param otherSecret other secret from ECDHE, or {@code null}. Must be
	 *            cloned for asynchronous use.
	 * @param seed seed for PRF.
	 */
	private void getSecretAsynchronous(ConnectionId cid, ServerNames serverNames, PskPublicInformation identity,
			String hmacAlgorithm, SecretKey otherSecret, byte[] seed) {
		PskSecretResult result = getPskSecretResult(cid, serverNames, identity, hmacAlgorithm, otherSecret, seed);
		resultHandler.apply(result);
	}

	/**
	 * Get psk secret result.
	 * 
	 * Depending on {@link #generateMasterSecret}, either the generated master
	 * secret (algorithm "MAC"), or a PSK secret key (algorithm "PSK") is
	 * included in the result.
	 * 
	 * @param cid connection id for stateless asynchronous implementations.
	 * @param serverName server names. Maybe {@code null}, if SNI is not enabled
	 *            or not used by the client.
	 * @param identity psk identity. Maybe normalized
	 * @param hmacAlgorithm HMAC algorithm name for PRF.
	 * @param otherSecret other secret from ECDHE, or {@code null}.
	 * @param seed seed for PRF.
	 * @return psk secret result
	 */
	private PskSecretResult getPskSecretResult(ConnectionId cid, ServerNames serverNames, PskPublicInformation identity,
			String hmacAlgorithm, SecretKey otherSecret, byte[] seed) {
		SecretKey secret = serverNames != null ? pskStore.getKey(serverNames, identity) : pskStore.getKey(identity);
		if (generateMasterSecret && secret != null) {
			SecretKey masterSecret = generateMasterSecret(hmacAlgorithm, secret, otherSecret, seed);
			SecretUtil.destroy(secret);
			secret = masterSecret;
		}
		return new PskSecretResult(cid, identity, secret);
	}

	@Override
	public void setResultHandler(PskSecretResultHandler resultHandler) {
		this.resultHandler = resultHandler;
	}
}
