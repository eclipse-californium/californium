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
 * Simple asynchrounos test implementation of {@link AdvancedPskStore}.
 * 
 * Use {@code 0} or negative delays for test with synchronous blocking
 * behaviour. And positive delays for test with asynchronous none-blocking
 * behaviour.
 */
public class AsyncInMemoryPskStore extends SyncAdvancedPskStore {

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
		this.delayMillis = delayMillis;
		executorService = ExecutorsUtil.newSingleThreadScheduledExecutor(THREAD_FACTORY); // $NON-NLS-1$
		if (delayMillis > 0) {
			LOGGER.warn("Asynchronous delayed PSK store {}ms.", delayMillis);
		} else if (delayMillis < 0) {
			LOGGER.warn("Synchronous delayed PSK store {}ms.", -delayMillis);
		} else {
			LOGGER.warn("Synchronous PSK store.");
		}
	}

	/**
	 * Set secret mode.
	 * 
	 * @param enableGenerateMasterSecret {@code true} to return generated master
	 *            secret, {@code false} for PSK secret key.
	 * @return this psk store for command chaining
	 */
	// TODO to remove
	public AsyncInMemoryPskStore setSecretMode(boolean enableGenerateMasterSecret) {
		this.generateMasterSecret = true;
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
		return this;
	}

	/**
	 * Shutdown. Cleanup resouces.
	 */
	public void shutdown() {
		executorService.shutdown();
	}

	@Override
	public PskSecretResult requestMasterSecret(final ConnectionId cid, final ServerNames serverNames,
			final PskPublicInformation identity, final String hmacAlgorithm, SecretKey otherSecret, byte[] seed,
			final PskSecretResultHandler callback) {
		if (delayMillis <= 0) {
			if (delayMillis < 0) {
				try {
					Thread.sleep(-delayMillis);
				} catch (InterruptedException e) {
				}
			}
			return super.requestMasterSecret(cid, serverNames, identity, hmacAlgorithm, otherSecret, seed, callback);
		} else {
			final byte[] localSeed = Arrays.copyOf(seed, seed.length);
			final SecretKey localOtherSecret = SecretUtil.create(otherSecret);
			executorService.schedule(new Runnable() {

				@Override
				public void run() {
					callback.apply(AsyncInMemoryPskStore.super.requestMasterSecret(cid, serverNames, identity,
							hmacAlgorithm, localOtherSecret, localSeed, callback));
				}
			}, delayMillis, TimeUnit.MILLISECONDS);
			return null;
		}
	}
}
