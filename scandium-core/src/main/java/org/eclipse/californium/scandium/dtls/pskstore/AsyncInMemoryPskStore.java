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
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.dtls.PskSecretResultHandler;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * Simple asynchronous test implementation of {@link AdvancedPskStore}.
 */
public class AsyncInMemoryPskStore extends AdvancedInMemoryPskStore {

	private final int delayMillis;
	private final ScheduledExecutorService executorService;
	private PskSecretResultHandler resultHandler;

	/**
	 * Create an advanced pskstore from {@link PskStore}.
	 * 
	 * @param pskStore psk store
	 * @param delayMillis delay in milliseconds to report result
	 * @throws NullPointerException if store is {@code null}
	 */
	public AsyncInMemoryPskStore(PskStore pskStore, int delayMillis) {
		this(pskStore, true, delayMillis);
	}

	/**
	 * Create an advanced pskstore from {@link PskStore}.
	 * 
	 * @param pskStore psk store
	 * @param master {@code true}, return master secret, {@code false} PSK
	 *            secret key.
	 * @param delayMillis delay in milliseconds to report result
	 * @throws NullPointerException if store is {@code null}
	 */
	public AsyncInMemoryPskStore(PskStore pskStore, boolean master, int delayMillis) {
		super(pskStore, master);
		this.delayMillis = delayMillis;
		executorService = ExecutorsUtil.newSingleThreadScheduledExecutor(new DaemonThreadFactory("AsyncPskStoreTimer")); //$NON-NLS-1$
	}

	public void shutdown() {
		executorService.shutdown();
	}

	@Override
	public PskSecretResult requestPskSecretResult(final ConnectionId cid, final ServerNames serverNames,
			final PskPublicInformation identity, final String hmacAlgorithm, SecretKey otherSecret, byte[] seed) {
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

	/**
	 * Get secret asynchronous and forward it to the {@link #resultHandler}.
	 * 
	 * @param cid connection id for stateless asynchronous implementations.
	 * @param serverName server names. Maybe {@code null}, if SNI is not enabled
	 *            or not used by the client.
	 * @param identity psk identity. Maybe normalized
	 * @param hmacAlgorithm HMAC algorithm name for PRF.
	 * @param otherSecret other secert from ECDHE, or {@code null}.
	 * @param seed seed for PRF.
	 */
	private void getSecretAsynchronous(ConnectionId cid, ServerNames serverNames, PskPublicInformation identity,
			String hmacAlgorithm, SecretKey otherSecret, byte[] seed) {
		PskSecretResult result = super.requestPskSecretResult(cid, serverNames, identity, hmacAlgorithm, otherSecret,
				seed);
		SecretUtil.destroy(otherSecret);
		resultHandler.apply(result);
	}

	@Override
	public void setResultHandler(PskSecretResultHandler resultHandler) {
		this.resultHandler = resultHandler;
	}
}
