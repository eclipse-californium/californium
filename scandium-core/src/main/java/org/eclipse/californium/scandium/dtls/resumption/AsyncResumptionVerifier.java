/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
package org.eclipse.californium.scandium.dtls.resumption;

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.ResumptionVerificationResult;
import org.eclipse.californium.scandium.dtls.ResumptionSupportingConnectionStore;
import org.eclipse.californium.scandium.dtls.SessionId;
import org.eclipse.californium.scandium.util.ServerNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Asynchronous test implementation using the provided
 * {@link ResumptionSupportingConnectionStore}.
 * 
 * Use {@code 0} or negative delays for test with synchronous blocking behavior.
 * And positive delays for test with asynchronous none-blocking behavior.
 * 
 * @since 3.0
 */
public class AsyncResumptionVerifier extends ConnectionStoreResumptionVerifier {

	private static final Logger LOGGER = LoggerFactory.getLogger(AsyncResumptionVerifier.class);

	/**
	 * Thread factory.
	 */
	private static final NamedThreadFactory THREAD_FACTORY = new DaemonThreadFactory("AsyncResumptionTimer#");
	/**
	 * Executor for asynchronous behaviour.
	 */
	private final ScheduledExecutorService executorService;
	/**
	 * Delay for resumption result. {@code 0} or negative delays for test with
	 * synchronous blocking behaviour. Positive delays for test with
	 * asynchronous none-blocking behaviour.
	 */
	private volatile int delayMillis = 1;
	/**
	 * Result handler set during initialization.
	 * 
	 * @see #setResultHandler(HandshakeResultHandler)
	 */
	private volatile HandshakeResultHandler resultHandler;

	/**
	 * Create a resumption verifier based on the
	 * {@link ResumptionSupportingConnectionStore} of the {@link DTLSConnector}.
	 * 
	 * A call to {@link #shutdown()} is required to cleanup the used resources
	 * (executor).
	 */
	public AsyncResumptionVerifier() {
		super();
		this.executorService = ExecutorsUtil.newSingleThreadScheduledExecutor(THREAD_FACTORY); // $NON-NLS-1$
	}

	/**
	 * Create a resumption verifier based on the provided
	 * {@link ResumptionSupportingConnectionStore}.
	 * 
	 * A call to {@link #shutdown()} is required to cleanup the used resources
	 * (executor).
	 * 
	 * @param connectionStore connection store to lookup the dtls session.
	 */
	public AsyncResumptionVerifier(ResumptionSupportingConnectionStore connectionStore) {
		super(connectionStore);
		this.executorService = ExecutorsUtil.newSingleThreadScheduledExecutor(THREAD_FACTORY); // $NON-NLS-1$
	}

	/**
	 * Set delay milliseconds.
	 * 
	 * @param delayMillis delay in milliseconds to report result. {@code 0} or
	 *            negative delays using synchronous blocking behaviour. Positive
	 *            delays using asynchronous none-blocking behaviour.
	 * @return this resumption verifier for command chaining
	 */
	public AsyncResumptionVerifier setDelay(int delayMillis) {
		this.delayMillis = delayMillis;
		if (delayMillis > 0) {
			LOGGER.info("Asynchronous delayed resumption verifier {}ms.", delayMillis);
		} else if (delayMillis < 0) {
			LOGGER.info("Synchronous delayed resumption verifier {}ms.", -delayMillis);
		} else {
			LOGGER.info("Synchronous resumption verifier.");
		}
		return this;
	}

	/**
	 * Get delay milliseconds.
	 * 
	 * @return delay milliseconds. {@code 0} or negative delays using
	 *         synchronous blocking behaviour. Positive delays using
	 *         asynchronous none-blocking behaviour.
	 */
	public int getDelay() {
		return delayMillis;
	}

	/**
	 * Shutdown. Cleanup resources.
	 */
	public void shutdown() {
		executorService.shutdown();
	}

	@Override
	public ResumptionVerificationResult verifyResumptionRequest(final ConnectionId cid, final ServerNames serverName,
			final SessionId sessionId) {

		if (delayMillis <= 0) {
			if (delayMillis < 0) {
				try {
					Thread.sleep(-delayMillis);
				} catch (InterruptedException e) {
				}
			}
			return super.verifyResumptionRequest(cid, serverName, sessionId);
		} else {
			executorService.schedule(new Runnable() {

				@Override
				public void run() {
					ResumptionVerificationResult result = AsyncResumptionVerifier.super.verifyResumptionRequest(cid,
							serverName, sessionId);
					resultHandler.apply(result);
				}
			}, delayMillis, TimeUnit.MILLISECONDS);
			return null;
		}
	}

	@Override
	public void setResultHandler(HandshakeResultHandler resultHandler) {
		if (this.resultHandler != null && resultHandler != null && this.resultHandler != resultHandler) {
			throw new IllegalStateException("handshake result handler already set!");
		}
		this.resultHandler = resultHandler;
	}

}
