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
package org.eclipse.californium.scandium.dtls.x509;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.scandium.dtls.CertificateIdentityResult;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.CertificateKeyAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.util.ServerNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Asynchronous test implementation based on {@link SingleCertificateProvider}.
 * 
 * Use {@code 0} or negative delays for test with synchronous blocking behavior.
 * And positive delays for test with asynchronous none-blocking behavior.
 * 
 * @since 3.0
 */
public class AsyncCertificateProvider extends SingleCertificateProvider {

	private static final Logger LOGGER = LoggerFactory.getLogger(AsyncCertificateProvider.class);

	/**
	 * Thread factory.
	 */
	private static final NamedThreadFactory THREAD_FACTORY = new DaemonThreadFactory("AsyncCertProvider#", NamedThreadFactory.SCANDIUM_THREAD_GROUP);
	/**
	 * Executor for asynchronous behaviour.
	 */
	private final ScheduledExecutorService executorService;
	/**
	 * Delay for certificate identity result. {@code 0} or negative delays for
	 * test with synchronous blocking behaviour. Positive delays for test with
	 * asynchronous none-blocking behaviour.
	 */
	private volatile int delayMillis = 1;
	/**
	 * Result handler set during initialization.
	 * 
	 * @see #setResultHandler(HandshakeResultHandler)
	 */
	private volatile HandshakeResultHandler resultHandler;

	public AsyncCertificateProvider(PrivateKey privateKey, Certificate[] chain,
			CertificateType... supportedCertificateTypes) {
		super(privateKey, chain, supportedCertificateTypes);
		this.executorService = ExecutorsUtil.newSingleThreadScheduledExecutor(THREAD_FACTORY); // $NON-NLS-1$
	}

	public AsyncCertificateProvider(PrivateKey privateKey, Certificate[] chain,
			List<CertificateType> supportedCertificateTypes) {
		super(privateKey, chain, supportedCertificateTypes);
		this.executorService = ExecutorsUtil.newSingleThreadScheduledExecutor(THREAD_FACTORY); // $NON-NLS-1$
	}

	public AsyncCertificateProvider(PrivateKey privateKey, PublicKey publicKey) {
		super(privateKey, publicKey);
		this.executorService = ExecutorsUtil.newSingleThreadScheduledExecutor(THREAD_FACTORY); // $NON-NLS-1$
	}

	/**
	 * Set delay milliseconds.
	 * 
	 * @param delayMillis delay in milliseconds to report result. {@code 0} or
	 *            negative delays using synchronous blocking behaviour. Positive
	 *            delays using asynchronous none-blocking behaviour.
	 * @return this certificate provider for command chaining
	 */
	public AsyncCertificateProvider setDelay(int delayMillis) {
		this.delayMillis = delayMillis;
		if (delayMillis > 0) {
			LOGGER.info("Asynchronous delayed certificate provider {}ms.", delayMillis);
		} else if (delayMillis < 0) {
			LOGGER.info("Synchronous delayed certificate provider {}ms.", -delayMillis);
		} else {
			LOGGER.info("Synchronous certificate provider.");
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
	public CertificateIdentityResult requestCertificateIdentity(final ConnectionId cid, final boolean client,
			final List<X500Principal> issuers, final ServerNames serverNames, final List<CertificateKeyAlgorithm> certificateKeyAlgorithms,
			final List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms, final List<SupportedGroup> curves) {

		if (delayMillis <= 0) {
			if (delayMillis < 0) {
				try {
					Thread.sleep(-delayMillis);
				} catch (InterruptedException e) {
				}
			}
			return super.requestCertificateIdentity(cid, client, issuers, serverNames, certificateKeyAlgorithms, signatureAndHashAlgorithms,
					curves);
		} else {
			executorService.schedule(new Runnable() {

				@Override
				public void run() {
					CertificateIdentityResult result = AsyncCertificateProvider.super.requestCertificateIdentity(cid,
							client, issuers, serverNames, certificateKeyAlgorithms, signatureAndHashAlgorithms, curves);
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
