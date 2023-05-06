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

import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.X509KeyManager;
import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.scandium.config.DtlsConfig;
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
 * Asynchronous test implementation based on
 * {@link KeyManagerCertificateProvider}.
 * 
 * Use {@code 0} or negative delays for test with synchronous blocking behavior.
 * And positive delays for test with asynchronous none-blocking behavior.
 * 
 * @since 3.0
 */
public class AsyncKeyManagerCertificateProvider extends KeyManagerCertificateProvider {

	private static final Logger LOGGER = LoggerFactory.getLogger(AsyncKeyManagerCertificateProvider.class);

	/**
	 * Thread factory.
	 */
	private static final NamedThreadFactory THREAD_FACTORY = new DaemonThreadFactory("AsyncKeyManagerCertProvider#",
			NamedThreadFactory.SCANDIUM_THREAD_GROUP);
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

	/**
	 * Create certificate provider based on key manager.
	 * 
	 * @param keyManager key manager with certificates and private keys
	 * @param supportedCertificateTypes array of supported certificate types
	 *            ordered by preference.
	 * @throws NullPointerException if the key manager is {@code null}
	 * @throws IllegalArgumentException if list of certificate types is empty or
	 *             contains unsupported types.
	 */
	public AsyncKeyManagerCertificateProvider(X509KeyManager keyManager, CertificateType... supportedCertificateTypes) {
		super(keyManager, supportedCertificateTypes);
		this.executorService = ExecutorsUtil.newSingleThreadScheduledExecutor(THREAD_FACTORY); // $NON-NLS-1$
	}

	/**
	 * Create certificate provider based on key manager.
	 * 
	 * @param keyManager key manager with certificates and private keys
	 * @param supportedCertificateTypes list of supported certificate types
	 *            ordered by preference. Intended to use
	 *            {@link DtlsConfig#DTLS_CERTIFICATE_TYPES} as input.
	 * @throws NullPointerException if the key manager is {@code null}
	 * @throws IllegalArgumentException if list of certificate types is empty or
	 *             contains unsupported types.
	 */
	public AsyncKeyManagerCertificateProvider(X509KeyManager keyManager,
			List<CertificateType> supportedCertificateTypes) {
		super(keyManager, supportedCertificateTypes);
		this.executorService = ExecutorsUtil.newSingleThreadScheduledExecutor(THREAD_FACTORY); // $NON-NLS-1$
	}

	/**
	 * Create certificate provider based on key manager with default alias.
	 * 
	 * @param defaultAlias default alias. May be {@code null}.
	 * @param keyManager key manager with certificates and private keys
	 * @param supportedCertificateTypes array of supported certificate types
	 *            ordered by preference
	 * @throws NullPointerException if the key manager is {@code null}
	 * @throws IllegalArgumentException if list of certificate types is empty or
	 *             contains unsupported types.
	 */
	public AsyncKeyManagerCertificateProvider(String defaultAlias, X509KeyManager keyManager,
			CertificateType... supportedCertificateTypes) {
		super(defaultAlias, keyManager, supportedCertificateTypes);
		this.executorService = ExecutorsUtil.newSingleThreadScheduledExecutor(THREAD_FACTORY); // $NON-NLS-1$
	}

	/**
	 * Create certificate provider based on key manager with default alias.
	 * 
	 * @param defaultAlias default alias. May be {@code null}.
	 * @param keyManager key manager with certificates and private keys
	 * @param supportedCertificateTypes list of supported certificate types
	 *            ordered by preference. Intended to use
	 *            {@link DtlsConfig#DTLS_CERTIFICATE_TYPES} as input.
	 * @throws NullPointerException if the key manager is {@code null}
	 * @throws IllegalArgumentException if list of certificate types is empty or
	 *             contains unsupported types.
	 */
	public AsyncKeyManagerCertificateProvider(String defaultAlias, X509KeyManager keyManager,
			List<CertificateType> supportedCertificateTypes) {
		super(defaultAlias, keyManager, supportedCertificateTypes);
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
	public AsyncKeyManagerCertificateProvider setDelay(int delayMillis) {
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
			final List<X500Principal> issuers, final ServerNames serverNames,
			final List<CertificateKeyAlgorithm> certificateKeyAlgorithms,
			final List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms, final List<SupportedGroup> curves) {

		if (delayMillis <= 0) {
			if (delayMillis < 0) {
				try {
					Thread.sleep(-delayMillis);
				} catch (InterruptedException e) {
				}
			}
			return super.requestCertificateIdentity(cid, client, issuers, serverNames, certificateKeyAlgorithms,
					signatureAndHashAlgorithms, curves);
		} else {
			executorService.schedule(new Runnable() {

				@Override
				public void run() {
					CertificateIdentityResult result = AsyncKeyManagerCertificateProvider.super.requestCertificateIdentity(
							cid, client, issuers, serverNames, certificateKeyAlgorithms, signatureAndHashAlgorithms,
							curves);
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
