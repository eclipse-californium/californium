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
package org.eclipse.californium.scandium.dtls.x509;

import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.CertificateVerificationResult;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * Simple asynchronous test implementation of
 * {@link NewAdvancedCertificateVerifier}.
 * 
 * Use {@code 0} or negative delays for test with synchronous blocking
 * behaviour. And positive delays for test with asynchronous none-blocking
 * behaviour.
 * 
 * @since 2.5
 */
public class AsyncNewAdvancedCertificateVerifier extends StaticNewAdvancedCertificateVerifier {

	/**
	 * Thread factory.
	 */
	private static final NamedThreadFactory THREAD_FACTORY = new DaemonThreadFactory("AsyncTimer#");
	/**
	 * Executor for asynchronous behaviour.
	 */
	private final ScheduledExecutorService executorService;
	/**
	 * Delay for certificate result. {@code 0} or negative delays for test with
	 * synchronous blocking behaviour. Positive delays for test with
	 * asynchronous none-blocking behaviour.
	 */
	private volatile int delayMillis = 1;
	/**
	 * Result handler set during initialization.
	 * 
	 * @see #setResultHandler(HandshakeResultHandler)
	 */
	private HandshakeResultHandler resultHandler;

	public AsyncNewAdvancedCertificateVerifier(X509Certificate[] trustedCertificates,
			RawPublicKeyIdentity[] trustedRPKs, List<CertificateType> supportedCertificateTypes) {
		super(trustedCertificates, trustedRPKs, supportedCertificateTypes);
		executorService = ExecutorsUtil.newSingleThreadScheduledExecutor(THREAD_FACTORY); // $NON-NLS-1$
	}

	/**
	 * Set delay.
	 * 
	 * @param delayMillis delay in milliseconds to report result. {@code 0} or
	 *            negative delays using synchronous blocking behaviour. Positive
	 *            delays using asynchronous none-blocking behaviour.
	 * @return this psk store for command chaining
	 */
	public AsyncNewAdvancedCertificateVerifier setDelay(int delayMillis) {
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
	public CertificateVerificationResult verifyCertificate(final ConnectionId cid, final ServerNames serverName,
			final Boolean clientUsage, final boolean truncateCertificatePath, final CertificateMessage message,
			final DTLSSession session) {
		if (delayMillis <= 0) {
			if (delayMillis < 0) {
				try {
					Thread.sleep(-delayMillis);
				} catch (InterruptedException e) {
				}
			}
			return super.verifyCertificate(cid, serverName, clientUsage, truncateCertificatePath, message, session);
		} else {
			executorService.schedule(new Runnable() {

				@Override
				public void run() {
					verifyCertificateAsynchronous(cid, serverName, clientUsage, truncateCertificatePath, message,
							session);
				}
			}, delayMillis, TimeUnit.MILLISECONDS);
			return null;
		}
	}

	private void verifyCertificateAsynchronous(ConnectionId cid, ServerNames serverName, Boolean clientUsage,
			boolean truncateCertificatePath, CertificateMessage message, DTLSSession session) {
		CertificateVerificationResult result = super.verifyCertificate(cid, serverName, clientUsage,
				truncateCertificatePath, message, session);
		CertPath certPath = result.getCertificatePath();
		PublicKey publicKey = result.getPublicKey();
		if (certPath == null && publicKey == null) {
			LOGGER.info("Validation failed!");
		} else if (certPath != null) {
			LOGGER.info("Validation {}", certPath.getCertificates().size());
		} else if (publicKey != null) {
			LOGGER.info("Validation RPK");
		}
		resultHandler.apply(result);
	}

	@Override
	public void setResultHandler(HandshakeResultHandler resultHandler) {
		if (this.resultHandler != null && resultHandler != null && this.resultHandler != resultHandler) {
			throw new IllegalStateException("handshake result handler already set!");
		}
		this.resultHandler = resultHandler;
	}

	public static Builder builder() {
		return new Builder();
	}

	public static class Builder extends StaticNewAdvancedCertificateVerifier.Builder {

		public AsyncNewAdvancedCertificateVerifier build() {
			return new AsyncNewAdvancedCertificateVerifier(trustedCertificates, trustedRPKs, supportedCertificateTypes);
		}
	}
}
