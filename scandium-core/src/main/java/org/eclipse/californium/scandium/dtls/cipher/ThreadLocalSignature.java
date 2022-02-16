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
package org.eclipse.californium.scandium.dtls.cipher;

import java.security.GeneralSecurityException;
import java.security.Signature;

import org.eclipse.californium.elements.util.JceProviderUtil;

/**
 * Thread local Signature.
 * 
 * Uses {@link ThreadLocal} to cache calls to
 * {@link Signature#getInstance(String)}.
 * 
 * @since 2.3
 */
public class ThreadLocalSignature extends ThreadLocalCrypto<Signature> {

	/**
	 * Create thread local Signature.
	 * 
	 * Try to instance the Signature for the provided algorithm.
	 * 
	 * @param algorithm algorithm. Passed to
	 *            {@link Signature#getInstance(String)}.
	 * @see ThreadLocalCrypto
	 */
	public ThreadLocalSignature(final String algorithm) {
		super(new Factory<Signature>() {

			@Override
			public Signature getInstance() throws GeneralSecurityException {
				String standardAlgorithm = JceProviderUtil.getEdDsaStandardAlgorithmName(algorithm, algorithm);
				return Signature.getInstance(standardAlgorithm);
			}

		});
	}

	/**
	 * Map of thread local key signatures.
	 * 
	 * @since 2.5
	 */
	public static final ThreadLocalCryptoMap<ThreadLocalSignature> SIGNATURES = new ThreadLocalCryptoMap<>(
			new ThreadLocalCryptoMap.Factory<ThreadLocalSignature>() {

				@Override
				public ThreadLocalSignature getInstance(String algorithm) {
					return new ThreadLocalSignature(algorithm);
				}
			});

}
