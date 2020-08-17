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
import java.security.KeyFactory;
import java.security.Provider;

import org.eclipse.californium.elements.util.Asn1DerDecoder;

/**
 * Thread local KeyFactory.
 * 
 * Uses {@link ThreadLocal} to cache calls to
 * {@link KeyFactory#getInstance(String)}.
 * 
 * @since 2.3
 */
public class ThreadLocalKeyFactory extends ThreadLocalCrypto<KeyFactory> {

	/**
	 * Create thread local KeyFactory.
	 * 
	 * Try to instance the KeyFactory for the provided algorithm.
	 * 
	 * @param algorithm algorithm. Passed to
	 *            {@link KeyFactory#getInstance(String)}.
	 * @see ThreadLocalCrypto
	 */
	public ThreadLocalKeyFactory(final String algorithm) {
		super(new Factory<KeyFactory>() {

			@Override
			public KeyFactory getInstance() throws GeneralSecurityException {
				String oid = Asn1DerDecoder.getEdDsaStandardAlgorithmName(algorithm, null);
				if (oid != null) {
					Provider provider = Asn1DerDecoder.getEdDsaProvider();
					if (provider != null) {
						return KeyFactory.getInstance(oid, provider);
					}
				}
				return KeyFactory.getInstance(algorithm);
			}

		});
	}

}
