/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;

import org.eclipse.californium.elements.util.Asn1DerDecoder;

/**
 * Thread local KeyPairGenerator.
 * 
 * Uses {@link ThreadLocal} to cache calls to
 * {@link KeyPairGenerator#getInstance(String)}.
 */
public class ThreadLocalKeyPairGenerator extends ThreadLocalCrypto<KeyPairGenerator> {

	/**
	 * Create thread local KeyPairGenerator.
	 * 
	 * Try to instance the KeyPairGenerator for the provided algorithm.
	 * 
	 * @param algorithm algorithm. Passed to
	 *            {@link KeyPairGenerator#getInstance(String)}.
	 * @see ThreadLocalCrypto
	 */
	public ThreadLocalKeyPairGenerator(final String algorithm) {
		super(new Factory<KeyPairGenerator>() {

			@Override
			public KeyPairGenerator getInstance() throws GeneralSecurityException {
				String oid = Asn1DerDecoder.getEdDsaStandardAlgorithmName(algorithm, algorithm);
				return KeyPairGenerator.getInstance(oid);
			}

		});
	}

}
