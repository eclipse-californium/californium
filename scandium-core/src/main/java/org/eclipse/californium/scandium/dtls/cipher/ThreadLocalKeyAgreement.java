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

import javax.crypto.KeyAgreement;

/**
 * Thread local KeyAgreement.
 * 
 * Uses {@link ThreadLocal} to cache calls to
 * {@link KeyAgreement#getInstance(String)}.
 */
public class ThreadLocalKeyAgreement extends ThreadLocalCrypto<KeyAgreement> {

	/**
	 * Create thread local KeyAgreement.
	 * 
	 * Try to instance the KeyAgreement for the provided algorithm.
	 * 
	 * @param algorithm algorithm. Passed to
	 *            {@link KeyAgreement#getInstance(String)}.
	 * @see ThreadLocalCrypto
	 */
	public ThreadLocalKeyAgreement(final String algorithm) {
		super(new Factory<KeyAgreement>() {

			@Override
			public KeyAgreement getInstance() throws GeneralSecurityException {
				return KeyAgreement.getInstance(algorithm);
			}

		});
	}

}
