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
import java.security.MessageDigest;

/**
 * Thread local MessageDigest.
 * 
 * Uses {@link ThreadLocal} to cache calls to
 * {@link MessageDigest#getInstance(String)}.
 */
public class ThreadLocalMessageDigest extends ThreadLocalCrypto<MessageDigest> {

	/**
	 * Create thread local MessageDigest.
	 * 
	 * Try to instance the MessageDigest for the provided algorithm.
	 * 
	 * @param algorithm algorithm. Passed to
	 *            {@link MessageDigest#getInstance(String)}.
	 * @see ThreadLocalCrypto
	 */
	public ThreadLocalMessageDigest(final String algorithm) {
		super(new Factory<MessageDigest>() {

			@Override
			public MessageDigest getInstance() throws GeneralSecurityException {
				return MessageDigest.getInstance(algorithm);
			}

		});
	}

}
