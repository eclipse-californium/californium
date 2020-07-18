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

import javax.crypto.Mac;

/**
 * Thread local mac.
 * 
 * Uses {@link ThreadLocal} to cache calls to {@link Mac#getInstance(String)}.
 */
public class ThreadLocalMac extends ThreadLocalCrypto<Mac> {

	/**
	 * Create thread local mac.
	 * 
	 * Try to instance the mac for the provided algorithm.
	 * 
	 * @param algorithm algorithm. Passed to {@link Mac#getInstance(String)}.
	 * @see ThreadLocalCrypto
	 */
	public ThreadLocalMac(final String algorithm) {
		super(new Factory<Mac>() {

			@Override
			public Mac getInstance() throws GeneralSecurityException {
				return Mac.getInstance(algorithm);
			}

		});
	}

}
