/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations GmbH - initial implementation. 
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * Cipher manager.
 * 
 * Uses {@link ThreadLocal} to cache calls to
 * {@link Cipher#getInstance(String)}.
 */
public class CipherManager {

	private static final ThreadLocal<Map<String, Cipher>> threadLocalCipherMap = new ThreadLocal<Map<String, Cipher>>() {

		@Override
		protected Map<String, Cipher> initialValue() {
			return new HashMap<String, Cipher>(5);
		}
	};

	/**
	 * Get "thread local" instance of cipher for the provided transformation.
	 * 
	 * @param transformation transformation. Passed to
	 *            {@link Cipher#getInstance(String)} and used to lookup a
	 *            already created cipher.
	 * @return thread local cipher.
	 * @throws NoSuchAlgorithmException if {@link Cipher#getInstance(String)}
	 *             throws it.
	 * @throws NoSuchPaddingException if {@link Cipher#getInstance(String)}
	 *             throws it.
	 */
	public static Cipher getInstance(final String transformation)
			throws NoSuchAlgorithmException, NoSuchPaddingException {
		Map<String, Cipher> map = threadLocalCipherMap.get();
		Cipher cipher = map.get(transformation);
		if (cipher == null) {
			cipher = Cipher.getInstance(transformation);
			map.put(transformation, cipher);
		}
		return cipher;
	}
}
