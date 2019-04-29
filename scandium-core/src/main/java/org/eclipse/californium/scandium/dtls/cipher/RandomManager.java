/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation. 
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import java.security.SecureRandom;
import java.util.Random;

/**
 * Random manager.
 * 
 * Uses {@link ThreadLocal} to cache calls to {@link SecureRandom} and
 * {@link Random}.
 */
public class RandomManager {

	private static final ThreadLocal<SecureRandom> threadLocalSecureRandom = new ThreadLocal<SecureRandom>() {

		@Override
		protected SecureRandom initialValue() {
			return new SecureRandom();
		}
	};

	/**
	 * Get thread local secure random.
	 * 
	 * @return thread local secure random
	 */
	public static SecureRandom currentSecureRandom() {
		return threadLocalSecureRandom.get();
	}

	private static final ThreadLocal<Random> threadLocalRandom = new ThreadLocal<Random>() {

		@Override
		protected Random initialValue() {
			return new Random(System.currentTimeMillis());
		}
	};

	/**
	 * Get thread local random.
	 * 
	 * @return thread local random
	 */
	public static Random currentRandom() {
		return threadLocalRandom.get();
	}
}
