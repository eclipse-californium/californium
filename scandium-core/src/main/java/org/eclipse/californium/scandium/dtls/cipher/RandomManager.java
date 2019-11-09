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
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix potentially equally initialized 
 *                                                    Random, if they are created very
 *                                                    fast from different threads without
 *                                                    currentTimeMillis changing. 
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
	/**
	 * Use system time as base for random seed.
	 */
	private static final long START = System.currentTimeMillis();

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
			return new Random(START + Thread.currentThread().getId());
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
