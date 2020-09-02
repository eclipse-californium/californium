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

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Map of algorithms and thread local crypto functions.
 * 
 * Example:
 * 
 * <pre>
 * 
 * private static final ThreadLocalCryptoMap&lt;ThreadLocalSignature&gt; SIGNATURES = new ThreadLocalCryptoMap&lt;&gt;(
 * 		new Factory&lt;ThreadLocalSignature&gt;{
 * 
 * 			&#64;Override
 * 			public ThreadLocalSignature getInstance(String algorithm) {
 * 				return new ThreadLocalSignature(algorithm);
 * 			}
 * 		});
 * 
 * </pre>
 * 
 * @since 2.3
 */
public class ThreadLocalCryptoMap<TL extends ThreadLocalCrypto<?>> {

	private final ConcurrentMap<String, TL> FUNCTIONS = new ConcurrentHashMap<String, TL>();

	private final Factory<TL> factory;

	/**
	 * Create map of thread local crypto functions.
	 * 
	 * @param factory factory for thread local crypto function
	 */
	public ThreadLocalCryptoMap(Factory<TL> factory) {
		this.factory = factory;
	}

	/**
	 * Get thread local crypto function for algorithm.
	 * 
	 * @param algorithm name of algorithm
	 * @return thread local crypto function
	 */
	public TL get(String algorithm) {
		TL threadLocalCryptFunction = FUNCTIONS.get(algorithm);
		if (threadLocalCryptFunction == null) {
			TL function = factory.getInstance(algorithm);
			threadLocalCryptFunction = FUNCTIONS.putIfAbsent(algorithm, function);
			if (threadLocalCryptFunction == null) {
				threadLocalCryptFunction = function;
			}
		}
		return threadLocalCryptFunction;
	}

	/**
	 * Factory to create instances of a thread local crypto functions for the
	 * provided algorithm.
	 */
	public static interface Factory<T> {

		/**
		 * Create instance of a thread local crypto function.
		 * 
		 * @param algorithm algorithm of crypto function
		 * @return a thread local crypto function
		 */
		T getInstance(String algorithm);
	}

}
