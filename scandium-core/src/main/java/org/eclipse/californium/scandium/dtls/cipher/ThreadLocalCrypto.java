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

import org.eclipse.californium.elements.util.JceProviderUtil;

/**
 * Thread local crypto function.
 * 
 * Uses {@link ThreadLocal} to cache calls to {@link Factory#getInstance()}.
 */
public class ThreadLocalCrypto<CryptoFunction> {

	static {
		JceProviderUtil.init();
	}

	private final Factory<CryptoFunction> factory;
	private final GeneralSecurityException exception;
	private final ThreadLocal<CryptoFunction> threadLocalFunction;

	/**
	 * Create thread local crypto function.
	 * 
	 * Try to instance the crypto function for the provided factory. Failures
	 * may be accessed by {@link #getCause()}. Use {@link #isSupported()} to
	 * check, if the java-vm supports the crypto function.
	 * 
	 * @param factory factory to create instances of the crypto function.
	 * @see ThreadLocalCipher
	 * @see ThreadLocalMac
	 * @see ThreadLocalMessageDigest
	 */
	public ThreadLocalCrypto(Factory<CryptoFunction> factory) {
		GeneralSecurityException exception = null;
		Factory<CryptoFunction> supportedfactory = null;
		ThreadLocal<CryptoFunction> threadLocalCipher = null;
		try {
			CryptoFunction function = factory.getInstance();
			if (function != null) {
				supportedfactory = factory;
				threadLocalCipher = new ThreadLocal<CryptoFunction>();
				threadLocalCipher.set(function);
			} else {
				exception = new GeneralSecurityException(factory.getClass().getSimpleName() + " not supported!");
			}
		} catch (GeneralSecurityException e) {
			exception = e;
		}
		this.threadLocalFunction = threadLocalCipher;
		this.factory = supportedfactory;
		this.exception = exception;
	}

	/**
	 * Get "thread local" instance of crypto function.
	 * 
	 * @return thread local crypto function, or {@code null}, if crypto function
	 *         is not supported by the java-vm.
	 */
	public CryptoFunction current() {
		if (!isSupported()) {
			return null;
		}
		CryptoFunction function = threadLocalFunction.get();
		if (function == null) {
			try {
				function = factory.getInstance();
				threadLocalFunction.set(function);
			} catch (GeneralSecurityException e) {
			}
		}
		return function;
	}

	/**
	 * Get "thread local" instance of crypto function.
	 * 
	 * @return thread local crypto function.
	 * @throws GeneralSecurityException if crypto function is not supported by
	 *             the java-vm.
	 * 
	 * @since 2.3
	 */
	public CryptoFunction currentWithCause() throws GeneralSecurityException {
		if (exception != null) {
			throw exception;
		}
		return current();
	}

	/**
	 * Check, if crypto function is supported by the java-vm.
	 * 
	 * @return {@code true}, if crypto function is supported by the java-vm.
	 */
	public final boolean isSupported() {
		return exception == null;
	}

	/**
	 * Get the failure of the initial try to instantiate the crypto function for
	 * the provided factory.
	 * 
	 * @return failure, or {@code null}, if no failure occurred.
	 */
	public final GeneralSecurityException getCause() {
		return exception;
	}

	/**
	 * Factory to create instances of crypto functions.
	 */
	public static interface Factory<CryptoFunction> {

		/**
		 * Create instance of crypto function.
		 * 
		 * @return crypto function, or {@code null}, if not supported
		 * @throws GeneralSecurityException if not supported.
		 */
		CryptoFunction getInstance() throws GeneralSecurityException;
	}
}
