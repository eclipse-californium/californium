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

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * Thread local cipher.
 * 
 * Uses {@link ThreadLocal} to cache calls to
 * {@link Cipher#getInstance(String)}.
 */
public class ThreadLocalCipher {

	private final String transformation;
	private final GeneralSecurityException exception;
	private final ThreadLocal<Cipher> threadLocalCipher;

	/**
	 * Create thread local cipher.
	 * 
	 * Try to instance the cipher for the provided transformation. Failures may
	 * be accessed by {@link #getCause()}. Use {@link #isSupported()} to check,
	 * if the java-vm supports the cipher.
	 * 
	 * @param transformation transformation. Passed to
	 *            {@link Cipher#getInstance(String)}.
	 */
	public ThreadLocalCipher(String transformation) {
		GeneralSecurityException exception = null;
		String supportedTransformation = null;
		ThreadLocal<Cipher> threadLocalCipher = null;
		try {
			Cipher cipher = Cipher.getInstance(transformation);
			if (cipher != null) {
				supportedTransformation = transformation;
				threadLocalCipher = new ThreadLocal<Cipher>();
				threadLocalCipher.set(cipher);
			}
		} catch (GeneralSecurityException e) {
			exception = e;
		}
		this.threadLocalCipher = threadLocalCipher;
		this.transformation = supportedTransformation;
		this.exception = exception;
	}

	/**
	 * Get "thread local" instance of cipher.
	 * 
	 * @return thread local cipher, or {@code null}, if cipher is not supported
	 *         by the java-vm.
	 */
	public Cipher current() {
		if (!isSupported()) {
			return null;
		}
		Cipher cipher = threadLocalCipher.get();
		if (cipher == null) {
			try {
				cipher = Cipher.getInstance(transformation);
				threadLocalCipher.set(cipher);
			} catch (NoSuchAlgorithmException e) {
			} catch (NoSuchPaddingException e) {
			}
		}
		return cipher;
	}

	/**
	 * Check, if cipher is supported by the java-vm.
	 * 
	 * @return {@code true}, if cipher is supported by the java-vm.
	 */
	public final boolean isSupported() {
		return transformation != null;
	}

	/**
	 * Get the failure of the initial try to instantiate the cipher for the
	 * provided transformation.
	 * 
	 * @return failure, or {@code null}, if cipher is supported.
	 */
	public final GeneralSecurityException getCause() {
		return exception;
	}
}
