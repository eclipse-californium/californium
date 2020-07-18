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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.util;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.eclipse.californium.elements.util.Bytes;

/**
 * Secure initial vector parameter specification.
 * 
 * Additional {@link Destroyable} to clear the iv after usage.
 */
public class SecretIvParameterSpec implements AlgorithmParameterSpec, Destroyable {

	/**
	 * The implicit iv.
	 *
	 * @serial
	 */
	private final byte[] iv;

	/**
	 * Indicates, that this instance has been {@link #destroy()}ed.
	 */
	private boolean destroyed;

	/**
	 * Create new secure iv parameters.
	 * 
	 * @param iv byte array
	 * @throws NullPointerException if iv is {@code null}
	 * @throws IllegalArgumentException if iv is empty.
	 */
	public SecretIvParameterSpec(byte[] iv) {
		this(iv, 0, iv.length);
	}

	/**
	 * Create new iv parameters.
	 * 
	 * @param iv byte array with the iv.
	 * @param offset offset of the iv within the byte array
	 * @param length length of the iv within the byte array
	 * @throws NullPointerException if iv is {@code null}
	 * @throws IllegalArgumentException if iv is empty, or length is negative or
	 *             offset and length doesn't fit into iv.
	 */
	public SecretIvParameterSpec(byte[] iv, int offset, int length) {
		if (iv == null) {
			throw new NullPointerException("IV missing");
		}
		if (iv.length == 0) {
			throw new IllegalArgumentException("IV is empty");
		}
		if (length < 0) {
			throw new ArrayIndexOutOfBoundsException("len is negative");
		}
		if (iv.length - offset < length) {
			throw new IllegalArgumentException("Invalid offset/length combination");
		}
		this.iv = Arrays.copyOfRange(iv, offset, offset + length);
	}

	/**
	 * Get copy of IV.
	 * 
	 * @return copy of iv.
	 * @throws IllegalStateException if instance was already destroyed
	 */
	public byte[] getIV() {
		if (destroyed) {
			throw new IllegalStateException("secret destroyed!");
		}
		return Arrays.copyOf(iv, iv.length);
	}

	/**
	 * Get iv extended by the explicit nonce.
	 * 
	 * @param explicitNonce byte array of explicit nonce.
	 * @return iv extended by explicit nonce
	 * @throws NullPointerException if explicit nonce is {@code null}
	 * @throws IllegalArgumentException explicit nonce iv is empty
	 * @throws IllegalStateException if instance was already destroyed
	 */
	public byte[] getIV(byte[] explicitNonce) {
		return getIV(explicitNonce, 0, explicitNonce.length);
	}

	/**
	 * Get iv extended by the explicit nonce.
	 * 
	 * @param explicitNonce byte array of explicit nonce.
	 * @param offset offset within byte array
	 * @param length length within byte array
	 * @return iv extended by explicit nonce
	 * @throws NullPointerException if explicit nonce is {@code null}
	 * @throws IllegalArgumentException explicit nonce iv is empty, or length is
	 *             negative or offset and length doesn't fit into explicit
	 *             nonce.
	 * @throws IllegalStateException if instance was already destroyed
	 */
	public byte[] getIV(byte[] explicitNonce, int offset, int length) {
		if (destroyed) {
			throw new IllegalStateException("secret destroyed!");
		}
		if (explicitNonce == null) {
			throw new NullPointerException("explicit nonce missing");
		}
		if (explicitNonce.length == 0) {
			throw new IllegalArgumentException("IV key");
		}
		if (length < 0) {
			throw new ArrayIndexOutOfBoundsException("len is negative");
		}
		if (explicitNonce.length - offset < length) {
			throw new IllegalArgumentException("Invalid offset/length combination");
		}
		byte[] result = Arrays.copyOf(iv, iv.length + length);
		System.arraycopy(explicitNonce, offset, result, iv.length, length);
		return result;
	}

	/**
	 * Destroy iv material.
	 */
	@Override
	public void destroy() throws DestroyFailedException {
		Bytes.clear(iv);
		destroyed = true;
	}

	@Override
	public boolean isDestroyed() {
		return destroyed;
	}

}
