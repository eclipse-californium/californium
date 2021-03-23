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

import java.security.MessageDigest;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.eclipse.californium.elements.util.Bytes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility to use {@link Destroyable} {@link SecretKey} for java before 1.8.
 */
public class SecretUtil {
	private static final Logger LOGGER = LoggerFactory.getLogger(SecretUtil.class);

	/**
	 * Destroy secret key.
	 * 
	 * @param key secret key to destroy. If {@code null}, nothing is destroyed.
	 */
	public static void destroy(SecretKey key) {
		if (key instanceof Destroyable) {
			destroy((Destroyable) key);
		}
	}

	/**
	 * Destroy provided security destroyable.
	 * 
	 * @param destroyable object to destroy. Maybe {@code null}.
	 */
	public static void destroy(Destroyable destroyable) {
		if (destroyable != null) {
			try {
				destroyable.destroy();
			} catch (DestroyFailedException e) {
				// Using SecretIvParameterSpec or SecretKey created by this class
				// should never throw it. Using other Destroyable implementations
				// may throw it.
				LOGGER.warn("Destroy on {} failed!", destroyable.getClass(), e);
			}
		}
	}

	/**
	 * Checks if a secret key has already been destroyed.
	 * 
	 * @param key secret key to check (may be {@code null}).
	 * @return {@code true} if the key either is {@code null} or has been destroyed.
	 */
	public static boolean isDestroyed(SecretKey key) {
		if (key != null) {
			if (key instanceof Destroyable) {
				return ((Destroyable) key).isDestroyed();
			} else {
				return false;
			}
		}
		return true;
	}

	/**
	 * Checks if a given destroyable has already been destroyed.
	 * 
	 * @param destroyable The destroyable to check (may be {@code null}).
	 * @return {@code true} if the given object either is {@code null} or has been destroyed.
	 */
	public static boolean isDestroyed(Destroyable destroyable) {
		return destroyable == null || destroyable.isDestroyed();
	}

	/**
	 * Creates a secret key.
	 * 
	 * @param secret The key material.
	 * @param algorithm The algorithm that the key is used for. The name
	 *                  <em>PSK</em> should be used if the key is supposed to
	 *                  be used with a PSK based TLS handshake.
	 * @return The newly created key which also implements {@code javax.security.auth.Destroyable}.
	 */
	public static SecretKey create(byte[] secret, String algorithm) {
		return new DestroyableSecretKeySpec(secret, algorithm);
	}

	/**
	 * Create a secret key.
	 * 
	 * @param secret The source to copy the key material from.
	 * @param offset The start index from which the key material should be copied.
	 * @param length The number of bytes to copy.
	 * @param algorithm The algorithm that the key is used for. The name
	 *                  <em>PSK</em> should be used if the key is supposed to
	 *                  be used with a PSK based TLS handshake.
	 * @return The newly created key which also implements {@code javax.security.auth.Destroyable}.
	 */
	public static SecretKey create(byte[] secret, int offset, int length, String algorithm) {
		return new DestroyableSecretKeySpec(secret, offset, length, algorithm);
	}

	/**
	 * Creates a copy of a secret key.
	 * 
	 * @param key The key to copy (may be {@code null}).
	 * @return The newly created key or {@code null} if the provided key was {@code null}.
	 *         The returned key also implements {@code javax.security.auth.Destroyable}.
	 */
	public static SecretKey create(SecretKey key) {
		SecretKey result = null;
		if (key != null) {
			byte[] secret = key.getEncoded();
			result = new DestroyableSecretKeySpec(secret, key.getAlgorithm());
			Bytes.clear(secret);
		}
		return result;
	}

	/**
	 * Creates copy of a secret init vector.
	 * 
	 * @param iv The init vector to copy (may be {@code null}).
	 * @return The newly created IV, or {@code null} if the provided IV was {@code null}.
	 */
	public static SecretIvParameterSpec createIv(SecretIvParameterSpec iv) {
		SecretIvParameterSpec result = null;
		if (iv != null) {
			result = new SecretIvParameterSpec(iv);
		}
		return result;
	}

	/**
	 * Create secret iv parameter (with destroyable implementation).
	 * 
	 * @param iv as byte array
	 * @param offset offset of iv within the provided byte array
	 * @param length length of iv
	 * @return the secret iv
	 * @throws NullPointerException if iv is {@code null}
	 * @throws IllegalArgumentException if iv is empty, or length is negative or
	 *             offset and length doesn't fit into iv.
	 */
	public static SecretIvParameterSpec createIv(byte[] iv, int offset, int length) {
		return new SecretIvParameterSpec(iv, offset, length);
	}

	/**
	 * Create secret iv parameter (with destroyable implementation).
	 * 
	 * @param iv as byte array
	 * @return the secret iv
	 * @throws NullPointerException if iv is {@code null}
	 * @since 2.6
	 */
	public static SecretIvParameterSpec createIv(byte[] iv) {
		return new SecretIvParameterSpec(iv, 0, iv.length);
	}

	/**
	 * Indicates whether some secret keys are "equal to" each other.
	 * 
	 * @param key1 first key to check
	 * @param key2 second key to check
	 * @return {@code true}, if the keys are equal, {@code false}, otherwise.
	 * @since 3.0
	 */
	public static boolean equals(SecretKey key1, SecretKey key2) {
		if (key1 == key2) {
			return true;
		} else if (key1 == null || key2 == null) {
			return false;
		}
		if (!key1.getAlgorithm().equals(key2.getAlgorithm())) {
			return false;
		}
		byte[] secret1 = key1.getEncoded();
		byte[] secret2 = key2.getEncoded();
		boolean ok = Arrays.equals(secret1, secret2);
		Bytes.clear(secret1);
		Bytes.clear(secret2);
		return ok;
	}

	private static class DestroyableSecretKeySpec implements KeySpec, SecretKey, Destroyable {

		private static final long serialVersionUID = 6578238307397289933L;

		private final int hashCode;
		/**
		 * The secret key.
		 *
		 * @serial
		 */
		private final byte[] key;

		/**
		 * The name of the algorithm associated with this key.
		 *
		 * @serial
		 */
		private final String algorithm;
		/**
		 * Indicates, that this instance has been {@link #destroy()}ed.
		 */
		private volatile boolean destroyed;

		private DestroyableSecretKeySpec(byte[] key, String algorithm) {
			this(key, 0, key == null ? 0 : key.length, algorithm);
		}

		private DestroyableSecretKeySpec(byte[] key, int offset, int len, String algorithm) {
			if (key == null) {
				throw new NullPointerException("Key missing");
			}
			if (algorithm == null) {
				throw new NullPointerException("Algorithm missing");
			}
			if (key.length == 0) {
				throw new IllegalArgumentException("Empty key");
			}
			if (key.length - offset < len) {
				throw new IllegalArgumentException("Invalid offset/length combination");
			}
			if (len < 0) {
				throw new ArrayIndexOutOfBoundsException("len is negative");
			}
			this.key = Arrays.copyOfRange(key, offset, offset + len);
			this.algorithm = algorithm;
			this.hashCode = calcHashCode();
		}

		private int calcHashCode() {
			return hashCode;
		}

		@Override
		public String getAlgorithm() {
			return algorithm;
		}

		@Override
		public String getFormat() {
			return "RAW";
		}

		@Override
		public byte[] getEncoded() {
			if (destroyed) {
				throw new IllegalStateException("secret destroyed!");
			}
			return key.clone();
		}

		@Override
		public int hashCode() {
			return hashCode;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			} else if (!(obj instanceof SecretKey)) {
				return false;
			}
			SecretKey other = (SecretKey) obj;
			if (!algorithm.equalsIgnoreCase(other.getAlgorithm())) {
				return false;
			}
			if (destroyed) {
				throw new IllegalStateException("secret destroyed!");
			}
			byte[] otherKey = other.getEncoded();
			boolean result = MessageDigest.isEqual(key, otherKey);
			Bytes.clear(otherKey);
			return result;
		}

		/**
		 * Destroy key material! {@link #equals(Object)} and {@link #hashCode}
		 * must not be used after the key is destroyed!
		 */
		@Override
		public void destroy() throws DestroyFailedException {
			Bytes.clear(key);
			destroyed = true;
		}

		@Override
		public boolean isDestroyed() {
			return destroyed;
		}
	}

}
