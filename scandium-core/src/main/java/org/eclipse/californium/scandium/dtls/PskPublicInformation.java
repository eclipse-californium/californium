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
 *    Bosch Software Innovations GmbH - initial API and implementation
 *******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.eclipse.californium.elements.util.StandardCharsets.UTF_8;

import java.util.Arrays;

import org.eclipse.californium.elements.auth.PreSharedKeyIdentity;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;

/**
 * Implementation of byte array based PSK public information (hint or identity).
 * 
 * Note: <a "https://tools.ietf.org/html/rfc4279#section-5.1">RFC 4279, Section
 * 5.1</a> defines to use UTF-8 to encode the identities. However, some peers
 * seems to use non UTF-8 encoded identities. This byte array based
 * implementation allows to support such non-compliant clients. The string based
 * identity is used for {@link PreSharedKeyIdentity}, therefore it's required to
 * use {@link #PskPublicInformation(String, byte[])} to setup a proper name for
 * such non-compliant peers in the
 * {@link org.eclipse.californium.scandium.dtls.pskstore.BytesPskStore}. During
 * the lookup of the secret key in the handshake, such a non-compliant identity
 * is normalized with the identity provided by the store.
 * 
 * <pre>
 * 
 */
public final class PskPublicInformation extends Bytes {

	public static final PskPublicInformation EMPTY = new PskPublicInformation("");

	private static final int MAX_LENGTH = 65535;

	/**
	 * {@code true}, if the byte array contains the string compliant encoded in
	 * UTF-8.
	 */
	private boolean compliantEncoding;

	/**
	 * Public information as string. The "hint" or "identity".
	 */
	private String publicInfo;

	/**
	 * Create PSK public information from bytes (identity or hint).
	 * 
	 * Used by {@link #fromByteArray(byte[])} for received public information
	 * (identity or hint).
	 * 
	 * @param publicInfoBytes PSK public information encoded as bytes. Identity
	 *            or hint.
	 * @throws NullPointerException if public information is {@code null}
	 * @throws IllegalArgumentException if public information length is larger
	 *             than {@link #MAX_LENGTH}.
	 */
	private PskPublicInformation(byte[] publicInfoBytes) {
		this(new String(publicInfoBytes, UTF_8), publicInfoBytes);
	}

	/**
	 * Create PSK public information from string (identity or hint).
	 * 
	 * @param publicInfo PSK public information as string. Identity or hint.
	 * @throws NullPointerException if public information is {@code null}
	 * @throws IllegalArgumentException if public information encoded in UTF-8
	 *             is larger than {@link #MAX_LENGTH}.
	 */
	public PskPublicInformation(String publicInfo) {
		super(publicInfo == null ? null : publicInfo.getBytes(UTF_8), MAX_LENGTH, false);
		this.publicInfo = publicInfo;
		this.compliantEncoding = true;
	}

	/**
	 * Create PSK public information from string and bytes (identity or hint).
	 * 
	 * Enables to create public information for none-compliant encodings!
	 * 
	 * Note: Please use this with care! Prefer to fix the clients and use it
	 * only as temporary work around!
	 * 
	 * @param publicInfo PSK public information as string. Identity or hint.
	 * @param publicInfoBytes PSK public information encoded as bytes. Identity
	 *            or hint.
	 * @throws NullPointerException if one of the parameters are {@code null}
	 * @throws IllegalArgumentException if public information encoded as bytes
	 *             is larger than {@link #MAX_LENGTH}.
	 */
	public PskPublicInformation(String publicInfo, byte[] publicInfoBytes) {
		super(publicInfoBytes, MAX_LENGTH, false);
		this.publicInfo = publicInfo;
		this.compliantEncoding = Arrays.equals(publicInfoBytes, publicInfo.getBytes(UTF_8));
	}

	/**
	 * Normalize public information.
	 * 
	 * Overwrite the decoded string with the intended string. Intended to be
	 * used during the PSK lookup and called, if a bytes-matching entry was
	 * found. The normalized string could then be used to create a
	 * {@link PreSharedKeyIdentity}.
	 * 
	 * @param publicInfo PSK public information as string. Identity or hint.
	 * @throws NullPointerException if public information is {@code null}
	 * @throws IllegalArgumentException if public information is empty.
	 * @see PskStore#getKey(PskPublicInformation)
	 * @see PskStore#getKey(org.eclipse.californium.scandium.util.ServerNames,
	 *      PskPublicInformation)
	 */
	public void normalize(String publicInfo) {
		if (publicInfo == null) {
			throw new NullPointerException("public information must not be null");
		}
		if (publicInfo.isEmpty()) {
			throw new IllegalArgumentException("public information must not be empty");
		}
		this.publicInfo = publicInfo;
		this.compliantEncoding = Arrays.equals(getBytes(), publicInfo.getBytes(UTF_8));
	}

	/**
	 * Check, if string is compliant encoded as bytes.
	 * 
	 * @return {@code true}, if encoding is compliant.
	 */
	public boolean isCompliantEncoding() {
		return compliantEncoding;
	}

	/**
	 * Get public information as string.
	 * 
	 * @return public information as string
	 */
	public String getPublicInfoAsString() {
		return publicInfo;
	}

	@Override
	public String toString() {
		if (compliantEncoding) {
			return publicInfo;
		} else {
			return publicInfo + "/" + getAsString();
		}
	}

	/**
	 * Create public information from received byte array.
	 * 
	 * @param byteArray received byte array
	 * @return public information
	 * @throws IllegalArgumentException if public information length is larger
	 *             than {@link #MAX_LENGTH}.
	 */
	public static PskPublicInformation fromByteArray(byte[] byteArray) {
		if (byteArray == null || byteArray.length == 0) {
			return EMPTY;
		}
		return new PskPublicInformation(byteArray);
	}

}
