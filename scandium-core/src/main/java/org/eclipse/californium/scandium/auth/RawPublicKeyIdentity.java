/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - store PublicKey instead of <em>subjectInfo</em>
 ******************************************************************************/
package org.eclipse.californium.scandium.auth;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import org.eclipse.californium.scandium.util.Base64;

/**
 * A principal representing an authenticated peer's <em>RawPublicKey</em>.
 */
public class RawPublicKeyIdentity implements Principal {

	private static final int BASE_64_ENCODING_OPTIONS = Base64.ENCODE | Base64.URL_SAFE | Base64.NO_PADDING;
	private String niUri;
	private final PublicKey publicKey;

	/**
	 * Creates a new instance for a given public key.
	 * 
	 * @param key the public key
	 * @throws NullPointerException if the key is <code>null</code>
	 */
	public RawPublicKeyIdentity(PublicKey key) {
		if (key == null) {
			throw new NullPointerException("Public key must not be null");
		} else {
			this.publicKey = key;
			createNamedInformationUri(publicKey.getEncoded());
		}
	}

	/**
	 * Creates a new instance for a given ASN.1 subject public key info structure.
	 * 
	 * @param subjectInfo the ASN.1 encoded X.509 subject public key info.
	 * @throws NullPointerException if the subject info is <code>null</code>
	 * @throws GeneralSecurityException if the JVM does not support Elliptic Curve cryptography.
	 */
	public RawPublicKeyIdentity(byte[] subjectInfo) throws GeneralSecurityException {
		if (subjectInfo == null) {
			throw new NullPointerException("SubjectPublicKeyInfo must not be null");
		} else {
			X509EncodedKeySpec spec = new X509EncodedKeySpec(subjectInfo);
			this.publicKey = KeyFactory.getInstance("EC").generatePublic(spec);
			createNamedInformationUri(subjectInfo);
		}
	}

	private void createNamedInformationUri(byte[] subjectPublicKeyInfo) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(subjectPublicKeyInfo);
			byte[] digest = md.digest();
			String base64urlDigest = Base64.encodeBytes(digest, BASE_64_ENCODING_OPTIONS);
			StringBuilder b = new StringBuilder("ni:///sha-256;").append(base64urlDigest);
			niUri = b.toString();
		} catch (NoSuchAlgorithmException | IOException e) {
			// should not happen because SHA-256 is a mandatory message digest algorithm for any Java 7 VM
			// no Base64 encoding of InputStream is done
		}
	}

	/**
	 * Gets the <em>Named Information</em> URI representing this raw public key.
	 * 
	 * The URI is created using the SHA-256 hash algorithm on the key's
	 * <em>SubjectPublicKeyInfo</em> as described in
	 * <a href="http://tools.ietf.org/html/rfc6920#section-2">RFC 6920, section 2</a>.
	 * 
	 * @return the named information URI
	 */
	@Override
	public final String getName() {
		return niUri;
	}

	/**
	 * Gets the raw public key.
	 * 
	 * @return the key
	 */
	public final PublicKey getKey() {
		return publicKey;
	}

	/**
	 * Gets the key's ASN.1 encoded <em>SubjectPublicKeyInfo</em>.
	 * 
	 * @return the subject info
	 */
	public final byte[] getSubjectInfo() {
		return publicKey.getEncoded();
	}

	/**
	 * Gets a string representation of this principal.
	 * 
	 * Clients should not assume any particular format of the returned string
	 * since it may change over time.
	 *  
	 * @return the string representation
	 */
	@Override
	public String toString() {
		return new StringBuilder("RawPublicKey Identity [").append(niUri).append("]").toString();
	}

	/**
	 * Creates a hash code based on the key's ASN.1 encoded <em>SubjectPublicKeyInfo</em>.
	 * 
	 * @return the hash code
	 */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((publicKey == null) ? 0 : Arrays.hashCode(getSubjectInfo()));
		return result;
	}

	/**
	 * Checks if this instance is equal to another object.
	 * 
	 * @return <code>true</code> if the other object is a <code>RawPublicKeyIdentity</code>
	 *           and has the same <em>SubjectPublicKeyInfo</em> as this instance
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		} else if (obj == null) {
			return false;
		} else if (!(obj instanceof RawPublicKeyIdentity)) {
			return false;
		} else {
			RawPublicKeyIdentity other = (RawPublicKeyIdentity) obj;
			if (publicKey == null) {
				if (other.publicKey != null) {
					return false;
				}
			} else if (!Arrays.equals(getSubjectInfo(), other.getSubjectInfo())) {
				return false;
			}
			return true;
		}
	}
}
