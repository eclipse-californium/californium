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
 ******************************************************************************/
package org.eclipse.californium.scandium.auth;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PublicKey;

import javax.xml.bind.DatatypeConverter;

/**
 * A principal representing an authenticated peer's <em>RawPublicKey</em>.
 */
public class RawPublicKeyIdentity implements Principal {

	private final byte[] subjectPublicKeyInfo;
	private String niUri;
	
	/**
	 * Creates a new instance for a given key.
	 * 
	 * @param key the key
	 * @throws NullPointerException if the key is <code>null</code>
	 */
	public RawPublicKeyIdentity(PublicKey key) {
		this(key.getEncoded());
	}
	
	/**
	 * Creates a new instance for a given ASN.1 encoded <em>SubjectPublicKeyInfo</em>.
	 * 
	 * @param subjectPublicKeyInfo the key's subject info
	 * @throws NullPointerException if subject info is <code>null</code>
	 */
	public RawPublicKeyIdentity(byte[] subjectPublicKeyInfo) {
		if (subjectPublicKeyInfo == null) {
			throw new NullPointerException("Subject info must not be null");
		} else {
			this.subjectPublicKeyInfo = subjectPublicKeyInfo;
			createNamedInformationUri(subjectPublicKeyInfo);
		}
	}
	
	private void createNamedInformationUri(byte[] subjectPublicKeyInfo) {
		// TODO: replace this with some dedicated Base64 helper class
		// capable of native base64url encoding in order to prevent
		// ugly post-processing of base64 encoded digest
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(subjectPublicKeyInfo);
			byte[] digest = md.digest();
			String base64urlDigest = DatatypeConverter.printBase64Binary(digest);
			// difference between canonical base64 and base64url is
			// two characters in the encoding alphabet
			// and abstinence from padding
			base64urlDigest = base64urlDigest.replace('+', '-');
			base64urlDigest = base64urlDigest.replace('/', '_');
			StringBuffer b = new StringBuffer("ni:///sha-256;");
			if (base64urlDigest.endsWith("==")) {
				b.append(base64urlDigest.substring(0, base64urlDigest.length() - 2));
			} else if (base64urlDigest.endsWith("=")) {
				b.append(base64urlDigest.substring(0, base64urlDigest.length() - 1));
			} else {
				b.append(base64urlDigest);
			}
			niUri = b.toString();
		} catch (NoSuchAlgorithmException e) {
			// should not happen because SHA-256 is a mandatory message digest algorithm for any Java 7 VM
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
	 * Gets the key's ASN.1 encoded <em>SubjectPublicKeyInfo</em>.
	 * 
	 * @return the subject info
	 */
	public final byte[] getSubjectInfo() {
		return subjectPublicKeyInfo;
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
		return new StringBuffer("RawPublicKey Identity [").append(niUri).append("]").toString();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((niUri == null) ? 0 : niUri.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof RawPublicKeyIdentity)) {
			return false;
		}
		RawPublicKeyIdentity other = (RawPublicKeyIdentity) obj;
		if (niUri == null) {
			if (other.niUri != null) {
				return false;
			}
		} else if (!niUri.equals(other.niUri)) {
			return false;
		}
		return true;
	}
}
