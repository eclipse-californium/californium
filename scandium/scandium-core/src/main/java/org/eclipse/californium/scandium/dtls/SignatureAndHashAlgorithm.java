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
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.scandium.dtls.CertificateRequest.HashAlgorithm;
import org.eclipse.californium.scandium.dtls.CertificateRequest.SignatureAlgorithm;

/**
 * See <a href="http://tools.ietf.org/html/rfc5246#appendix-A.4.1">RFC 5246</a>
 * for details.
 */
public class SignatureAndHashAlgorithm {
	
	// Members ////////////////////////////////////////////////////////

	private HashAlgorithm hash;

	private SignatureAlgorithm signature;
	
	// Constructors ///////////////////////////////////////////////////

	public SignatureAndHashAlgorithm(HashAlgorithm hashAlgorithm, SignatureAlgorithm signatureAlgorithm) {
		this.signature = signatureAlgorithm;
		this.hash = hashAlgorithm;
	}
	
	/**
	 * Constructs it with the corresponding codes (received when parsing the
	 * received message).
	 * 
	 * @param hashAlgorithmCode
	 *            the hash algorithm's code.
	 * @param signatureAlgorithmCode
	 *            the signature algorithm's code.
	 */
	public SignatureAndHashAlgorithm(int hashAlgorithmCode, int signatureAlgorithmCode) {
		this.signature = SignatureAlgorithm.getAlgorithmByCode(signatureAlgorithmCode);
		this.hash = HashAlgorithm.getAlgorithmByCode(hashAlgorithmCode);
	}
	
	// Getters and Setters ////////////////////////////////////////////

	public SignatureAlgorithm getSignature() {
		return signature;
	}

	public void setSignature(SignatureAlgorithm signature) {
		this.signature = signature;
	}

	public HashAlgorithm getHash() {
		return hash;
	}

	public void setHash(HashAlgorithm hash) {
		this.hash = hash;
	}
	
	@Override
	public String toString() {
		// Construct the signature algorithm according to
		// http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Signature
		return hash.toString() + "with" + signature.toString();
	}
}
