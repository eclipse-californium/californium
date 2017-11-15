/*******************************************************************************
 * Copyright (c) 2015 - 2017 Institute for Pervasive Computing, ETH Zurich and others.
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

/**
 * See <a href="http://tools.ietf.org/html/rfc5246#appendix-A.4.1">RFC 5246</a>
 * for details.
 */
public final class SignatureAndHashAlgorithm {

	/**
	 * Hash algorithms as defined by
	 * <a href="http://tools.ietf.org/html/rfc5246#appendix-A.4.1">RFC 5246</a>.
	 * <P>
	 * Code is at most 255 (1 byte needed for representation).
	 */
	public static enum HashAlgorithm {

		NONE(0), MD5(1), SHA1(2), SHA224(3), SHA256(4), SHA384(5), SHA512(6);

		private int code;

		private HashAlgorithm(int code) {
			this.code = code;
		}

		/**
		 * Gets an algorithm by its code.
		 * 
		 * @param code The algorithm's code.
		 * @return The algorithm or {@code null} if no algorithm is defined for the given code by
		 *         <a href="https://tools.ietf.org/html/rfc5246#appendix-A.4.1">RFC 5246, Appendix A.4.1</a>.
		 */
		public static HashAlgorithm getAlgorithmByCode(int code) {
			for (HashAlgorithm algorithm : values()) {
				if (algorithm.code == code) {
					return algorithm;
				}
			}
			return null;
		}

		/**
		 * Gets the code of this algorithm as defined by
		 * <a href="https://tools.ietf.org/html/rfc5246#appendix-A.4.1">RFC 5246, Appendix A.4.1</a>.
		 * 
		 * @return The code.
		 */
		public int getCode() {
			return code;
		}
	}

	/**
	 * Signature algorithms as defined by
	 * <a href="http://tools.ietf.org/html/rfc5246#appendix-A.4.1">RFC 5246</a>.
	 * <p>
	 * Code is at most 255 (1 byte needed for representation).
	 */
	public static enum SignatureAlgorithm {

		ANONYMOUS(0), RSA(1), DSA(2), ECDSA(3);

		private int code;

		private SignatureAlgorithm(int code) {
			this.code = code;
		}

		/**
		 * Gets an algorithm by its code.
		 * 
		 * @param code The algorithm's code.
		 * @return The algorithm or {@code null} if no algorithm is defined for the given code by
		 *         <a href="https://tools.ietf.org/html/rfc5246#appendix-A.4.1">RFC 5246, Appendix A.4.1</a>.
		 */
		public static SignatureAlgorithm getAlgorithmByCode(int code) {
			switch (code) {
			case 0:
				return ANONYMOUS;
			case 1:
				return RSA;
			case 2:
				return DSA;
			case 3:
				return ECDSA;

			default:
				return null;
			}
		}

		/**
		 * Gets the code of this algorithm as defined by
		 * <a href="https://tools.ietf.org/html/rfc5246#appendix-A.4.1">RFC 5246, Appendix A.4.1</a>.
		 * 
		 * @return The code.
		 */
		public int getCode() {
			return code;
		}
	}

	private final HashAlgorithm hash;
	private final SignatureAlgorithm signature;

	/**
	 * Creates an instance for a hash and signature algorithm.
	 * 
	 * @param hashAlgorithm The hash algorithm.
	 * @param signatureAlgorithm The signature algorithm.
	 */
	public SignatureAndHashAlgorithm(HashAlgorithm hashAlgorithm, SignatureAlgorithm signatureAlgorithm) {

		this.signature = signatureAlgorithm;
		this.hash = hashAlgorithm;
	}

	/**
	 * Creates an instance for corresponding algorithm codes.
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

	/**
	 * Gets the signature algorithm in use.
	 * 
	 * @return The algorithm name.
	 */
	public SignatureAlgorithm getSignature() {
		return signature;
	}

	/**
	 * Gets the hash algorithm in use.
	 * 
	 * @return The algorithm name.
	 */
	public HashAlgorithm getHash() {
		return hash;
	}

	/**
	 * Gets the <a href="http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Signature">
	 * JCA standard name</a> corresponding to this combination of hash and signature algorithm.
	 * <p>
	 * The name returned by this method can be used to instantiate a {@code java.security.Signature} object like this:
	 * <pre>
	 * Signature signature = Signature.newInstance(signatureAndHash.jcaName());
	 * </pre>
	 * 
	 * @return The name.
	 */
	public String jcaName() {
		return hash.toString() + "with" + signature.toString();
	}
}
