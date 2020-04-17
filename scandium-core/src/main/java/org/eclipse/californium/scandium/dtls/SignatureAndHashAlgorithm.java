/*******************************************************************************
 * Copyright (c) 2015 - 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalSignature;

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

	private static final ConcurrentMap<String, ThreadLocalSignature> SIGNATURES = new ConcurrentHashMap<String, ThreadLocalSignature>();

	/**
	 * SHA1_with_Ecdsa.
	 * 
	 * @since 2.3
	 */
	public static SignatureAndHashAlgorithm SHA1_WITH_ECDSA = new SignatureAndHashAlgorithm(HashAlgorithm.SHA1,
			SignatureAlgorithm.ECDSA);
	/**
	 * SHA256_with_Ecdsa.
	 * 
	 * @since 2.3
	 */
	public static SignatureAndHashAlgorithm SHA256_WITH_ECDSA = new SignatureAndHashAlgorithm(HashAlgorithm.SHA256,
			SignatureAlgorithm.ECDSA);
	/**
	 * SHA384_with_Ecdsa.
	 * 
	 * @since 2.3
	 */
	public static SignatureAndHashAlgorithm SHA384_WITH_ECDSA = new SignatureAndHashAlgorithm(HashAlgorithm.SHA384,
			SignatureAlgorithm.ECDSA);
	/**
	 * SHA256_with_Rsa.
	 * 
	 * @since 2.3
	 */
	public static SignatureAndHashAlgorithm SHA256_WITH_RSA = new SignatureAndHashAlgorithm(HashAlgorithm.SHA256,
			SignatureAlgorithm.RSA);
	/**
	 * Default list of supported signature and hash algorithms. Contains only
	 * SHA256_with_Ecdsa.
	 * 
	 * @since 2.3
	 */
	public static List<SignatureAndHashAlgorithm> DEFAULT = Collections
			.unmodifiableList(Arrays.asList(SHA256_WITH_ECDSA));

	/**
	 * Get thread local signature.
	 * 
	 * @param algorithm name of signature algorithm
	 * @return thread local signature.
	 * @since 2.3
	 */
	public static ThreadLocalSignature getThreadLocalSignature(String algorithm) {
		if (algorithm == null) {
			algorithm = "UNKNOWN";
		}
		ThreadLocalSignature threadLocalSignature = SIGNATURES.get(algorithm);
		if (threadLocalSignature == null) {
			SIGNATURES.putIfAbsent(algorithm, new ThreadLocalSignature(algorithm));
			threadLocalSignature = SIGNATURES.get(algorithm);
		}
		return threadLocalSignature;
	}

	/**
	 * Get signature and hash algorithm from JCA name.
	 * 
	 * @param jcaName name of signature and hash algorithm. e.g.
	 *            "SHA256withECDSA".
	 * @return signature and hash algorithm, or {@code null}, if signature or
	 *         hash is unknown.
	 * 
	 * @since 2.3
	 */
	public static SignatureAndHashAlgorithm valueOf(String jcaName) {
		int index = jcaName.indexOf("with");
		if (index < 0) {
			index = jcaName.indexOf("WITH");
		}
		if (0 < index) {
			String hash = jcaName.substring(0, index);
			String signature = jcaName.substring(index + 4, jcaName.length());
			HashAlgorithm hashAlgorithm = HashAlgorithm.valueOf(hash);
			SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.valueOf(signature);
			if (hashAlgorithm != null && signatureAlgorithm != null) {
				return new SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm);
			}
		}
		return null;
	}

	/**
	 * Get list of signature and hash algorithms from certificate chain.
	 * 
	 * @param certificateChain certificate chain
	 * @return list list of signature and hash algorithms
	 * 
	 * @since 2.3
	 */
	public static List<SignatureAndHashAlgorithm> getSignatureAlgorithmsFromCertificateChain(
			List<X509Certificate> certificateChain) {
		List<SignatureAndHashAlgorithm> result = new ArrayList<>();
		for (X509Certificate certificate : certificateChain) {
			String sigAlgName = certificate.getSigAlgName();
			SignatureAndHashAlgorithm signature = valueOf(sigAlgName);
			if (signature != null && !result.contains(signature)) {
				result.add(signature);
			}
		}
		return result;
	}

	/**
	 * Get the common signature and hash algorithms in the order of the proposed
	 * list.
	 * 
	 * @param proposedSignatureAndHashAlgorithms proposed signature and hash
	 *            algorithms, ordered
	 * @param supportedSignatureAndHashAlgorithms supported signature and hash
	 *            algorithms
	 * @return list of common signature and hash algorithms in the order of the
	 *         proposed list. empty, if no common signature and hash algorithm
	 *         is found.
	 * 
	 * @since 2.3
	 */
	public static List<SignatureAndHashAlgorithm> getCommonSignatureAlgorithms(
			List<SignatureAndHashAlgorithm> proposedSignatureAndHashAlgorithms,
			List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms) {
		List<SignatureAndHashAlgorithm> result = new ArrayList<>();
		for (SignatureAndHashAlgorithm algo : proposedSignatureAndHashAlgorithms) {
			if (supportedSignatureAndHashAlgorithms.contains(algo)) {
				result.add(algo);
			}
		}
		return result;
	}

	/**
	 * Gets a signature and hash algorithm that is compatible with a given
	 * public key.
	 * 
	 * @param supportedSignatureAlgorithms list of supported signature and hash
	 *            algorithms.
	 * @param key public key
	 * @return A signature and hash algorithm that can be used with the provided
	 *         public key, or {@code null}, if the public key is not compatible
	 *         with any of the supported signature and hash algorithms.
	 * 
	 * @since 2.3
	 */
	public static SignatureAndHashAlgorithm getSupportedSignatureAlgorithm(
			List<SignatureAndHashAlgorithm> supportedSignatureAlgorithms, PublicKey key) {
		for (SignatureAndHashAlgorithm supportedAlgorithm : supportedSignatureAlgorithms) {
			try {
				Signature sign = supportedAlgorithm.getThreadLocalSignature().current();
				if (sign != null) {
					sign.initVerify(key);
					return supportedAlgorithm;
				}
			} catch (InvalidKeyException e) {
			}
		}
		return null;
	}

	/**
	 * Checks if all of a given certificates in the chain have been signed using
	 * a algorithm supported by the server.
	 * 
	 * @param supportedSignatureAlgorithms list of supported signature and hash
	 *            algorithms.
	 * @param certificateChain The certificate chain to test.
	 * @return {@code true} if all certificates have been signed using a
	 *         supported algorithm.
	 * 
	 * @since 2.3
	 */
	public static boolean isSignedWithSupportedAlgorithms(List<SignatureAndHashAlgorithm> supportedSignatureAlgorithms,
			List<X509Certificate> certificateChain) {
		for (X509Certificate certificate : certificateChain) {
			if (!isSignedWithSupportedAlgorithm(supportedSignatureAlgorithms, certificate)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Checks if the given certificate have been signed using one of the
	 * algorithms supported by the server.
	 * 
	 * @param certificate The certificate to test.
	 * @return {@code true} if the certificate have been signed using one of the
	 *         supported algorithms.
	 * 
	 * @since 2.3
	 */
	private static boolean isSignedWithSupportedAlgorithm(List<SignatureAndHashAlgorithm> supportedSignatureAlgorithms,
			X509Certificate certificate) {
		String sigAlgName = certificate.getSigAlgName();
		for (SignatureAndHashAlgorithm supportedAlgorithm : supportedSignatureAlgorithms) {
			// android's certificate returns a upper case SigAlgName, e.g.
			// "SHA256WITHECDSA", but the getJcaName returns a mixed case
			// name, e.g. "SHA256withECDSA"
			if (supportedAlgorithm.getJcaName().equalsIgnoreCase(sigAlgName)) {
				return true;
			}
		}
		return false;
	}


	private final String jcaName;
	private final HashAlgorithm hash;
	private final SignatureAlgorithm signature;
	private final int hashAlgorithmCode;
	private final int signatureAlgorithmCode;
	private final boolean supported;

	/**
	 * Creates an instance for a hash and signature algorithm.
	 * 
	 * @param hashAlgorithm The hash algorithm.
	 * @param signatureAlgorithm The signature algorithm.
	 * @throws NullPointerException if one of the provided arguments was
	 *             {@code null}
	 */
	public SignatureAndHashAlgorithm(HashAlgorithm hashAlgorithm, SignatureAlgorithm signatureAlgorithm) {
		if (hashAlgorithm == null) {
			throw new NullPointerException("Hash Algorithm must not be null!");
		}
		if (signatureAlgorithm == null) {
			throw new NullPointerException("Signature Algorithm must not be null!");
		}
		this.hash = hashAlgorithm;
		this.signature = signatureAlgorithm;
		this.hashAlgorithmCode = hashAlgorithm.getCode();
		this.signatureAlgorithmCode = signatureAlgorithm.getCode();
		this.jcaName = buildJcaName();
		this.supported = jcaName != null && getThreadLocalSignature(jcaName) .current() != null;
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
		this.hashAlgorithmCode = hashAlgorithmCode;
		this.signatureAlgorithmCode = signatureAlgorithmCode;
		this.signature = SignatureAlgorithm.getAlgorithmByCode(signatureAlgorithmCode);
		this.hash = HashAlgorithm.getAlgorithmByCode(hashAlgorithmCode);
		this.jcaName = buildJcaName();
		this.supported = jcaName != null && getThreadLocalSignature(jcaName) .current() != null;
	}

	private String buildJcaName() {
		if (hash != null && signature != null) {
			StringBuilder name = new StringBuilder();
			name.append(hash);
			name.append("with");
			name.append(signature);
			return name.toString();
		}
		return null;
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
	 * @return The name, or {@code null}, if name is not available/not known by this implementation.
	 * 
	 * @since 2.3
	 */
	public String getJcaName() {
		return jcaName;
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
	 * @return The name, or {@code null}, if name is not available/not known by this implementation.
	 * @deprecated use {@link #getJcaName()}.
	 */
	@Deprecated
	public String jcaName() {
		return jcaName;
	}

	/**
	 * Check, if signature and hash algorithm is supported by JRE.
	 * 
	 * @return {@code true}, if supported by JRE, {@code false}, otherwise.
	 * @since 2.3
	 */
	public boolean isSupported() {
		return supported;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Returns literal name, if signature or hash algortihm is unknown.
	 * 
	 * @since 2.3
	 */
	@Override
	public String toString() {
		if (jcaName != null) {
			return jcaName;
		} else {
			StringBuilder result = new StringBuilder();
			if (hash != null) {
				result.append(hash);
			} else {
				result.append(String.format("0x%02x", hashAlgorithmCode));
			}
			result.append("with");
			if (signature != null) {
				result.append(signature);
			} else {
				result.append(String.format("0x%02x", signatureAlgorithmCode));
			}
			return result.toString();
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @since 2.3
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		} else if (obj == null) {
			return false;
		} else if (getClass() != obj.getClass()) {
			return false;
		}
		SignatureAndHashAlgorithm other = (SignatureAndHashAlgorithm) obj;
		return this.signatureAlgorithmCode == other.signatureAlgorithmCode
				&& this.hashAlgorithmCode == other.hashAlgorithmCode;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @since 2.3
	 */
	@Override
	public int hashCode() {
		return this.hashAlgorithmCode * 100 + this.signatureAlgorithmCode;
	}

	/**
	 * Get thread local signature for this signature and hash algorithm.
	 * 
	 * @return thread local signature.
	 * @since 2.3
	 */
	public ThreadLocalSignature getThreadLocalSignature() {
		return getThreadLocalSignature(getJcaName());
	}
}
