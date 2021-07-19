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

import org.eclipse.californium.elements.util.Asn1DerDecoder;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalSignature;
import org.eclipse.californium.scandium.util.ListUtils;

/**
 * See <a href="https://tools.ietf.org/html/rfc5246#appendix-A.4.1" target=
 * "_blank">RFC 5246</a> for details.
 * 
 * Since 2.4: added support for
 * <a href="https://tools.ietf.org/html/rfc8422#section-5.1.3" target=
 * "_blank">RFC 8422</a>.
 * 
 * Since 3.0: added recommend for upcoming <a href=
 * "https://datatracker.ietf.org/doc/html/draft-ietf-tls-md5-sha1-deprecate-07"
 * target="_blank">draft-ietf-tls-md5-sha1-deprecate</a>.
 */
public final class SignatureAndHashAlgorithm {

	/**
	 * Hash algorithms as defined by
	 * <a href="https://tools.ietf.org/html/rfc5246#appendix-A.4.1" target=
	 * "_blank">RFC 5246</a>.
	 * <P>
	 * Code is at most 255 (1 byte needed for representation).
	 * 
	 * Since 2.4: added {@link #INTRINSIC} defined by
	 * <a href="https://tools.ietf.org/html/rfc8422#section-5.1.3" target=
	 * "_blank">RFC 8422</a>.
	 * 
	 * Since 3.0: added recommend for upcoming <a href=
	 * "https://datatracker.ietf.org/doc/html/draft-ietf-tls-md5-sha1-deprecate-07"
	 * target="_blank">draft-ietf-tls-md5-sha1-deprecate</a>.
	 * 
	 * SHA224 is not listed in the "TLS SignatureScheme", therefore it is set to
	 * "not recommended".
	 */
	public static enum HashAlgorithm {

		NONE(0, false), MD5(1, false), SHA1(2, false), SHA224(3, false), SHA256(4, true), SHA384(5, true), SHA512(6,
				true),
		/**
		 * Do not hash before sign.
		 * 
		 * @since 2.4
		 */
		INTRINSIC(8, true);

		private final int code;
		private final boolean recommended;

		private HashAlgorithm(int code, boolean recommended) {
			this.code = code;
			this.recommended = recommended;
		}

		/**
		 * Gets an algorithm by its code.
		 * 
		 * @param code The algorithm's code.
		 * @return The algorithm or {@code null} if no algorithm is defined for
		 *         the given code by
		 *         <a href="https://tools.ietf.org/html/rfc5246#appendix-A.4.1"
		 *         target="_blank">RFC 5246, Appendix A.4.1</a>, or
		 *         <a href="https://tools.ietf.org/html/rfc8422#section-5.1.3"
		 *         target="_blank">RFC 8422, Section 5.1.3</a>.
		 */
		public static HashAlgorithm getAlgorithmByCode(int code) {
			switch (code) {
			case 0:
				return NONE;
			case 1:
				return MD5;
			case 2:
				return SHA1;
			case 3:
				return SHA224;
			case 4:
				return SHA256;
			case 5:
				return SHA384;
			case 6:
				return SHA512;
			case 8:
				return INTRINSIC;

			default:
				return null;
			}
		}

		/**
		 * Gets the code of this algorithm as defined by
		 * <a href="https://tools.ietf.org/html/rfc5246#appendix-A.4.1" target=
		 * "_blank">RFC 5246, Appendix A.4.1</a>, or
		 * <a href="https://tools.ietf.org/html/rfc8422#section-5.1.3" target=
		 * "_blank">RFC 8422, Section 5.1.3</a>.
		 * 
		 * @return The code.
		 */
		public int getCode() {
			return code;
		}

		public boolean isRecommended() {
			return recommended;
		}
	}

	/**
	 * Signature algorithms as defined by
	 * <a href="https://tools.ietf.org/html/rfc5246#appendix-A.4.1" target=
	 * "_blank">RFC 5246</a>.
	 * <p>
	 * Code is at most 255 (1 byte needed for representation).
	 * 
	 * Since 2.4: added {@link #ED25519} and {@link #ED448} defined by
	 * <a href="https://tools.ietf.org/html/rfc8422#section-5.1.3" target=
	 * "_blank">RFC 8422</a>.
	 */
	public static enum SignatureAlgorithm {

		ANONYMOUS(0), RSA(1), DSA(2), ECDSA(3, Asn1DerDecoder.EC, true, false),
		/**
		 * ED25519 signature.
		 * 
		 * @since 2.4
		 */
		ED25519(7, Asn1DerDecoder.OID_ED25519, true, true),
		/**
		 * ED448 signature
		 * 
		 * @since 2.4
		 */
		ED448(8, Asn1DerDecoder.OID_ED448, true, true);

		private final int code;
		private final String keyAlgorithm;
		private final boolean isEcdsaCompatible;
		private final boolean isIntrinsic;

		private SignatureAlgorithm(int code) {
			this.code = code;
			this.keyAlgorithm = name();
			this.isEcdsaCompatible = false;
			this.isIntrinsic = false;
		}

		private SignatureAlgorithm(int code, String keyAlgorithm, boolean ecdsa, boolean intrinsic) {
			this.code = code;
			this.keyAlgorithm = keyAlgorithm;
			this.isEcdsaCompatible = ecdsa;
			this.isIntrinsic = intrinsic;
		}

		/**
		 * Gets an algorithm by its code.
		 * 
		 * @param code The algorithm's code.
		 * @return The algorithm or {@code null} if no algorithm is defined for
		 *         the given code by
		 *         <a href="https://tools.ietf.org/html/rfc5246#appendix-A.4.1"
		 *         target="_blank">RFC 5246, Appendix A.4.1</a>, or
		 *         <a href="https://tools.ietf.org/html/rfc8422#section-5.1.3"
		 *         target="_blank">RFC 8422, Section 5.1.3</a>.
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
			case 7:
				return ED25519;
			case 8:
				return ED448;

			default:
				return null;
			}
		}

		/**
		 * Gets the code of this algorithm as defined by
		 * <a href="https://tools.ietf.org/html/rfc5246#appendix-A.4.1" target=
		 * "_blank">RFC 5246, Appendix A.4.1</a>, or
		 * <a href="https://tools.ietf.org/html/rfc8422#section-5.1.3" target=
		 * "_blank">RFC 8422, Section 5.1.3</a>.
		 * 
		 * @return The code.
		 */
		public int getCode() {
			return code;
		}

		/**
		 * Gets ECDSA compatibility.
		 * 
		 * @return {@code true}, for ECDSA compatible signature, {@code false},
		 *         otherwise.
		 * @since 2.4
		 */
		public boolean isEcdsaCompatible() {
			return isEcdsaCompatible;
		}

		/**
		 * Checks, if key algorithm is supported by signature algorithm.
		 * 
		 * The key size is not considered, and so supported signatures may fail
		 * to actually use the public key.
		 * 
		 * @param keyAlgorithm key algorithm.
		 * @return {@code true}, if supported, {@code false}, otherwise.
		 */
		public boolean isSupported(String keyAlgorithm) {
			String key = Asn1DerDecoder.getEdDsaStandardAlgorithmName(keyAlgorithm, keyAlgorithm);
			if (Asn1DerDecoder.EDDSA.equalsIgnoreCase(key)) {
				return ED25519 == this || ED448 == this;
			} else {
				return this.keyAlgorithm.equalsIgnoreCase(key);
			}
		}
	}

	/**
	 * SHA1_with_Ecdsa.
	 * 
	 * @since 2.3
	 */
	public static final SignatureAndHashAlgorithm SHA1_WITH_ECDSA = new SignatureAndHashAlgorithm(HashAlgorithm.SHA1,
			SignatureAlgorithm.ECDSA);
	/**
	 * SHA256_with_Ecdsa.
	 * 
	 * @since 2.3
	 */
	public static final SignatureAndHashAlgorithm SHA256_WITH_ECDSA = new SignatureAndHashAlgorithm(
			HashAlgorithm.SHA256, SignatureAlgorithm.ECDSA);
	/**
	 * SHA384_with_Ecdsa.
	 * 
	 * @since 2.3
	 */
	public static final SignatureAndHashAlgorithm SHA384_WITH_ECDSA = new SignatureAndHashAlgorithm(
			HashAlgorithm.SHA384, SignatureAlgorithm.ECDSA);
	/**
	 * SHA256_with_Rsa.
	 * 
	 * @since 2.3
	 */
	public static final SignatureAndHashAlgorithm SHA256_WITH_RSA = new SignatureAndHashAlgorithm(HashAlgorithm.SHA256,
			SignatureAlgorithm.RSA);
	/**
	 * INTRINSIC_WITH_ED25519.
	 * 
	 * @since 2.4
	 */
	public static final SignatureAndHashAlgorithm INTRINSIC_WITH_ED25519 = new SignatureAndHashAlgorithm(
			HashAlgorithm.INTRINSIC, SignatureAlgorithm.ED25519);
	/**
	 * INTRINSIC_WITH_ED448.
	 * 
	 * @since 2.4
	 */
	public static final SignatureAndHashAlgorithm INTRINSIC_WITH_ED448 = new SignatureAndHashAlgorithm(
			HashAlgorithm.INTRINSIC, SignatureAlgorithm.ED448);
	/**
	 * Default list of supported signature and hash algorithms. Contains only
	 * SHA256_with_Ecdsa.
	 * 
	 * @since 2.3
	 */
	public static final List<SignatureAndHashAlgorithm> DEFAULT = Collections
			.unmodifiableList(Arrays.asList(SHA256_WITH_ECDSA, SHA256_WITH_RSA));

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
		return ThreadLocalSignature.SIGNATURES.get(algorithm);
	}

	/**
	 * Get signature and hash algorithm from JCA name.
	 * 
	 * @param jcaName name of signature and hash algorithm. e.g.
	 *            "SHA256withECDSA". If "with" is not contained in the provided
	 *            name, {@link HashAlgorithm#INTRINSIC} is assumed.
	 * @return signature and hash algorithm, or {@code null}, if signature or
	 *         hash is unknown.
	 * 
	 * @since 3.0 (added {@link HashAlgorithm#INTRINSIC} as default)
	 */
	public static SignatureAndHashAlgorithm valueOf(String jcaName) {
		int index = jcaName.indexOf("with");
		if (index < 0) {
			index = jcaName.indexOf("WITH");
		}
		HashAlgorithm hashAlgorithm;
		SignatureAlgorithm signatureAlgorithm;
		if (0 < index) {
			String hash = jcaName.substring(0, index);
			String signature = jcaName.substring(index + 4, jcaName.length());
			hashAlgorithm = HashAlgorithm.valueOf(hash);
			signatureAlgorithm = SignatureAlgorithm.valueOf(signature);
		} else {
			hashAlgorithm = HashAlgorithm.INTRINSIC;
			signatureAlgorithm = SignatureAlgorithm.valueOf(jcaName);
		}
		if (hashAlgorithm != null && signatureAlgorithm != null) {
			return new SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm);
		}
		return null;
	}

	/**
	 * Get list of signature and hash algorithms used by the certificate chain.
	 * 
	 * @param certificateChain certificate chain. May be {@code null}.
	 * @return list list of signature and hash algorithms
	 * 
	 * @since 3.0
	 */
	public static List<SignatureAndHashAlgorithm> getSignatureAlgorithms(List<X509Certificate> certificateChain) {
		List<SignatureAndHashAlgorithm> result = new ArrayList<>();
		if (certificateChain != null && !certificateChain.isEmpty()) {
			for (X509Certificate certificate : certificateChain) {
				String sigAlgName = certificate.getSigAlgName();
				SignatureAndHashAlgorithm signature = valueOf(sigAlgName);
				if (signature == null) {
					throw new IllegalArgumentException(sigAlgName + " not supported!");
				}
				ListUtils.addIfAbsent(result, signature);
			}
		}
		return result;
	}

	/**
	 * Ensure, that the list contains a signature and hash algorithms usable by
	 * the public key.
	 * 
	 * Adds a signature and hash algorithms usable by the public key to the
	 * list, if missing.
	 * 
	 * @param algorithms list of default algorithms. If not already supported, a
	 *            signature and hash algorithms usable by the public key is
	 *            added to this list.
	 * @param publicKey publicKey. May be {@code null}.
	 * @throws NullPointerException if one of the arguments is {@code null}
	 * @throws IllegalArgumentException if no signature is supported for this
	 *             public key
	 * @since 3.0
	 */
	public static void ensureSignatureAlgorithm(List<SignatureAndHashAlgorithm> algorithms, PublicKey publicKey) {
		if (publicKey == null) {
			throw new NullPointerException("Public key must not be null!");
		}
		SignatureAndHashAlgorithm signAndHash = getSupportedSignatureAlgorithm(DEFAULT, publicKey);
		if (signAndHash != null) {
			ListUtils.addIfAbsent(algorithms, signAndHash);
			return;
		}
		if (algorithms == null) {
			throw new NullPointerException("The defaults list must not be null!");
		}
		if (getSupportedSignatureAlgorithm(algorithms, publicKey) != null) {
			return;
		}
		boolean keyAlgorithmSupported = false;
		for (SignatureAlgorithm signatureAlgorithm : SignatureAlgorithm.values()) {
			if (signatureAlgorithm.isSupported(publicKey.getAlgorithm())) {
				keyAlgorithmSupported = true;
				if (signatureAlgorithm.isIntrinsic) {
					signAndHash = new SignatureAndHashAlgorithm(HashAlgorithm.INTRINSIC, signatureAlgorithm);
					if (signAndHash.isSupported(publicKey)) {
						ListUtils.addIfAbsent(algorithms, signAndHash);
						return;
					}
				} else {
					for (HashAlgorithm hashAlgorithm : HashAlgorithm.values()) {
						if (hashAlgorithm != HashAlgorithm.INTRINSIC && hashAlgorithm.isRecommended()) {
							signAndHash = new SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm);
							if (signAndHash.isSupported(publicKey)) {
								ListUtils.addIfAbsent(algorithms, signAndHash);
								return;
							}
						}
					}
				}
			}
		}
		if (keyAlgorithmSupported) {
			throw new IllegalArgumentException(publicKey.getAlgorithm() + " public key is not supported!");
		} else {
			throw new IllegalArgumentException(publicKey.getAlgorithm() + " is not supported!");
		}
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
				ListUtils.addIfAbsent(result, algo);
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
	 * @throws NullPointerException if any parameter is {@code null}.
	 * @since 2.3
	 */
	public static SignatureAndHashAlgorithm getSupportedSignatureAlgorithm(
			List<SignatureAndHashAlgorithm> supportedSignatureAlgorithms, PublicKey key) {
		if (key == null) {
			throw new NullPointerException("Public key must not be null!");
		}
		for (SignatureAndHashAlgorithm supportedAlgorithm : supportedSignatureAlgorithms) {
			if (supportedAlgorithm.isSupported(key)) {
				return supportedAlgorithm;
			}
		}
		return null;
	}

	/**
	 * Get ECDSA compatible signature and hash algorithms.
	 * 
	 * @param signatureAndHashAlgorithms list of signature and hash algorithms
	 * @return ECDSA compatible signature and hash algorithms
	 * @see SignatureAlgorithm#isEcdsaCompatible()
	 * @since 2.4
	 */
	public static List<SignatureAndHashAlgorithm> getEcdsaCompatibleSignatureAlgorithms(
			List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms) {
		List<SignatureAndHashAlgorithm> result = new ArrayList<>();
		for (SignatureAndHashAlgorithm algo : signatureAndHashAlgorithms) {
			if (algo.getSignature().isEcdsaCompatible()) {
				result.add(algo);
			}
		}
		return result;
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
	 * @param supportedSignatureAlgorithms list of supported signatures and hash
	 *            algorithms
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
		this.supported = jcaName != null && getThreadLocalSignature(jcaName).isSupported();
	}

	/**
	 * Creates an instance for corresponding algorithm codes.
	 * 
	 * @param hashAlgorithmCode the hash algorithm's code.
	 * @param signatureAlgorithmCode the signature algorithm's code.
	 */
	public SignatureAndHashAlgorithm(int hashAlgorithmCode, int signatureAlgorithmCode) {
		this.hashAlgorithmCode = hashAlgorithmCode;
		this.signatureAlgorithmCode = signatureAlgorithmCode;
		this.signature = SignatureAlgorithm.getAlgorithmByCode(signatureAlgorithmCode);
		this.hash = HashAlgorithm.getAlgorithmByCode(hashAlgorithmCode);
		this.jcaName = buildJcaName();
		this.supported = jcaName != null && getThreadLocalSignature(jcaName).isSupported();
	}

	private String buildJcaName() {
		if (hash != null && signature != null) {
			StringBuilder name = new StringBuilder();
			if (hash != HashAlgorithm.INTRINSIC) {
				name.append(hash);
				name.append("with");
			}
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
	 * Gets the <a href=
	 * "https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Signature"
	 * target="_blank"> JCA standard name</a> corresponding to this combination
	 * of hash and signature algorithm.
	 * <p>
	 * The name returned by this method can be used to instantiate a
	 * {@code java.security.Signature} object like this:
	 * 
	 * <pre>
	 * 
	 * Signature signature = Signature.newInstance(signatureAndHash.jcaName());
	 * </pre>
	 * 
	 * @return The name, or {@code null}, if name is not available/not known by
	 *         this implementation.
	 * 
	 * @since 2.3
	 */
	public String getJcaName() {
		return jcaName;
	}

	/**
	 * Check, if signature and hash algorithm is recommended.
	 * 
	 * @return {@code true}, if recommended, {@code false}, otherwise.
	 * @since 3.0
	 */
	public boolean isRecommended() {
		return signature != null && hash != null && hash.isRecommended();
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
	 * Check, if signature and hash algorithm is supported to be used with the
	 * public key algorithm by the JRE.
	 * 
	 * @param keyAlgorithm key algorithm.
	 * @return {@code true}, if supported, {@code false}, otherwise.
	 * @since 3.0
	 */
	public boolean isSupported(String keyAlgorithm) {
		if (supported) {
			return signature.isSupported(keyAlgorithm);
		}
		return false;
	}

	/**
	 * Check, if signature and hash algorithm is supported to be used with the
	 * public key by the JRE.
	 * 
	 * @param publicKey public key
	 * @return {@code true}, if supported, {@code false}, otherwise.
	 * @since 3.0
	 */
	public boolean isSupported(PublicKey publicKey) {
		if (supported && signature.isSupported(publicKey.getAlgorithm())) {
			Signature signature = getThreadLocalSignature().current();
			if (signature != null) {
				try {
					signature.initVerify(publicKey);
					return true;
				} catch (InvalidKeyException e) {
				}
			}
		}
		return false;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Returns literal name, if signature or hash algorithm is unknown.
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
		return this.hashAlgorithmCode * 256 + this.signatureAlgorithmCode;
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
