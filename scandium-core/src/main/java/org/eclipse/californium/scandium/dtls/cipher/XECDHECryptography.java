/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 *                    derived from ECDHECryptography
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.eclipse.californium.elements.util.JceNames;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.JceProviderUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;

/**
 * A helper class to execute the XDH and ECDHE key agreement and key generation.
 * <p>
 * Supports X25519 and X448 with java 11. Experimentally Bouncy Castle 1.69
 * could be used as alternative JCE.
 * <p>
 * <b>Note:</b> No support for Bouncy Castle issues with or without relation to
 * Californium could be provided! You may report issues as common, but it's not
 * ensured, that they could be considered.
 * <p>
 * A ECDHE key exchange starts with negotiating a curve. The possible curves are
 * listed at <a href=
 * "http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8" target="_blank">
 * IANA Transport Layer Security (TLS) Parameters - TLS Supported Groups</a>.
 * The {@link SupportedGroup} reflects that and offer the curve's
 * {@link SupportedGroup#name()} (description in the IANA table) or
 * {@link SupportedGroup#getId()} (value in the IANA table). You may refer
 * directly a member, e.g. {@link SupportedGroup#X25519}, or get it by id
 * {@link SupportedGroup#fromId(int)} or by the curve-name
 * {@link SupportedGroup#valueOf(String)}.
 * <p>
 * Once you have a curve negotiated, you create a instance of
 * {@link XECDHECryptography#XECDHECryptography(SupportedGroup)} providing this
 * curve as parameter. This will also create the ephemeral key-pair for the key
 * exchange. After each peer creates such a instance (and so different
 * key-pairs), the "public key" is sent to the other peer. Though the curve is
 * transfered by it's {@link SupportedGroup#getId()} (named curve), the public
 * key itself is sent just by the {@link #getEncodedPoint()} and not the ASN.1
 * encoding ({@link PublicKey#getEncoded()}). Each peer converts the received
 * encoded point of the other peer into a {@link PublicKey} and applies that to
 * {@link KeyAgreement#doPhase(java.security.Key, boolean)}. Outside of this
 * class only the encoded point and the {@link SupportedGroup} is used to do the
 * key exchange. Access to the {@link PrivateKey} nor {@link PublicKey} is
 * required outside.
 * <pre>
 * <code>
 * SupportedGroup group = SupportedGroup.X25519;
 * 
 * // peer 1
 * XECDHECryptography ecdhe1 = new XECDHECryptography(group);
 * byte[] point1 = ecdhe1.getEncodedPoint();
 * 
 * // send group + encoded point to other peer
 * 
 * // peer 2, use received group
 * XECDHECryptography ecdhe2 = new XECDHECryptography(group);
 * byte[] point2 = ecdhe2.getEncodedPoint();
 * SecretKey secret2 = ecdhe2.generateSecret(point1);
 * 
 * // send own encoded point back to first peer
 * 
 * // peer 1
 * SecretKey secret1 = ecdhe1.generateSecret(point2);
 * </code>
 * </pre>
 * results in same secrets {@code secret1} and {@code secret2}.
 * 
 * @see <a href="https://tools.ietf.org/html/rfc7748" target="_blank">RFC
 *      7748</a>
 * @since 2.3
 */
public final class XECDHECryptography implements Destroyable {

	// Logging ////////////////////////////////////////////////////////
	/**
	 * The logger.
	 * 
	 * @deprecated scope will change to private.
	 */
	@Deprecated
	protected static final Logger LOGGER = LoggerFactory.getLogger(XECDHECryptography.class);

	// Static members /////////////////////////////////////////////////

	static {
		JceProviderUtil.init();
	}

	/**
	 * The algorithm for the elliptic curve key pair generation.
	 * 
	 * See also <a href=
	 * "http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator"
	 * target="_blank" >KeyPairGenerator Algorithms</a>.
	 */
	private static final String EC_KEYPAIR_GENERATOR_ALGORITHM = "EC";

	private static final ThreadLocalKeyPairGenerator EC_KEYPAIR_GENERATOR = new ThreadLocalKeyPairGenerator(
			EC_KEYPAIR_GENERATOR_ALGORITHM);

	/**
	 * X25519 and X448.
	 */
	private static final String XDH_KEYPAIR_GENERATOR_ALGORITHM = "XDH";

	private static final ThreadLocalKeyPairGenerator XDH_KEYPAIR_GENERATOR = new ThreadLocalKeyPairGenerator(
			XDH_KEYPAIR_GENERATOR_ALGORITHM);

	private static final String EC_KEY_FACTORY_ALGORITHM = "EC";

	private static final ThreadLocalKeyFactory EC_KEY_FACTORY = new ThreadLocalKeyFactory(EC_KEY_FACTORY_ALGORITHM);

	private static final String XDH_KEY_FACTORY_ALGORITHM = "XDH";

	/**
	 * XDH key factory.
	 * 
	 * May be used for {@link XDHPublicKeyApi}.
	 */
	public static final ThreadLocalKeyFactory XDH_KEY_FACTORY = new ThreadLocalKeyFactory(XDH_KEY_FACTORY_ALGORITHM);

	/**
	 * Elliptic Curve Diffie-Hellman algorithm name. See also <a href=
	 * "http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyAgreement"
	 * >KeyAgreement Algorithms</a>.
	 */
	private static final String ECDH_KEY_AGREEMENT_ALGORITHM = "ECDH";

	private static final ThreadLocalKeyAgreement ECDH_KEY_AGREEMENT = new ThreadLocalKeyAgreement(
			ECDH_KEY_AGREEMENT_ALGORITHM);

	/**
	 * X25519 and X448.
	 */
	private static final String XDH_KEY_AGREEMENT_ALGORITHM = "XDH";

	private static final ThreadLocalKeyAgreement XDH_KEY_AGREEMENT = new ThreadLocalKeyAgreement(
			XDH_KEY_AGREEMENT_ALGORITHM);

	/**
	 * Use java 11 XDH via reflection.
	 */
	private static volatile XDHPublicKeyApi xDHPublicKeyApi = XDHPublicKeyReflection.init();

	/**
	 * Map of {@link SupportedGroup#getId()} to {@link SupportedGroup}.
	 * 
	 * @see SupportedGroup#fromId(int)
	 */
	private static final Map<Integer, SupportedGroup> EC_CURVE_MAP_BY_ID = new HashMap<>();
	/**
	 * Map of {@link EllipticCurve} to {@link SupportedGroup}.
	 * 
	 * @see ECParameterSpec#getCurve()
	 */
	private static final Map<EllipticCurve, SupportedGroup> EC_CURVE_MAP_BY_CURVE = new HashMap<>();

	// Members ////////////////////////////////////////////////////////

	/**
	 * Supported group (curve) of this key exchange.
	 */
	private final SupportedGroup supportedGroup;

	/** The ephemeral private key. */
	private PrivateKey privateKey;

	/** The ephemeral public key. */
	private final PublicKey publicKey;

	private final byte[] encodedPoint;

	// Constructors ///////////////////////////////////////////////////

	/**
	 * Creates an ephemeral ECDH key pair for a given supported group.
	 * 
	 * @param supportedGroup a curve as defined in the <a href=
	 *            "http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8">
	 *            IANA Supported Groups Registry</a>
	 * @throws GeneralSecurityException if the key pair cannot be created from
	 *             the given supported group, e.g. because the JRE's crypto
	 *             provider doesn't support the group
	 */
	public XECDHECryptography(SupportedGroup supportedGroup) throws GeneralSecurityException {
		KeyPair keyPair;
		if (supportedGroup.getAlgorithmName().equals(EC_KEYPAIR_GENERATOR_ALGORITHM)) {
			KeyPairGenerator keyPairGenerator = EC_KEYPAIR_GENERATOR.currentWithCause();
			ECGenParameterSpec params = new ECGenParameterSpec(supportedGroup.name());
			keyPairGenerator.initialize(params, RandomManager.currentSecureRandom());
			keyPair = keyPairGenerator.generateKeyPair();
		} else if (supportedGroup.getAlgorithmName().equals(XDH_KEYPAIR_GENERATOR_ALGORITHM)) {
			KeyPairGenerator keyPairGenerator = XDH_KEYPAIR_GENERATOR.currentWithCause();
			ECGenParameterSpec params = new ECGenParameterSpec(supportedGroup.name());
			keyPairGenerator.initialize(params, RandomManager.currentSecureRandom());
			keyPair = keyPairGenerator.generateKeyPair();
		} else {
			throw new GeneralSecurityException(supportedGroup.name() + " not supported by KeyPairGenerator!");
		}
		this.privateKey = keyPair.getPrivate();
		this.publicKey = keyPair.getPublic();
		this.supportedGroup = supportedGroup;
		this.encodedPoint = supportedGroup.encodedPoint(publicKey);
		check("OUT: ", publicKey, encodedPoint);
	}

	/**
	 * Get public key.
	 * 
	 * Unit-tests only!
	 * 
	 * @return public key
	 */
	PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Get the supported group (curve) of this key exchange.
	 * 
	 * @return supported group
	 */
	public SupportedGroup getSupportedGroup() {
		return supportedGroup;
	}

	/**
	 * Get public key as encoded point.
	 * 
	 * The key exchange contains the used curve by its
	 * {@link SupportedGroup#getId()}, therefore the ASN.1
	 * {@link PublicKey#getEncoded()} is not required.
	 * 
	 * @return encoded point to be sent to the other peer
	 */
	public byte[] getEncodedPoint() {
		return encodedPoint;
	}

	/**
	 * Generate secret of key exchange.
	 * 
	 * @param encodedPoint the other peer's public key as encoded point
	 * @return the premaster secret
	 * @throws NullPointerException if encodedPoint is {@code null}.
	 * @throws GeneralSecurityException if a crypto error occurred.
	 */
	public SecretKey generateSecret(byte[] encodedPoint) throws GeneralSecurityException {
		if (privateKey == null) {
			throw new IllegalStateException("private key must not be destroyed");
		}
		PublicKey peersPublicKey = supportedGroup.decodedPoint(encodedPoint);
		KeyAgreement keyAgreement = null;
		if (supportedGroup.getAlgorithmName().equals(EC_KEYPAIR_GENERATOR_ALGORITHM)) {
			keyAgreement = ECDH_KEY_AGREEMENT.currentWithCause();
		} else if (xDHPublicKeyApi != null
				&& supportedGroup.getAlgorithmName().equals(XDH_KEYPAIR_GENERATOR_ALGORITHM)) {
			keyAgreement = XDH_KEY_AGREEMENT.currentWithCause();
		} else {
			throw new GeneralSecurityException(supportedGroup.name() + " not supported by JCE!");
		}
		check("IN: ", peersPublicKey, encodedPoint);

		try {
			keyAgreement.init(privateKey);
			keyAgreement.doPhase(peersPublicKey, true);
			byte[] secret = keyAgreement.generateSecret();
			SecretKey secretKey = SecretUtil.create(secret, "TlsPremasterSecret");
			Bytes.clear(secret);
			return secretKey;
		} catch(InvalidKeyException ex) {
			LOGGER.warn("Fail: {} {}", supportedGroup.name(), ex.getMessage());
			throw ex;
		}
	}

	@Override
	public void destroy() {
		privateKey = null;
	}

	@Override
	public boolean isDestroyed() {
		return privateKey == null;
	}

	private void check(String tag, PublicKey publicKey, byte[] point) throws GeneralSecurityException {
		if (LOGGER.isDebugEnabled()) {
			byte[] asn1 = publicKey.getEncoded();
			String s1 = StringUtil.byteArray2Hex(asn1);
			String s2 = StringUtil.byteArray2Hex(point);
			if (s2.length() < s1.length()) {
				s2 = String.format("%" + s1.length() + "s", s2);
			}
			LOGGER.debug("{}ASN1 encoded '{}'", tag, s1);
			LOGGER.debug("{}DHE  encoded '{}'", tag, s2);
			for (int index = 0; index < point.length; ++index) {
				if (point[point.length - index - 1] != asn1[asn1.length - index - 1]) {
					throw new GeneralSecurityException(
							"DHE: failed to encoded point! " + supportedGroup.name() + ", position: " + index);
				}
			}
		}
	}

	/**
	 * The <em>Supported Groups</em> as defined in the official <a href=
	 * "https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8"
	 * target="_blank"> IANA Transport Layer Security (TLS) Parameters</a>.
	 * 
	 * Also see
	 * <a href="https://tools.ietf.org/html/rfc4492#section-5.1.1" target=
	 * "_blank">RFC 4492, Section 5.1.1 Supported Elliptic Curves Extension</a>.
	 */
	public enum SupportedGroup {

		sect163k1(1, false),
		sect163r1(2, false),
		sect163r2(3, false),
		sect193r1(4, false),
		sect193r2(5, false),
		sect233k1(6, false),
		sect233r1(7, false),
		sect239k1(8, false),
		sect283k1(9, false),
		sect283r1(10, false),
		sect409k1(11, false),
		sect409r1(12, false),
		sect571k1(13, false),
		sect571r1(14, false),
		secp160k1(15, false),
		secp160r1(16, false),
		secp160r2(17, false),
		secp192k1(18, false),
		secp192r1(19, false),
		secp224k1(20, false),
		secp224r1(21, false),
		secp256k1(22, false),
		secp256r1(23, true),
		secp384r1(24, true),
		secp521r1(25, false),
		brainpoolP256r1(26, false),
		brainpoolP384r1(27, false),
		brainpoolP512r1(28, false),
		X25519(29, 32, XDH_KEYPAIR_GENERATOR_ALGORITHM, true),
		X448(30, 56, XDH_KEYPAIR_GENERATOR_ALGORITHM, true),
		ffdhe2048(256, false),
		ffdhe3072(257, false),
		ffdhe4096(258, false),
		ffdhe6144(259, false),
		ffdhe8192(260, false),
		arbitrary_explicit_prime_curves(65281, false),
		arbitrary_explicit_char2_curves(65282, false);

		private final int id;
		private final String algorithmName;
		private final int keySizeInBytes;
		private final int encodedPointSizeInBytes;
		private final boolean usable;
		private final boolean recommended;
		private final byte[] asn1header;
		private final ThreadLocalKeyFactory keyFactory;

		/**
		 * Create supported group.
		 * 
		 * @param code code according IANA
		 * @param recommended {@code true}, for IANA recommended curves,
		 *            {@code false}, otherwise.
		 */
		private SupportedGroup(int code, boolean recommended) {
			this.id = code;
			this.algorithmName = EC_KEYPAIR_GENERATOR_ALGORITHM;
			this.recommended = recommended;
			EllipticCurve curve = null;
			int keySize = 0;
			int publicKeySize = 0;
			byte[] header = null;
			try {
				KeyPairGenerator keyPairGenerator = EC_KEYPAIR_GENERATOR.currentWithCause();
				ECGenParameterSpec genParams = new ECGenParameterSpec(name());
				keyPairGenerator.initialize(genParams, RandomManager.currentSecureRandom());
				ECPublicKey publicKey = (ECPublicKey) keyPairGenerator.generateKeyPair().getPublic();
				curve = publicKey.getParams().getCurve();
				keySize = (curve.getField().getFieldSize() + Byte.SIZE - 1) / Byte.SIZE;
				publicKeySize = keySize * 2 + 1;
				EC_CURVE_MAP_BY_CURVE.put(curve, this);
				header = publicKey.getEncoded();
				header = Arrays.copyOf(header, header.length - publicKeySize);
			} catch (Throwable e) {
				LOGGER.trace("Group [{}] is not supported by JCE! {}", name(), e.getMessage());
				curve = null;
			}
			this.keySizeInBytes = keySize;
			this.encodedPointSizeInBytes = publicKeySize;
			this.asn1header = header;
			this.usable = curve != null;
			this.keyFactory = EC_KEY_FACTORY;
			EC_CURVE_MAP_BY_ID.put(code, this);
		}

		/**
		 * Create supported group.
		 * 
		 * @param code code according IANA
		 * @param keySizeInBytes public key size in bytes
		 * @param algorithmName JRE name of key pair generator algorithm.
		 *            Currently only "XDH" is implemented!
		 * @param recommended {@code true}, for IANA recommended curves,
		 *            {@code false}, otherwise.
		 */
		private SupportedGroup(int code, int keySizeInBytes, String algorithmName, boolean recommended) {
			this.id = code;
			this.algorithmName = algorithmName;
			this.keySizeInBytes = keySizeInBytes;
			this.encodedPointSizeInBytes = keySizeInBytes;
			this.recommended = recommended;
			byte[] header = null;
			boolean usable = false;
			try {
				KeyPairGenerator keyPairGenerator = XDH_KEYPAIR_GENERATOR.currentWithCause();
				ECGenParameterSpec params = new ECGenParameterSpec(name());
				keyPairGenerator.initialize(params, RandomManager.currentSecureRandom());
				PublicKey publicKey = keyPairGenerator.generateKeyPair().getPublic();
				header = publicKey.getEncoded();
				header = Arrays.copyOf(header, header.length - keySizeInBytes);
				usable = true;
			} catch (Throwable e) {
				LOGGER.trace("Group [{}] is not supported by JCE! {}", name(), e.getMessage());
			}
			this.usable = usable;
			this.asn1header = header;
			this.keyFactory = XDH_KEY_FACTORY;
			EC_CURVE_MAP_BY_ID.put(code, this);
		}

		/**
		 * Gets this group's official id as registered with IANA.
		 * 
		 * @return the id
		 */
		public int getId() {
			return id;
		}

		/**
		 * Get algorithm name.
		 * 
		 * @return algorithm name
		 */
		public String getAlgorithmName() {
			return algorithmName;
		}

		/**
		 * Get public key as encoded point.
		 * 
		 * @param publicKey public key
		 * @return encoded point, or {@code null}, if not supported
		 * @throws NullPointerException if publicKey is {@code null}.
		 * @throws GeneralSecurityException if a encoding is not supported
		 * @since 3.0
		 */
		public byte[] encodedPoint(PublicKey publicKey) throws GeneralSecurityException {
			if (publicKey == null) {
				throw new NullPointerException("public key must not be null!");
			}
			byte[] result = publicKey.getEncoded();
			if (result == null) {
				throw new GeneralSecurityException(name() + " not supported!");
			}
			return Arrays.copyOfRange(result, asn1header.length, result.length);
		}

		/**
		 * Get public key from encoded point
		 * 
		 * @param encodedPoint encoded point
		 * @return public key
		 * @throws NullPointerException if encoded point is {@code null}.
		 * @throws IllegalArgumentException if encoded point has mismatching
		 *             length.
		 * @throws GeneralSecurityException if an error occurred
		 * @since 3.0
		 */
		public PublicKey decodedPoint(byte[] encodedPoint) throws GeneralSecurityException {
			if (encodedPoint == null) {
				throw new NullPointerException("encoded point must not be null!");
			}
			if (encodedPointSizeInBytes != encodedPoint.length) {
				throw new IllegalArgumentException("encoded point must have " + encodedPointSizeInBytes + " bytes, not "
						+ encodedPoint.length + "!");
			}
			byte[] encodedKey = Bytes.concatenate(asn1header, encodedPoint);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
			KeyFactory factory = keyFactory.currentWithCause();
			return factory.generatePublic(keySpec);
		}

		/**
		 * Gets the group for a given id.
		 * 
		 * @param id the id
		 * @return the group or {@code null} if no group with the given id is
		 *         (currently) registered
		 */
		public static SupportedGroup fromId(int id) {
			return EC_CURVE_MAP_BY_ID.get(id);
		}

		/**
		 * Gets the group for a given public key.
		 * 
		 * @param publicKey the public key
		 * @return the group or {@code null}, if no group with the given id is
		 *         (currently) registered
		 */
		public static SupportedGroup fromPublicKey(PublicKey publicKey) {
			if (publicKey != null) {
				if (publicKey instanceof ECPublicKey) {
					ECParameterSpec params = ((ECPublicKey) publicKey).getParams();
					return EC_CURVE_MAP_BY_CURVE.get(params.getCurve());
				} else if (xDHPublicKeyApi != null && xDHPublicKeyApi.isSupporting(publicKey)) {
					try {
						String name = xDHPublicKeyApi.getCurveName(publicKey);
						return SupportedGroup.valueOf(name);
					} catch (GeneralSecurityException ex) {

					}
				} else {
					// EdDsa work around ...
					String algorithm = publicKey.getAlgorithm();
					String oid = JceProviderUtil.getEdDsaStandardAlgorithmName(algorithm, null);
					if (JceNames.OID_ED25519.equals(oid) || JceNames.EDDSA.equalsIgnoreCase(oid)) {
						return X25519;
					} else if (JceNames.OID_ED448.equals(oid)) {
						return X448;
					} else {
						LOGGER.warn("No supported curve {}/{}", publicKey.getAlgorithm(), oid);
					}
				}
			}
			return null;
		}

		/**
		 * Checks, if provided public key is a EC or XEC key.
		 * 
		 * @param publicKey the public key
		 * @return {@code true}, if it's a EC of XEC key, {@code false},
		 *         otherwise.
		 */
		public static boolean isEcPublicKey(PublicKey publicKey) {
			if (publicKey instanceof ECPublicKey) {
				return true;
			} else {
				return xDHPublicKeyApi != null && xDHPublicKeyApi.isSupporting(publicKey);
			}
		}

		/**
		 * Check, if all ECDSA certificates uses a supported group (curve) from
		 * the provided list.
		 * 
		 * @param list list of supported groups
		 * @param certificateChain certificate chain
		 * @return {@code true}, if all ECDSA certificates uses supported group
		 *         (curve) from the provided list, {@code false}, otherwise.
		 */
		public static boolean isSupported(List<SupportedGroup> list, List<X509Certificate> certificateChain) {
			for (X509Certificate certificate : certificateChain) {
				PublicKey publicKey = certificate.getPublicKey();
				if (isEcPublicKey(publicKey)) {
					SupportedGroup group = fromPublicKey(publicKey);
					if (group == null || !group.isUsable() || !list.contains(group)) {
						return false;
					}
				}
			}
			return true;
		}

		/**
		 * Returns size of the key in bytes.
		 * 
		 * @return key size in bytes
		 */
		public int getKeySizeInBytes() {
			return keySizeInBytes;
		}

		/**
		 * Returns size of the encoded point in bytes.
		 * 
		 * @return encoded point size in bytes
		 * @since 3.0
		 */
		public int getEncodedPointSizeInBytes() {
			return encodedPointSizeInBytes;
		}

		/**
		 * Checks whether this group can be used on this platform.
		 * 
		 * @return {@code true}, if the group's domain params are known and the
		 *         JRE's crypto provider supports it
		 */
		public boolean isUsable() {
			return usable;
		}

		public boolean isRecommended() {
			return recommended;
		}

		/**
		 * Gets all {@code SupportedGroup}s that can be used on this platform.
		 * 
		 * @return the supported groups as unmodifiable list.
		 * @see #isUsable()
		 */
		public static List<SupportedGroup> getUsableGroups() {
			return Initialize.USABLE_GROUPS;
		}

		/**
		 * Gets all {@code SupportedGroup}s that can be used on this platform as array.
		 * 
		 * @return the supported groups as array.
		 * @see #isUsable()
		 * @since 3.0
		 */
		public static SupportedGroup[] getUsableGroupsArray() {
			return Initialize.USABLE_GROUPS.toArray(new SupportedGroup[Initialize.USABLE_GROUPS.size()]);
		}

		/**
		 * Gets the preferred <em>supported groups</em>.
		 * 
		 * @return the groups in order of preference as unmodifiable list.
		 */
		public static List<SupportedGroup> getPreferredGroups() {
			return Initialize.PREFERRED_GROUPS;
		}
	}

	/**
	 * Prepare usable and preferred list of ec groups.
	 */
	private static class Initialize {

		/**
		 * Default preferred supported groups. Keep
		 * {@link SupportedGroup#secp256r1} at the first position for backwards
		 * compatibility, when the server doesn't receive the "supported
		 * elliptic curves extension".
		 */
		private static final SupportedGroup PREFERRED[] = { SupportedGroup.secp256r1, SupportedGroup.X25519,
				SupportedGroup.X448, SupportedGroup.secp384r1 };
		private static final List<SupportedGroup> USABLE_GROUPS;
		private static final List<SupportedGroup> PREFERRED_GROUPS;

		static {
			List<SupportedGroup> usableGroups = new ArrayList<>();
			List<SupportedGroup> preferredGroups = new ArrayList<>();
			for (SupportedGroup group : SupportedGroup.values()) {
				if (group.isUsable()) {
					usableGroups.add(group);
				}
			}
			for (SupportedGroup group : PREFERRED) {
				if (group.isUsable()) {
					preferredGroups.add(group);
				}
			}
			if (preferredGroups.isEmpty() && !usableGroups.isEmpty()) {
				preferredGroups.add(usableGroups.get(0));
			}
			USABLE_GROUPS = Collections.unmodifiableList(usableGroups);
			PREFERRED_GROUPS = Collections.unmodifiableList(preferredGroups);
		}
	}

	/**
	 * Set {@link XDHPublicKeyApi} implementation.
	 * <p>
	 * As default, java 11 is supported by a implementation using reflection (in
	 * order to prevent a hard dependency to java 11). Bouncy Castle 1.69 is
	 * experimentally also supported using a implementation based on reflection
	 * (as well, to prevent a hard dependency). Ensure, Bouncy Castle is set as
	 * provider before access.
	 * <pre>
	 * <code>
	 * Security.removeProvider("BC");
	 * BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
	 * Security.insertProviderAt(bouncyCastleProvider, 1);
	 * </code>
	 * </pre>
	 * <b>Note:</b> No support for Bouncy Castle issues with or without relation
	 * to Californium could be provided! You may report issues as common, but
	 * it's not ensured, that they could be considered.
	 * <p>
	 * If other XDH providers are used, or the reflection ones should be
	 * replaced, provide that custom implementation as parameter.
	 * <p>
	 * e.g. Bouncy Castle (simple example, no support):
	 * <pre>
	 * <code>
	 * Security.removeProvider("BC");
	 * BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
	 * Security.insertProviderAt(bouncyCastleProvider, 1);
	 * XECDHECryptography.XDHPublicKeyApi api = new XECDHECryptography.XDHPublicKeyApi() {
	 * 
	 * 	&#64;Override
	 * 	public boolean isSupporting(PublicKey publicKey) {
	 * 		return publicKey instanceof BCXDHPublicKey;
	 * 	}
	 * 
	 * 	&#64;Override
	 * 	public String getCurveName(PublicKey publicKey) throws GeneralSecurityException {
	 * 		return ((BCXDHPublicKey) publicKey).getAlgorithm();
	 * 	}
	 * 
	 * };
	 * XECDHECryptography.setXDHPublicKeyApi(api);
	 * </code>
	 * </pre>
	 * 
	 * @param api {@link XDHPublicKeyApi} implementation
	 */
	public static void setXDHPublicKeyApi(XDHPublicKeyApi api) {
		xDHPublicKeyApi = api;
	}

	/**
	 * API for XDH (X25519/X448) public keys.
	 * 
	 * @since 3.0
	 */
	public interface XDHPublicKeyApi {

		/**
		 * Check, if provided public key is a XDH (X25519/X448) public key
		 * supported by this implementation.
		 * 
		 * @param publicKey public key to check.
		 * @return {@code true}, if public key is a XDH (X25519/X448) public key
		 *         and supported by this implementation.
		 */
		boolean isSupporting(PublicKey publicKey);

		/**
		 * Gets curve name of the public key.
		 * 
		 * @param publicKey public key.
		 * @return curve name
		 * @throws GeneralSecurityException if not supported by this
		 *             implementation
		 * @see #isSupporting(PublicKey)
		 */
		String getCurveName(PublicKey publicKey) throws GeneralSecurityException;

	}

	/**
	 * Implementation of {@link XDHPublicKeyApi} based on reflection running on
	 * java 11 XDH, or, experimentally, Bouncy Castle 1.69.
	 * 
	 * @since 3.0
	 */
	private static class XDHPublicKeyReflection implements XDHPublicKeyApi {

		private final Class<?> XECPublicKeyClass;
		private final Method XECPublicKeyGetParams;
		private final Method NamedParameterSpecGetName;

		private XDHPublicKeyReflection(Class<?> XECPublicKeyClass) {
			if (XECPublicKeyClass == null) {
				throw new NullPointerException("XECPublicKeyClass must not be null!");
			}
			this.XECPublicKeyClass = XECPublicKeyClass;
			this.XECPublicKeyGetParams = null;
			this.NamedParameterSpecGetName = null;
		}

		private XDHPublicKeyReflection(Class<?> XECPublicKeyClass, Method XECPublicKeyGetParams,
				Method NamedParameterSpecGetName) {
			if (XECPublicKeyClass == null) {
				throw new NullPointerException("XECPublicKeyClass must not be null!");
			}
			if (XECPublicKeyGetParams == null) {
				throw new NullPointerException("XECPublicKeyGetParams must not be null!");
			}
			if (NamedParameterSpecGetName == null) {
				throw new NullPointerException("NamedParameterSpecGetName must not be null!");
			}
			this.XECPublicKeyClass = XECPublicKeyClass;
			this.XECPublicKeyGetParams = XECPublicKeyGetParams;
			this.NamedParameterSpecGetName = NamedParameterSpecGetName;
		}

		@Override
		public boolean isSupporting(PublicKey publicKey) {
			return XECPublicKeyClass.isInstance(publicKey);
		}

		@Override
		public String getCurveName(PublicKey publicKey) throws GeneralSecurityException {
			if (XECPublicKeyClass.isInstance(publicKey)) {
				if (XECPublicKeyGetParams != null && NamedParameterSpecGetName != null) {
					try {
						Object params = XECPublicKeyGetParams.invoke(publicKey);
						return (String) NamedParameterSpecGetName.invoke(params);
					} catch (Exception e) {
						throw new GeneralSecurityException("X25519/X448 not supported by JRE!", e);
					}
				} else {
					return publicKey.getAlgorithm();
				}
			}
			throw new GeneralSecurityException(publicKey.getAlgorithm() + " not supported!");
		}

		private static XDHPublicKeyApi init() {
			try {
				if (JceProviderUtil.usesBouncyCastle()) {
					Class<?> cls = Class.forName("org.bouncycastle.jcajce.provider.asymmetric.edec.BCXDHPublicKey");
					return new XDHPublicKeyReflection(cls);
				} else {
					Class<?> cls = Class.forName("java.security.spec.NamedParameterSpec");
					Method getName = cls.getMethod("getName");
					cls = Class.forName("java.security.interfaces.XECPublicKey");
					Method getParams = cls.getMethod("getParams");
					return new XDHPublicKeyReflection(cls, getParams, getName);
				}
			} catch (Throwable t) {
				LOGGER.info("X25519/X448 not supported!");
				return null;
			}
		}
	}
}
