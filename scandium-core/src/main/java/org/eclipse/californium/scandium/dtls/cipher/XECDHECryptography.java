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

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.eclipse.californium.elements.util.Asn1DerDecoder;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;

/**
 * A helper class to execute the XDH and ECDHE key agreement and key generation.
 * Support X25519 and X448 with java 11.
 * 
 * A ECDHE key exchange starts with negotiating a curve. The possible curves are
 * listed at <a href=
 * "http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8">
 * IANA Transport Layer Security (TLS) Parameters - TLS Supported Groups</a>.
 * The {@link SupportedGroup} reflects that and offer the curve's
 * {@link SupportedGroup#name()} (description in the IANA table) or
 * {@link SupportedGroup#getId()} (value in the IANA table). You may refer
 * directly a member, e.g. {@link SupportedGroup#X25519}, or get it by id
 * {@link SupportedGroup#fromId(int)} or by the curve-name
 * {@link SupportedGroup#valueOf(String)}.
 * 
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
 * 
 * <pre>
 * 
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
 * 
 * </pre>
 * 
 * results in same secrets {@code secret1} and {@code secret2}.
 * 
 * @see <a href="https://tools.ietf.org/html/rfc7748">RFC 7748</a>
 * @since 2.3
 */
public final class XECDHECryptography implements Destroyable {

	// Logging ////////////////////////////////////////////////////////

	protected static final Logger LOGGER = LoggerFactory.getLogger(XECDHECryptography.class);

	// Static members /////////////////////////////////////////////////

	/**
	 * The algorithm for the elliptic curve key pair generation.
	 * 
	 * See also <a href=
	 * "http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator"
	 * >KeyPairGenerator Algorithms</a>.
	 */
	private static final String EC_KEYPAIR_GENERATOR_ALGORITHM = "EC";

	private static final ThreadLocalKeyPairGenerator EC_KEYPAIR_GENERATOR = new ThreadLocalKeyPairGenerator(EC_KEYPAIR_GENERATOR_ALGORITHM);

	/**
	 * X25519 and X448.
	 */
	private static final String XDH_KEYPAIR_GENERATOR_ALGORITHM = "XDH";

	private static final ThreadLocalKeyPairGenerator XDH_KEYPAIR_GENERATOR = new ThreadLocalKeyPairGenerator(XDH_KEYPAIR_GENERATOR_ALGORITHM);

	private static final String EC_KEY_FACTORY_ALGORITHM = "EC";

	private static final ThreadLocalKeyFactory EC_KEY_FACTORY = new ThreadLocalKeyFactory(EC_KEY_FACTORY_ALGORITHM);

	private static final String XDH_KEY_FACTORY_ALGORITHM = "XDH";

	private static final ThreadLocalKeyFactory XDH_KEY_FACTORY = new ThreadLocalKeyFactory(XDH_KEY_FACTORY_ALGORITHM);

	/**
	 * Elliptic Curve Diffie-Hellman algorithm name. See also <a href=
	 * "http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyAgreement"
	 * >KeyAgreement Algorithms</a>.
	 */
	private static final String ECDH_KEY_AGREEMENT_ALGORITHM = "ECDH";

	private static final ThreadLocalKeyAgreement ECDH_KEY_AGREEMENT = new ThreadLocalKeyAgreement(ECDH_KEY_AGREEMENT_ALGORITHM);

	/**
	 * X25519 and X448.
	 */
	private static final String XDH_KEY_AGREEMENT_ALGORITHM = "XDH";

	private static final ThreadLocalKeyAgreement XDH_KEY_AGREEMENT = new ThreadLocalKeyAgreement(XDH_KEY_AGREEMENT_ALGORITHM);

	/**
	 * Use java 11 XDH via reflection.
	 */
	private static final Class<?> XECPublicKeyClass;
	private static final Method XECPublicKeyGetU;
	private static final Method XECPublicKeyGetParams;
	private static final Method NamedParameterSpecGetName;
	private static final Constructor<?> XECPublicKeySpecInit;

	static {
		Class<?> cls =null;
		Method getParams = null;
		Method getU = null;
		Method getName = null;
		Constructor<?> init = null;
		try {
			cls = Class.forName("java.security.spec.XECPublicKeySpec");
			init = cls.getConstructor(AlgorithmParameterSpec.class, BigInteger.class);
			cls = Class.forName("java.security.spec.NamedParameterSpec");
			getName = cls.getMethod("getName");
			cls = Class.forName("java.security.interfaces.XECPublicKey");
			getU = cls.getMethod("getU");
			getParams = cls.getMethod("getParams");
		} catch (Throwable t) {
			LOGGER.info("X25519/X448 not supported!");
		}
		XECPublicKeyClass = cls;
		XECPublicKeyGetU = getU;
		XECPublicKeyGetParams = getParams;
		NamedParameterSpecGetName = getName;
		XECPublicKeySpecInit = init;
	}

	/**
	 * Map of {@link SupportedGroup#getId() to {@link SupportedGroup}.
	 * 
	 * @see {@link SupportedGroup#fromId(int)}.
	 */
	private static final Map<Integer, SupportedGroup> EC_CURVE_MAP_BY_ID = new HashMap<>();
	/**
	 * Map of {@link SupportedGroup#getId() to {@link SupportedGroup}.
	 * 
	 * @see {@link SupportedGroup#fromId(int)}.
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
		privateKey = keyPair.getPrivate();
		publicKey = keyPair.getPublic();
		this.supportedGroup = supportedGroup;
		this.encodedPoint = encodedPoint(keyPair.getPublic());
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
	 * @throws GeneralSecurityException if a crypt error occurred.
	 */
	public SecretKey generateSecret(byte[] encodedPoint) throws GeneralSecurityException {
		if (encodedPoint == null) {
			throw new NullPointerException("encoded point must not be null!");
		}
		PublicKey peerPublicKey;
		int keySize = supportedGroup.getKeySizeInBytes();
		// extract public key
		if (supportedGroup.getAlgorithmName().equals(EC_KEYPAIR_GENERATOR_ALGORITHM)) {
			int left = encodedPoint.length - 1;
			if (encodedPoint[0] == Asn1DerDecoder.EC_PUBLIC_KEY_UNCOMPRESSED && left % 2 == 0 && left / 2 == keySize) {
				left /= 2;
				byte[] encoded = new byte[keySize];
				System.arraycopy(encodedPoint, 1, encoded, 0, keySize);
				BigInteger x = new BigInteger(1, encoded);
				System.arraycopy(encodedPoint, 1 + keySize, encoded, 0, keySize);
				BigInteger y = new BigInteger(1, encoded);
				ECParameterSpec ecParams = ((ECPrivateKey)privateKey).getParams();
				KeySpec publicKeySpec = new ECPublicKeySpec(new ECPoint(x, y), ecParams);
				KeyFactory keyFactory = EC_KEY_FACTORY.currentWithCause();
				peerPublicKey = keyFactory.generatePublic(publicKeySpec);
			} else {
				throw new GeneralSecurityException(
						"DHE: failed to decoded point! " + supportedGroup.name());
			}
		} else {
			BigInteger u = new BigInteger(1, revert(encodedPoint, keySize));
			KeySpec spec = getXECPublicKeySpec(supportedGroup.name(), u);
			KeyFactory keyFactory = XDH_KEY_FACTORY.currentWithCause();
			peerPublicKey = keyFactory.generatePublic(spec);
		}
		check("IN: ", peerPublicKey, encodedPoint);
		return generateSecret(peerPublicKey);
	}

	/**
	 * Runs the specified key agreement algorithm (ECDH) to generate the
	 * premaster secret.
	 * 
	 * @param peerPublicKey
	 *            the other peer's ephemeral public key.
	 * @return the premaster secret.
	 * @throws GeneralSecurityException if a crypt error occurred.
	 */
	private SecretKey generateSecret(PublicKey peerPublicKey) throws GeneralSecurityException {
		KeyAgreement keyAgreement = null;
		if (supportedGroup.getAlgorithmName().equals(EC_KEYPAIR_GENERATOR_ALGORITHM)) {
			keyAgreement = ECDH_KEY_AGREEMENT.currentWithCause();
		} else if (supportedGroup.getAlgorithmName().equals(XDH_KEYPAIR_GENERATOR_ALGORITHM)) {
			keyAgreement = XDH_KEY_AGREEMENT.currentWithCause();
		}
		keyAgreement.init(privateKey);
		keyAgreement.doPhase(peerPublicKey, true);
		byte[] secret = keyAgreement.generateSecret();
		SecretKey secretKey = SecretUtil.create(secret, "TlsPremasterSecret");
		Bytes.clear(secret);
		return secretKey;
	}

	@Override
	public void destroy() {
		privateKey = null;
	}

	@Override
	public boolean isDestroyed() {
		return privateKey == null;
	}

	/**
	 * Get public key as encoded point.
	 * 
	 * The key exchange contains the used curve by its
	 * {@link SupportedGroup#getId()}, therefore the ASN.1
	 * {@link PublicKey#getEncoded()} is not required.
	 * 
	 * @param publicKey public key
	 * @return encoded point to be sent to the other peer
	 * @throws GeneralSecurityException if the public key could not be converted
	 *             into a encoded point.
	 */
	private byte[] encodedPoint(PublicKey publicKey) throws GeneralSecurityException {
		byte[] result = null;
		int keySizeInBytes = supportedGroup.getKeySizeInBytes();
		try {
			if (supportedGroup.getAlgorithmName().equals(EC_KEYPAIR_GENERATOR_ALGORITHM)) {
				ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
				result = encodePoint(ecPublicKey.getW(), keySizeInBytes);
			} else if (supportedGroup.getAlgorithmName().equals(XDH_KEYPAIR_GENERATOR_ALGORITHM)) {
				BigInteger u = getXECPublicKeyU(publicKey);
				result = revert(u.toByteArray(), keySizeInBytes);
			}
		} catch (RuntimeException ex) {
			throw new GeneralSecurityException("DHE: failed to encoded point! " + supportedGroup.name(), ex);
		}
		if (result == null) {
			throw new GeneralSecurityException("DHE: failed to encoded point! " + supportedGroup.name());
		}
		check("OUT: ", publicKey, result);
		return result;
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

	// Serialization //////////////////////////////////////////////////

	private BigInteger getXECPublicKeyU(PublicKey publicKey) throws GeneralSecurityException {
		if (XECPublicKeyGetU == null) {
			throw new GeneralSecurityException(supportedGroup.name() + " not supported by JRE!");
		}
		try {
			return (BigInteger) XECPublicKeyGetU.invoke(publicKey);
		} catch (Exception e) {
			throw new GeneralSecurityException(supportedGroup.name() + " not supported by JRE!", e);
		}
	}

	private KeySpec getXECPublicKeySpec(String name, BigInteger u) throws GeneralSecurityException {
		if (XECPublicKeySpecInit == null) {
			throw new GeneralSecurityException(supportedGroup.name() + " not supported by JRE!");
		}
		try {
			ECGenParameterSpec parameterSpec = new ECGenParameterSpec(name);
			return (KeySpec) XECPublicKeySpecInit.newInstance(parameterSpec, u);
		} catch (Exception e) {
			throw new GeneralSecurityException(supportedGroup.name() + " not supported by JRE!", e);
		}
	}

	private static String getXECPublicKeyName(PublicKey publicKey) throws GeneralSecurityException {
		if (XECPublicKeyGetParams == null || NamedParameterSpecGetName == null) {
			throw new GeneralSecurityException("X25519/X448 not supported by JRE!");
		}
		try {
			Object params = XECPublicKeyGetParams.invoke(publicKey);
			return (String) NamedParameterSpecGetName.invoke(params);
		} catch (Exception e) {
			throw new GeneralSecurityException("X25519/X448 not supported by JRE!");
		}
	}

	/**
	 * Get offset for none zero data.
	 * 
	 * @param byteArray bytes to check for first none zero value
	 * @return offset of first none zero value
	 */
	private static int noneZeroOffset(byte[] byteArray) {
		int offset = 0;
		while (offset < byteArray.length && byteArray[offset] == 0) {
			++offset;
		}
		return offset;
	}

	/**
	 * Revert provided bytes into a array of provided size.
	 * 
	 * Strip leading zeros of the provided array. Adjust size of resulting array
	 * by append zeros.
	 * 
	 * @param byteArray array to revert
	 * @param size size of reverse array
	 * @return reverse array with appended padding zeros
	 */
	private static byte[] revert(byte[] byteArray, int size) {
		int offset = noneZeroOffset(byteArray);
		int length = byteArray.length - offset;
		if (length > size) {
			throw new IllegalArgumentException("big integer array exceeds size! " + length + " > " + size);
		}
		byte[] result = new byte[size];
		for (int index = 0; index < length; ++index) {
			result[length - 1 - index] = byteArray[index + offset];
		}
		return result;
	}

	/**
	 * Encodes an EC point according to the X9.62 specification.
	 * 
	 * @param point
	 *            the EC point to be encoded.
	 * @param keySizeInBytes
	 *            the keysize in bytes.
	 * @return the encoded EC point.
	 */
	private static byte[] encodePoint(ECPoint point, int keySizeInBytes) {
		// get field size in bytes (rounding up)

		byte[] xb = point.getAffineX().toByteArray();
		byte[] yb = point.getAffineY().toByteArray();
		int xbOffset = noneZeroOffset(xb);
		int xbLength = xb.length - xbOffset;
		int ybOffset = noneZeroOffset(yb);
		int ybLength = yb.length - ybOffset;

		if ((xbLength > keySizeInBytes) || (ybLength > keySizeInBytes)) {
			throw new IllegalArgumentException("ec point exceeds size! " + xbLength + "," + ybLength + " > " + keySizeInBytes);
		}

		// 1 byte (compression state) + twice field size
		byte[] encoded = new byte[1 + (keySizeInBytes * 2)];
		encoded[0] = Asn1DerDecoder.EC_PUBLIC_KEY_UNCOMPRESSED; // uncompressed
		System.arraycopy(xb, xbOffset, encoded, keySizeInBytes + 1 - xbLength, xbLength);
		System.arraycopy(yb, ybOffset, encoded, encoded.length - ybLength, ybLength);

		return encoded;
	}

	/**
	 * The <em>Supported Groups</em> as defined in the official
	 * <a href="http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8">
	 * IANA Transport Layer Security (TLS) Parameters</a>.
	 * 
	 * Also see <a href="http://tools.ietf.org/html/rfc4492#section-5.1.1">RFC 4492,
	 * Section 5.1.1 Supported Elliptic Curves Extension</a>.
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
		ffdhe2048(256, false),
		ffdhe3072(257, false),
		ffdhe4096(258, false),
		ffdhe6144(259, false),
		ffdhe8192(260, false),
		arbitrary_explicit_prime_curves(65281, false),
		arbitrary_explicit_char2_curves(65282, false),

		X25519(29, 32, XDH_KEYPAIR_GENERATOR_ALGORITHM, true),
		X448(30, 56, XDH_KEYPAIR_GENERATOR_ALGORITHM, true);

		private final int id;
		private final String algorithmName;
		private final int keySizeInBytes;
		private final boolean usable;
		private final boolean recommended;

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
			try {
				KeyPairGenerator keyPairGenerator = EC_KEYPAIR_GENERATOR.currentWithCause();
				ECGenParameterSpec genParams = new ECGenParameterSpec(name());
				keyPairGenerator.initialize(genParams);
				ECPublicKey apub = (ECPublicKey) keyPairGenerator.generateKeyPair().getPublic();
				curve= apub.getParams().getCurve();
				keySize = (curve.getField().getFieldSize() + Byte.SIZE - 1) / Byte.SIZE;
				EC_CURVE_MAP_BY_CURVE.put(curve, this);
			} catch (Throwable e) {
				LOGGER.trace("Group [{}] is not supported by JRE! {}", name(), e.getMessage());
				curve = null;
			}
			this.keySizeInBytes = keySize;
			this.usable = curve != null;
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
			this.recommended = recommended;
			boolean usable = false;
			try {
				KeyPairGenerator keyPairGenerator = XDH_KEYPAIR_GENERATOR.currentWithCause();
				ECGenParameterSpec params = new ECGenParameterSpec(name());
				keyPairGenerator.initialize(params);
				keyPairGenerator.generateKeyPair();
				usable = true;
			} catch (Throwable e) {
				LOGGER.trace("Group [{}] is not supported by JRE! {}", name(), e.getMessage());
			}
			this.usable = usable;
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

		public String getAlgorithmName() {
			return algorithmName;
		}

		/**
		 * Gets the group for a given id.
		 * 
		 * @param id the id
		 * @return the group or {@code null} if no group with the given id
		 *          is (currently) registered
		 */
		public static SupportedGroup fromId(int id) {
			return EC_CURVE_MAP_BY_ID.get(id);
		}

		/**
		 * Gets the group for a given public key.
		 * 
		 * @param publicKey the public key 
		 * @return the group or {@code null}, if no group with the given id
		 *          is (currently) registered
		 */
		public static SupportedGroup fromPublicKey(PublicKey publicKey) {
			if (publicKey != null) {
				if (publicKey instanceof ECPublicKey) {
					ECParameterSpec params = ((ECPublicKey) publicKey).getParams();
					return EC_CURVE_MAP_BY_CURVE.get(params.getCurve());
				} else if (XECPublicKeyClass != null && XECPublicKeyClass.isInstance(publicKey)) {
					try {
						String name = getXECPublicKeyName(publicKey);
						return SupportedGroup.valueOf(name);
					} catch (GeneralSecurityException ex) {

					}
				} else {
					// EdDsa work around ...
					String algorithm = publicKey.getAlgorithm();
					String oid = Asn1DerDecoder.getEdDsaStandardAlgorithmName(algorithm, null);
					if (Asn1DerDecoder.OID_ED25519.equals(oid) || Asn1DerDecoder.EDDSA.equalsIgnoreCase(oid)) {
						return X25519;
					} else if (Asn1DerDecoder.OID_ED448.equals(oid)) {
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
			} else if (XECPublicKeyClass != null && XECPublicKeyClass.isInstance(publicKey)) {
				return true;
			}
			return false;
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
					SupportedGroup group = fromPublicKey(certificate.getPublicKey());
					if (group == null || !group.isUsable() || !list.contains(group)) {
						return false;
					}
				}
			}
			return true;
		}

		/**
		 * Returns size of public key in bytes.
		 * 
		 * @return key size in bytes
		 */
		public int getKeySizeInBytes() {
			return keySizeInBytes;
		}

		/**
		 * Checks whether this group can be used on this platform.
		 * 
		 * @return <code>true</code> if the group's domain params are known
		 *            and the JRE's crypto provider supports it
		 */
		public boolean isUsable() {
			return usable;
		}

		public boolean isRecommended() {
			return recommended;
		}

		/**
		 * Gets all <code>SupportedGroup</code>s that can be used on this
		 * platform.
		 * 
		 * @return the supported groups as unmodifiable list.
		 * @see #isUsable()
		 */
		public static List<SupportedGroup> getUsableGroups() {
			return Initialize.USABLE_GROUPS;
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
}
