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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add latest curves from IANA registry,
 *                                                    add SupportedGroup enum also holding
 *                                                    curve params, add brainpool curve params
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import org.eclipse.californium.scandium.util.ByteArrayUtils;

/**
 * A helper class to execute the ECDHE key agreement and key generation.
 */
public final class ECDHECryptography {

	// Logging ////////////////////////////////////////////////////////

	protected static final Logger LOGGER = Logger.getLogger(ECDHECryptography.class.getCanonicalName());

	// Static members /////////////////////////////////////////////////

	/**
	 * The algorithm for the elliptic curve key pair generation.
	 * 
	 * See also <a href=
	 * "http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator"
	 * >KeyPairGenerator Algorithms</a>.
	 */
	private static final String KEYPAIR_GENERATOR_ALGORITHM = "EC";

	private static final int PRIME = 1;
	private static final int BINARY = 2;
	

	/**
	 * Elliptic Curve Diffie-Hellman algorithm name. See also <a href=
	 * "http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyAgreement"
	 * >KeyAgreement Algorithms</a>.
	 */
	private static final String KEY_AGREEMENT_INSTANCE = "ECDH";

	// Members ////////////////////////////////////////////////////////
	
	/** The ephemeral private key. */
	private ECPrivateKey privateKey;
	
	/** The ephemeral public key. */
	private ECPublicKey publicKey;

	// Constructors ///////////////////////////////////////////////////

	/**
	 * Creates an ephemeral ECDH key pair for a given set of EC domain parameters.
	 * 
	 * This constructor is usually invoked by the client after having received
	 * the params in the <em>SERVER_KEY_EXCHANGE</em> message.
	 * 
	 * @param params
	 *            the domain parameters to create the keys for
	 * @throws GeneralSecurityException if the key pair cannot be created from the
	 *            given parameters
	 */
	public ECDHECryptography(ECParameterSpec params) throws GeneralSecurityException {
		createKeys(params);
	}

	/**
	 * Creates an ephemeral ECDH key pair for a given supported group.
	 * 
	 * @param supportedGroup
	 *            the name of the supported group to use as defined in
	 *            the <a href="http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8">
	 *            IANA Supported Groups Registry</a>
	 * @throws GeneralSecurityException if the key pair cannot be created from the
	 *            given name, e.g. because the JRE's crypto provider doesn't support the group
	 */
	private ECDHECryptography(String supportedGroup) throws GeneralSecurityException {
		createKeys(new ECGenParameterSpec(supportedGroup));
	}

	/**
	 * Creates an ephemeral ECDH key pair for a supported group (named curve).
	 * 
	 * @param supportedGroupId
	 *            the ID of the supported group (named curve) which will be used to create
	 *            the keys
	 * @return the object containing the keys or <code>null</code> if the group with the given
	 *            id is not supported by the JRE's cryptography provider(s)
	 */
	public static ECDHECryptography fromNamedCurveId(int supportedGroupId) {
		SupportedGroup group = SupportedGroup.fromId(supportedGroupId);
		if (group == null) {
			return null;
		} else {
			try {
				return new ECDHECryptography(group.name());
			} catch (GeneralSecurityException e) {
				LOGGER.log(
					Level.WARNING,
					"Cannot create ephemeral keys for group [{0}]: {1}",
					new Object[]{group.name(), e.getMessage()});
				return null;
			}
		}
	}
	
	private void createKeys(AlgorithmParameterSpec params) throws GeneralSecurityException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEYPAIR_GENERATOR_ALGORITHM);
		keyPairGenerator.initialize(params, new SecureRandom());

		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		privateKey = (ECPrivateKey) keyPair.getPrivate();
		publicKey = (ECPublicKey) keyPair.getPublic();
	}
	
	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public ECPublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Called by the server. Extracts the client's public key from the encoded
	 * point and then runs the specified key agreement algorithm (ECDH) to
	 * generate the premaster secret.
	 * 
	 * @param encodedPoint
	 *            the client's public key (encoded)
	 * @return the premaster secret
	 */
	public SecretKey getSecret(byte[] encodedPoint) {
		SecretKey secretKey = null;
		try {
			// extract public key
			ECParameterSpec params = publicKey.getParams();
			ECPoint point = decodePoint(encodedPoint, params.getCurve());

			KeyFactory keyFactory = KeyFactory.getInstance(KEYPAIR_GENERATOR_ALGORITHM);
			ECPublicKeySpec keySpec = new ECPublicKeySpec(point, params);
			PublicKey peerPublicKey = keyFactory.generatePublic(keySpec);

			secretKey = getSecret(peerPublicKey);

		} catch (Exception e) {
			LOGGER.log(Level.SEVERE,"Could not generate the premaster secret.",e);
		}
		return secretKey;
	}

	/**
	 * Runs the specified key agreement algorithm (ECDH) to generate the
	 * premaster secret.
	 * 
	 * @param peerPublicKey
	 *            the peer's ephemeral public key.
	 * @return the premaster secret.
	 */
	public SecretKey getSecret(PublicKey peerPublicKey) {
		SecretKey secretKey = null;
		try {
			KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_INSTANCE);
			keyAgreement.init(privateKey);
			keyAgreement.doPhase(peerPublicKey, true);
			
			secretKey = keyAgreement.generateSecret("TlsPremasterSecret");
		} catch (Exception e) {
			LOGGER.log(Level.SEVERE,"Could not generate the premaster secret.",e);
		}
		return secretKey;
	}
	
	// Serialization //////////////////////////////////////////////////
	
	/**
	 * Decodes an EC point according to the X9.62 specification.
	 * 
	 * @param encoded
	 *            the encoded EC point.
	 * @param curve
	 *            the elliptic curve the point lies on.
	 * @return the EC point.
	 */
	public static ECPoint decodePoint(byte[] encoded, EllipticCurve curve) {
		if ((encoded.length == 0) || (encoded[0] != 0x04)) {
			LOGGER.severe("Only uncompressed point format supported.");
			return null;
		}
		
		int fieldSize = (curve.getField().getFieldSize() + 7) / 8;
		if (encoded.length != (fieldSize * 2) + 1) {
			LOGGER.severe("Point does not match field size.");
			return null;
		}
		byte[] xb = new byte[fieldSize];
		byte[] yb = new byte[fieldSize];
		
		System.arraycopy(encoded, 1, xb, 0, fieldSize);
		System.arraycopy(encoded, fieldSize + 1, yb, 0, fieldSize);
		
		return new ECPoint(new BigInteger(1, xb), new BigInteger(1, yb));
	}
	
	/**
	 * Encodes an EC point according to the X9.62 specification.
	 * 
	 * @param point
	 *            the EC point to be encoded.
	 * @param curve
	 *            the elliptic curve the point lies on.
	 * @return the encoded EC point.
	 */
	public static byte[] encodePoint(ECPoint point, EllipticCurve curve) {
		// get field size in bytes (rounding up)
		int fieldSize = (curve.getField().getFieldSize() + 7) / 8;
		
		byte[] xb = ByteArrayUtils.trimZeroes(point.getAffineX().toByteArray());
		byte[] yb = ByteArrayUtils.trimZeroes(point.getAffineY().toByteArray());
		
		if ((xb.length > fieldSize) || (yb.length > fieldSize)) {
			LOGGER.severe("Point coordinates do not match field size.");
			return null;
		}
		
		// 1 byte (compression state) + twice field size
		byte[] encoded = new byte[1 + (fieldSize * 2)];
		encoded[0] = 0x04; // uncompressed
		System.arraycopy(xb, 0, encoded, fieldSize - xb.length + 1, xb.length);
		System.arraycopy(yb, 0, encoded, encoded.length - yb.length, yb.length);
		
		return encoded;
	}

	/**
	 * The <em>Supported Groups</em> as defined in the official
	 * <a href="http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8">
	 * IANA Transport Layer Security (TLS) Parameters</a>.
	 * 
	 * Also see <a href="http://tools.ietf.org/html/rfc4492#section-5.1.1">RFC 4492,
	 * Section 5.1.1 Supported Elliptic Curves Extension</a>.
	 * 
	 * Brainpool curve domain parameters as defined in
	 * <a href="http://tools.ietf.org/html/rfc5639">
	 * RFC 5639 - ECC Brainpool Standard Curves and Curve Generation</a>.
	 * 
	 * Sec curve domain parameters taken from <a href="http://www.secg.org/sec2-v2.pdf">
	 * SEC 2: Recommended Elliptic Curve Domain Parameters</a>
	 */
	public enum SupportedGroup {

		sect163k1(1),
		sect163r1(2),
		sect163r2(3),
		sect193r1(4),
		sect193r2(5),
		sect233k1(6),
		sect233r1(7),
		sect239k1(8),
		sect283k1(9),
		sect283r1(10),
		sect409k1(11),
		sect409r1(12),
		sect571k1(13),
		sect571r1(14),
		secp160k1(15),
		secp160r1(16),
		secp160r2(17),
		secp192k1(18, PRIME,
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37",
				"000000000000000000000000000000000000000000000000",
				"000000000000000000000000000000000000000000000003",
				"DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D",
				"9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D",
				"FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D",
				1),
		secp192r1(19, PRIME,
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF",
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC",
				"64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1",
				"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012",
				"07192B95FFC8DA78631011ED6B24CDD573F977A11E794811",
				"FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
				1),
		secp224k1(20, PRIME,
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D",
				"00000000000000000000000000000000000000000000000000000000",
				"00000000000000000000000000000000000000000000000000000005",
				"A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C",
				"7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5",
				"010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7",
				1),
		secp224r1(21, PRIME, // [NIST P-224]
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
				"B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
				"B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
				"BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
				1),
		secp256k1(22, PRIME,
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
				"0000000000000000000000000000000000000000000000000000000000000000",
				"0000000000000000000000000000000000000000000000000000000000000007",
				"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
				"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
				1),
		secp256r1(23, PRIME, // [NIST P-256, X9.62 prime256v1]
				"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
				"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
				"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
				"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
				"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
				"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
				1),
		secp384r1(24, PRIME, // [NIST P-384]
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
				"B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
				"AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
				"3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
				1),
		secp521r1(25, PRIME, // [NIST P-521]
				"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
				"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
				"0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
				"00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
				"011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
				"01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
				1),
		brainpoolP256r1(26, PRIME,
				"A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
				"7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
				"26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
				"8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
				"547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
				"A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",
				1),
		brainpoolP384r1(27, PRIME,
				"8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
				"7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
				"4A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
				"1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
				"8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
				"8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565",
				1),
		brainpoolP512r1(28, PRIME,
				"AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
				"7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
				"3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
				"81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
				"7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
				"AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069",
				1),
		ffdhe2048(256),
		ffdhe3072(257),
		ffdhe4096(258),
		ffdhe6144(259),
		ffdhe8192(260),
		arbitrary_explicit_prime_curves(65281),
		arbitrary_explicit_char2_curves(65282);

		private int id;
		private ECParameterSpec params = null;
		private boolean usable;

		private SupportedGroup(int code) {
			this.id = code;
		}

		private SupportedGroup(int code, int type, String p, String a, String b, String x, String y,
				String n, int h) {
			this(code);
			BigInteger bip = bi(p);
			ECField field;
			switch(type) {
			case(PRIME):
				field = new ECFieldFp(bip);
				break;
			case(BINARY):
				field = new ECFieldF2m(bip.bitLength() - 1, bip);
				break;
			default:
				throw new RuntimeException("Cannot handle supported groups of type " + type);
			}
			EllipticCurve curve = new EllipticCurve(field, bi(a), bi(b));
			ECPoint g = new ECPoint(bi(x), bi(y));
			this.params = new ECParameterSpec(curve, g, bi(n), h);
			try {
				KeyPairGenerator gen = KeyPairGenerator.getInstance(KEYPAIR_GENERATOR_ALGORITHM);
				gen.initialize(new ECGenParameterSpec(name()));
				usable = true;
			} catch (GeneralSecurityException e) {
				LOGGER.log(Level.FINE, "Group [{0}] is not supported by JRE", name());
			}
		}

		private BigInteger bi(String s) {
			return new BigInteger(s, 16);
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
		 * Gets the group for a given id.
		 * 
		 * @param id the id
		 * @return the group or <code>null</code> if no group with the given id
		 *          is (currently) registered
		 */
		public static SupportedGroup fromId(int id) {
			for (SupportedGroup group : values()) {
				if (group.getId() == id) {
					return group;
				}
			}
			return null;
		}

		/**
		 * Gets this group's corresponding EC parameters.
		 * 
		 * @return the parameter object or <code>null</code> if the params
		 *           for this group are not (yet) registered
		 */
		public ECParameterSpec getEcParams() {
			return params;
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

		/**
		 * Gets all <code>SupportedGroup</code>s that can be used on this platform.
		 * 
		 * @return the supported groups
		 * @see #isUsable()
		 */
		public static SupportedGroup[] getUsableGroups() {
			List<SupportedGroup> result = new ArrayList<>();
			for (SupportedGroup group : SupportedGroup.values()) {
				if (group.isUsable()) {
					result.add(group);
				}
			}
			return result.toArray(new SupportedGroup[]{});
		}

		/**
		 * Gets the preferred <em>supported groups</em>.
		 * 
		 * @return the groups in order of preference
		 */
		public static List<SupportedGroup> getPreferredGroups() {
			List<SupportedGroup> result = new ArrayList<>();
			for (SupportedGroup group : SupportedGroup.values()) {
				switch(group) {
				case secp256r1:
				case secp384r1:
				case secp521r1:
					result.add(group);
				default:
					// skip
				}
			}
			return result;
		}
	}
}
