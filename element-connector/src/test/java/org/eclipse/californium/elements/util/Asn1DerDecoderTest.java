/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeNoException;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.Asn1DerDecoder.Keys;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verifies behavior of {@link Asn1DerDecoder}.
 */
@Category(Small.class)
public class Asn1DerDecoderTest {

	/**
	 * DH subject public key, ASN.1 DER / Base64 encoded.
	 */
	private static final String DH_BASE64 = "MIIBpjCCARsGCSqGSIb3DQEDATCCAQwCgYEA/X9TgR11EilS30qcLuzk5/YRt1I870QAwx4/gLZRJmlFXUAiUftZPY1Y+r/F9bow9subVWzXgTuAHTRv8mZgt2uZUKWkn5/oBHsQIsJPu6nX/rfGG/g7V+fGqKYVDwT7g/bTxR7DAjVUE1oWkTL2dfOuK2HXKu/yIgMZndFIAccCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoCAgIAA4GEAAKBgH5J+o19W2ct7iGFz0/dLMaYLjCuw7TdaU2QtzZb5FmGj1TyglARYb9V3nKoqifSKlgnwFU8RBu61Sw5/gZYhAeap8kvPH7dwIrBNc4wbt5CMdicCZlSluOPrX6mYn9HzvuIaS0V8G11soSHikCCIp9gFeMLfI0AtbPOYDYD0jHA";
	/**
	 * EC subject public key, ASN.1 DER / Base64 encoded.
	 */
	private static final String EC_BASE64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEx4ABEJuzneP12mmh/RLlE6lM58MIrngQtfOK/eguzwNuTEP0wrE3H0p9rg1fZywtwleyl7lYUcxa8mQPOi4mRA==";
	/**
	 * DSA subject public key, ASN.1 DER / Base64 encoded.
	 */
	private static final String DSA_BASE64 = "MIIBtzCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYQAAoGAdp65TFSOhis6Ezu3Hq5LmKuu1eVDFkb1G/YuLOCYnkjG976B8G+W4TIVdM5yg7+Q0DU35mb2jrKHnRqnf5hRODnlp7kmUE2y1VBpgkx/9y+NYVMmfCqFqEn3c4DbWJvDcmvlKxG0okcSUdHcfxsF7grsyKB0RUTaXpwzdskHYo0=";
	/**
	 * RSA subject public key, ASN.1 DER / Base64 encoded.
	 */
	private static final String RSA_BASE64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCNPpjuSuq6BQ3/YGWbVpmNa0q+/vURtkbwPJIocT/b8QqmqdebnQxvADv9UpwWSrEyPkzY8Mq9bJRzRokJ8KQKbf9DTVFQmRmzikIk/Jwcm4+ST2plfHxDnywT9EYPrnNf6TrL/6fZsN0x1NMtr5unnlTND66HGNp+YMjqFgfnWwIDAQAB";
	/**
	 * EdDSA subject public key, ASN.1 DER / Base64 encoded.
	 * 
	 * @since 3.0
	 */
	private static final String EDDSA_BASE64 = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";
	/**
	 * DH private key, ASN.1 DER / Base64 encoded.
	 */
	private static final String DH_PRIVATE_KEY_BASE64 = "MIIBqQIBADCCARsGCSqGSIb3DQEDATCCAQwCggEBAP//////////yQ/aoiFowjTExmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR7ORbPcIAfLihY78FmNpINhxV05ppFj+o/STPX4NlXSPco62WHGLzViCFUrue1SkHcJaWbWcMNU5KvJgE8XRsCMoYIXwykF5GLjbOO+OedywYDoYDmyeDouwHoo+1xV3wb0xSyd4ry/aVWBcYOZVJfOqVauUV0iYYmPoFEBVyjlqKrKpo//////////8CAQICAgQABIGEAoGBAONq49y1IsHNiwJ29e6ajPsikR/SZM+g0aWIVlTT4CFZxQggHw5lSmZ0rtFig8ZNjAxozWB2Bkb8+592oHNDf683N9MCtPC98B+BL98PvCRt8/GVHX0eOTHyiIl/xJYcKznlYUlXNuwmjmLM3PyLkzyOfzNaE7elYoaqBrm3YeRF";
	/**
	 * EC private key, ASN.1 DER / Base64 encoded.
	 */
	private static final String EC_PRIVATE_KEY_BASE64 = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBXZvjdi6st1zBCLZMbWLcJJm9hPilOMfpDU2O5ocj09A==";
	/**
	 * DSA private key, ASN.1 DER / Base64 encoded.
	 */
	private static final String DSA_PRIVATE_KEY_BASE64 = "MIICXAIBADCCAjUGByqGSM44BAEwggIoAoIBAQCPeTXZuarpv6vtiHrPSVG28y7FnjuvNxjo6sSWHz79NgbnQ1GpxBgzObgJ58KuHFObp0dbhdARrbi0eYd1SYRpXKwOjxSzNggooi/6JxEKPWKpk0U0CaD+aWxGWPhL3SCBnDcJoBBXsZWtzQAjPbpUhLYpH51kjviDRIZ3l5zsBLQ0pqwudemYXeI9sCkvwRGMn/qdgYHnM423krcw17njSVkvaAmYchU5Feo9a4tGU8YzRY+AOzKkwuDycpAlbk4/ijsIOKHEUOThjBopo33fXqFD3ktm/wSQPtXPFiPhWNSHxgjpfyEc2B3KI8tuOAdl+CLjQr5ITAV2OTlgHNZnAh0AuvaWpoV499/e5/pnyXfHhe8ysjO65YDAvNVpXQKCAQAWplxYIEhQcE51AqOXVwQNNNo6NHjBVNTkpcAtJC7gT5bmHkvQkEq9rI837rHgnzGC0jyQQ8tkL4gAQWDt+coJsyB2p5wypifyRz6Rh5uixOdEvSCBVEy1W4AsNo0fqD7UielOD6BojjJCilx4xHjGjQUntxyaOrsLC+EsRGiWOefTznTbEBplqiuH9kxoJts+xy9LVZmDS7TtsC98kOmkltOlXVNb6/xF1PYZ9j897buHOSXC8iTgdzEpbaiH7B5HSPh++1/et1SEMWsiMt7lU92vAhErDR8C2jCXMiT+J67ai51LKSLZuovjntnhA6Y8UoELxoi34u1DFuHvF9veBB4CHEpxWKYNTQUZzEBfqFWuYbTgHkVHjWX+KJC1E24=";
	/**
	 * RSA private key, ASN.1 DER / Base64 encoded.
	 */
	private static final String RSA_PRIVATE_KEY_BASE64 = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCu1A2ebEmUwPw0AUm9jQmZyiQTNADG4x7tXBGg7mIFiqgSDjwAWCGxx6RJ5kOMmhkNHU2bFq+42brWxNWAJxPtWC9j7fX4+i1h9koo8CS5LmPFxdgZnPanyl8XEwq54wKmvGAoiKRSfGNKn8FPIdRZMfJKd9+8dn3Qwvgzw0uHvVsg2cmJLsi/cfFuG54SO6uwPHylNPxdWpcKED8rKsFVWYv8FYyj6xN2fl8G2pBMVI1LYZRCmQjStoaFt8QsFi9L3U5yzdVDadwSdWLrvYbUGaZ4+64YRrDjf3kGRDNT46KpAg9hcXhusVIJVN+oe/t5Dp7wUuPtHuU6ZbJCH8rfAgMBAAECggEBAITZDiA8GQ24N+0srWQkMA9000TkV1LKc03akGrBuiqL2nsd5eo9Dh2Rnv2ow9urnS2h/r7C1nSYvqlEmRfwmevY/unogOjY8nNmO6QwFzfAUICQfk24QJXv6aIXDieCoRkiO8+RRYyIiMrD6pi/FCVTFtIPlSwYvjJMdV6gIFzb+sDTMROvLNYsIMVybTzcCMzXt7yMrPgP9gXM1Y3/+vaJNPF8mdBtS+VMnbhl2B4sXnpwxrm5QjcOvGABjf16gAUKa5EGU6BDpH+H/xHNnCkTo+mSe5jGg71VCRRPKxoVbGmUD7x+Rx4hRlfsp7PnujW1guCEe5cO/mnYXBa+zAECgYEA78WD/ZUyXlqJv/fsQfhdn8rEd0y2L9U/8ku8nZIIGGN0+cYDBG3P2d9qgd2pKmDvepM18tw8E0T3csL+/FsfiiREsB4uO19syk6i4/vW6T7s+Z3w5FZu1/RspzcW0SEIMV6lszyRTcauifT4rNvbmCFWaN7BvX0HE1Y5uC2rFh8CgYEAuqlG0U4Wpn2eLK7hFgdQTWc2xh2KjYEreSm6rAd8LtqYTvV1NsJN6MRk558zss06PRVx0vEoi9yzVszO1WRu8niZUIFbbxZUJYeNP9fHH+m6PcBm1tvyRGneBhzcNPSNBp5gLYGKExG9bDOEYQU3fTkf14iVpxkkf81vrazZM0ECgYBkl6ILdleeXC+keTgGaVOmIWSRhH5+zOG6HmowVT7ONJOz4o4LgqKMDn5Zo4xAOlDeRPqCPEF7+Bg0bniZmQU/aH3kwZS11hAHRDx0l4iPbJXxF4Ej2ttAAMzAzozlCg2s4L911fhEABHj0QGvS8HyLjJZZvMzM0wPocIvcgFwEwKBgG7+XWf0YS+bHsU/MATjUHLWXxGrW0oNdwZTM/c7dDKANXUuLAblv2Ib9kxstFcsBedwqwBd+lhAYjvJCWyGjhqMb84ZPX9u7ZZrZiiCbJujZeV2VTCKFSNtOGK2IpMyn/FBl7s3fh0cvWBrudnfOkGyCCcnxqVYJAYC6NeDIpyBAoGBANdZuLSCOoNc60Askcc+IlhiAr01+nXw6EChmHHYsnmlt68ymG3MZXJ0knSHVLBsd8SKsMlZaIXik1qK1IFCn6UeR9+NBv5t3xPplWBky8qKJPfwYoPCFsdwXgLmI46zmGjsIw7LxQ9bS/mNus01x1lkLAHnZzfUjOG+5LBckTNz";
	/**
	 * EdDSA v1 private key, ASN.1 DER / Base64 encoded.
	 */
	private static final String EDDSA_PRIVATE_KEY_BASE64 = "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC";
	/**
	 * EC v2 private key, ASN.1 DER / Base64 encoded.
	 */
	private static final String EC_PRIVATE_KEY_V2_BASE64 = "MHcCAQEEIGDNwnadKqfjorTbDAVsWmWHTf2fBoU2b6HwtgKkiiNvoAoGCCqGSM49AwEHoUQDQgAE40FK6QvIFN+T6fAQLIv0PA9IrbrgxHSOcwspNx1V2xqWKs6/rSle/uMXo4KIzCl+HVKlr+nshvXrpOesdvJAaQ==";
	/**
	 * EdDSA v2 private key, ASN.1 DER / Base64 encoded.
	 */
	private static final String EDDSA_PRIVATE_KEY_V2_BASE64 = "MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhCoB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";
	/**
	 * X509Principal, ASN.1 DER / Base64 encoded.
	 */
	private static final String PRINCIPAL_BASE64 = "MF4xEjAQBgNVBAMTCWNmLXNlcnZlcjEUMBIGA1UECxMLQ2FsaWZvcm5pdW0xFDASBgNVBAoTC0VjbGlwc2UgSW9UMQ8wDQYDVQQHEwZPdHRhd2ExCzAJBgNVBAYTAkNB";
	/**
	 * X509Principal, ASN.1 DER / Base64 encoded.
	 */
	private static final String WILDCARD_PRINCIPAL_BASE64 = "MGAxFDASBgNVBAMMCyouY2Ytc2VydmVyMRQwEgYDVQQLEwtDYWxpZm9ybml1bTEUMBIGA1UEChMLRWNsaXBzZSBJb1QxDzANBgNVBAcTBk90dGF3YTELMAkGA1UEBhMCQ0E=";

	/**
	 * Sequence, ASN.1 DER encoded.
	 */
	private static byte[] sequence;

	/**
	 * Creates a ASN.1 SEQUENCE.
	 * 
	 * @throws IOException
	 */
	@BeforeClass
	public static void init() throws IOException {
		// use subject public key as SEQUENCE
		sequence = Base64.decode(RSA_BASE64);
	}

	/**
	 * Test, if decoder can read entity (tag, length, and value).
	 */
	@Test
	public void testSequenceEntityDecoder() throws NoSuchAlgorithmException {
		DatagramReader reader = new DatagramReader(sequence);
		byte[] sequenceEntity = Asn1DerDecoder.readSequenceEntity(reader);
		assertThat(sequenceEntity, is(sequence));
	}

	/**
	 * Test, if decoder can read entity (tag, length, and value), when more data
	 * is available.
	 */
	@Test
	public void testSequenceEntityDecoderProvideMoreData() throws NoSuchAlgorithmException {
		byte[] more = Arrays.copyOf(sequence, sequence.length * 2);
		DatagramReader reader = new DatagramReader(more);
		byte[] sequenceEntity = Asn1DerDecoder.readSequenceEntity(reader);
		assertThat(sequenceEntity, is(sequence));
	}

	/**
	 * Test, if decoder can read RSA subject public key and algorithm.
	 */
	@Test
	public void testKeyAlgorithmRsa() throws IOException, GeneralSecurityException {
		byte[] data = Base64.decode(RSA_BASE64);
		assertThat(Asn1DerDecoder.readSubjectPublicKeyAlgorithm(data), is("RSA"));
		assertThat(Asn1DerDecoder.readSubjectPublicKey(data), is(notNullValue()));
	}

	/**
	 * Test, if decoder can read DSA subject public key and algorithm.
	 */
	@Test
	public void testKeyAlgorithmDsa() throws IOException, GeneralSecurityException {
		byte[] data = Base64.decode(DSA_BASE64);
		assertThat(Asn1DerDecoder.readSubjectPublicKeyAlgorithm(data), is("DSA"));
		assertThat(Asn1DerDecoder.readSubjectPublicKey(data), is(notNullValue()));
	}

	/**
	 * Test, if decoder can read EC subject public key and algorithm.
	 */
	@Test
	public void testKeyAlgorithmEc() throws IOException, GeneralSecurityException {
		byte[] data = Base64.decode(EC_BASE64);
		assertThat(Asn1DerDecoder.readSubjectPublicKeyAlgorithm(data), is("EC"));
		assertThat(Asn1DerDecoder.readSubjectPublicKey(data), is(notNullValue()));
	}

	/**
	 * Test, if decoder can read DH subject public key and algorithm.
	 */
	@Test
	public void testKeyAlgorithmDH() throws IOException, GeneralSecurityException {
		byte[] data = Base64.decode(DH_BASE64);
		assertThat(Asn1DerDecoder.readSubjectPublicKeyAlgorithm(data), is("DH"));
		assertThat(Asn1DerDecoder.readSubjectPublicKey(data), is(notNullValue()));
	}

	/**
	 * Test, if decoder can read EdDSa subject public key and algorithm.
	 */
	@Test
	public void testKeyAlgorithmEddsa() throws IOException, GeneralSecurityException {
		byte[] data = Base64.decode(EDDSA_BASE64);
		assertThat(Asn1DerDecoder.readSubjectPublicKeyAlgorithm(data), is(JceNames.ED25519));
		if (JceProviderUtil.isSupported(JceNames.ED25519)) {
			assertThat(Asn1DerDecoder.readSubjectPublicKey(data), is(notNullValue()));
		}
	}

	/**
	 * Test, if decoder handles the key algorithm synonym proper.
	 */
	@Test
	public void testEqualKeyAlgorithmSynonyms() throws NoSuchAlgorithmException {
		assertSynonym("", true, "RSA", "RSA");
		assertSynonym("", true, "DH", "DiffieHellman");
		assertSynonym("", true, "DiffieHellman", "DiffieHellman");
		assertSynonym("", true, "DiffieHellman", "DH");
		assertSynonym("", false, "DH", "RSA");
		assertSynonym("", false, "DSA", "DiffieHellman");
		assertSynonym("", false, "EC", "ED25519");
		assertSynonym("", false, "ED448", "ED25519");
		assertSynonym("", true, "EdDSA", "ED25519");
		assertSynonym("", true, "EdDSA", "ED448");
		assertSynonym("", true, "ED25519.v2", "ED25519");
		assertSynonym("", true, "X25519.v2", "X25519");
	}

	/**
	 * Test, if decoder can read EC private key and algorithm.
	 */
	@Test
	public void testPrivateKeyAlgorithmRSA() throws IOException, GeneralSecurityException {
		byte[] data = Base64.decode(RSA_PRIVATE_KEY_BASE64);
		assertThat(Asn1DerDecoder.readPrivateKeyAlgorithm(data), is(JceNames.RSA));
		assertThat(Asn1DerDecoder.readPrivateKey(data), is(notNullValue()));
	}

	/**
	 * Test, if decoder can read EC private key and algorithm.
	 */
	@Test
	public void testPrivateKeyAlgorithmDsa() throws IOException, GeneralSecurityException {
		byte[] data = Base64.decode(DSA_PRIVATE_KEY_BASE64);
		assertThat(Asn1DerDecoder.readPrivateKeyAlgorithm(data), is(JceNames.DSA));
		assertThat(Asn1DerDecoder.readPrivateKey(data), is(notNullValue()));
	}

	/**
	 * Test, if decoder can read EC private key and algorithm.
	 */
	@Test
	public void testPrivateKeyAlgorithmEc() throws IOException, GeneralSecurityException {
		byte[] data = Base64.decode(EC_PRIVATE_KEY_BASE64);
		assertThat(Asn1DerDecoder.readPrivateKeyAlgorithm(data), is(JceNames.EC));
		assertThat(Asn1DerDecoder.readPrivateKey(data), is(notNullValue()));
	}

	/**
	 * Test, if decoder can read DH private key and algorithm.
	 */
	@Test
	public void testPrivateKeyAlgorithmDH() throws IOException, GeneralSecurityException {
		byte[] data = Base64.decode(DH_PRIVATE_KEY_BASE64);
		assertThat(Asn1DerDecoder.readPrivateKeyAlgorithm(data), is(JceNames.DH));
		assertThat(Asn1DerDecoder.readPrivateKey(data), is(notNullValue()));
	}

	/**
	 * Test, if decoder can read EdDSA private key and algorithm.
	 */
	@Test
	public void testPrivateKeyAlgorithmEddsa() throws IOException, GeneralSecurityException {
		byte[] data = Base64.decode(EDDSA_PRIVATE_KEY_BASE64);
		assertThat(Asn1DerDecoder.readPrivateKeyAlgorithm(data), is(JceNames.ED25519));
		if (JceProviderUtil.isSupported(JceNames.ED25519)) {
			assertThat(Asn1DerDecoder.readPrivateKey(data), is(notNullValue()));
		}
	}

	/**
	 * Test, if decoder can read EC v2 private key and algorithm.
	 */
	@Test
	public void testPrivateKeyAlgorithmEcV2() throws IOException {
		byte[] data = Base64.decode(EC_PRIVATE_KEY_V2_BASE64);
		assertThat(Asn1DerDecoder.readPrivateKeyAlgorithm(data), is(JceNames.ECv2));
	}

	/**
	 * Test, if decoder can read EdDSA v2 private key algorithm.
	 */
	@Test
	public void testPrivateKeyAlgorithmEdDsaV2() throws IOException {
		byte[] data = Base64.decode(EDDSA_PRIVATE_KEY_V2_BASE64);
		assertThat(Asn1DerDecoder.readPrivateKeyAlgorithm(data), is(JceNames.ED25519v2));
	}

	/**
	 * Test, if decoder can read EC v2 private key.
	 */
	@Test
	public void testReadPrivateKeyEcV2() throws IOException, GeneralSecurityException {
		byte[] data = Base64.decode(EC_PRIVATE_KEY_V2_BASE64);
		Keys keys = Asn1DerDecoder.readPrivateKey(data);
		assertThat(keys, is(notNullValue()));
		assertThat(keys.getPrivateKey(), is(notNullValue()));
		assertThat(keys.getPublicKey(), is(notNullValue()));
		TestCertificatesTools.assertSigning("asn.1", keys.getPrivateKey(), keys.getPublicKey(), "SHA256withECDSA");
	}

	@Test
	public void testBrokenEcdsa() throws IOException, GeneralSecurityException {
		String version = System.getProperty("java.version");
		byte[] data = Base64.decode(EC_PRIVATE_KEY_V2_BASE64);
		Keys keys = Asn1DerDecoder.readPrivateKey(data);
		assertThat(keys, is(notNullValue()));
		assertThat(keys.getPrivateKey(), is(notNullValue()));
		assertThat(keys.getPublicKey(), is(notNullValue()));
		try {
			boolean broken = false;
			SecureRandom random = new SecureRandom();
			Signature signature = Signature.getInstance("SHA256withECDSA");
			String provider = signature.getProvider().toString();
			String info = "Java " + version + ", "+ provider;
			byte[] message = Bytes.createBytes(random, 1024);
			signature.initSign(keys.getPrivateKey());
			signature.update(message);
			byte[] sign = signature.sign();

			// verify the proper signature
			signature.initVerify(keys.getPublicKey());
			signature.update(message);
			if (!signature.verify(sign)) {
				fail(info + ": verify failed!");
			}
			Asn1DerDecoder.checkEcDsaSignature(sign, keys.getPublicKey());

			// check the ghost signature with R := 0 and L := 0
			byte[] ghost = StringUtil.hex2ByteArray("3006020100020100");
			signature.initVerify(keys.getPublicKey());
			signature.update(message);
			boolean valid = signature.verify(ghost);
			if (valid) {
				broken = true;
				System.err.println(info + " is vulnerable for ECDSA R := 0, CVE-2022-21449!");
			} else {
				System.out.println(info + " is not vulnerable for ECDSA R := 0, CVE-2022-21449!");
			}
			try {
				Asn1DerDecoder.checkEcDsaSignature(ghost, keys.getPublicKey());
				fail("Failed to detect R := 0 ECDSA signature!");
			} catch (GeneralSecurityException ex) {
				assertThat(ex.getMessage(), is("ECDSA signature R is less than 1!"));
			}

			// check the ghost signature with R := N and L := N
			BigInteger order = ((ECPublicKey) keys.getPublicKey()).getParams().getOrder();
			byte[] number = order.toByteArray();
			if (number[0] < 0) {
				number = Bytes.concatenate(new byte[] { 0 }, number);
			}
			number = Bytes.concatenate(new byte[] { 0x02, (byte) number.length }, number);

			byte[] ghost2 = Bytes.concatenate(new byte[] { 0x30, (byte) (number.length * 2) }, number);
			ghost2 = Bytes.concatenate(ghost2, number);

			signature.initVerify(keys.getPublicKey());
			signature.update(message);
			try {
				valid = signature.verify(ghost2);
			} catch (SignatureException e) {
				System.out.println(info + ", possible: " + e.getMessage());
				valid = false;
			}
			if (valid) {
				broken = true;
				System.err.println(info + " is vulnerable for ECDSA R := N, CVE-2022-21449!");
			} else {
				System.out.println(info + " is not vulnerable for ECDSA R := N, CVE-2022-21449!");
			}
			try {
				Asn1DerDecoder.checkEcDsaSignature(ghost2, keys.getPublicKey());
				fail("failed to detect R := N ECDSA signature!");
			} catch (GeneralSecurityException ex) {
				assertThat(ex.getMessage(), is("ECDSA signature R is not less than N!"));
			}
			assertThat("detect broken ECDSA failed!", JceProviderUtil.isEcdsaVulnerable(), is(broken));
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
			fail("Failed with " + e);
		} catch (RuntimeException e) {
			e.printStackTrace();
			fail("Failed with " + e);
		}
	}

	/**
	 * Test, if decoder throws NoSuchAlgorithmException when reading EdDSA v2 private key.
	 */
	@Test
	public void testReadPrivateKeyEdDsaV2() throws IOException, GeneralSecurityException {
		assumeTrue("ED25519 requires JCE support!", JceProviderUtil.isSupported(JceNames.ED25519));
		byte[] data = Base64.decode(EDDSA_PRIVATE_KEY_V2_BASE64);
		Keys keys = Asn1DerDecoder.readPrivateKey(data);
		assertThat(keys, is(notNullValue()));
		assertThat(keys.getPrivateKey(), is(notNullValue()));
		assertThat(keys.getPublicKey(), is(notNullValue()));
		TestCertificatesTools.assertSigning("asn.1", keys.getPrivateKey(), keys.getPublicKey(), JceNames.ED25519);
	}

	/**
	 * Test, if decoder can read RSA public and private key algorithm.
	 */
	@Test
	public void testRsaKeyAlgorithmGenerated() throws IOException {
		assertKeyAlgorithmGenerated(JceNames.RSA);
	}

	/**
	 * Test, if decoder can read DSA public and private key algorithm.
	 */
	@Test
	public void testDsaKeyAlgorithmGenerated() throws IOException {
		assertKeyAlgorithmGenerated(JceNames.DSA);
	}

	/**
	 * Test, if decoder can read EC public and private key algorithm.
	 */
	@Test
	public void testEcKeyAlgorithmGenerated() throws IOException {
		assertKeyAlgorithmGenerated(JceNames.EC);
	}

	/**
	 * Test, if decoder can read DH public and private key algorithm.
	 */
	@Test
	public void testDHKeyAlgorithmGenerated() throws IOException {
		assertKeyAlgorithmGenerated(JceNames.DH);
	}

	/**
	 * Test, if decoder can read EC public and private key algorithm.
	 */
	@Test
	public void testEdDsaKeyAlgorithmGenerated() throws IOException {
		assumeTrue("ED25519 requires JCE support!", JceProviderUtil.isSupported(JceNames.ED25519));
		assertKeyAlgorithmGenerated(JceNames.ED25519);
	}

	private void assertKeyAlgorithmGenerated(String algorithm) throws IOException {
		try {
			KeyPairGenerator generator = Asn1DerDecoder.getKeyPairGenerator(algorithm);
			KeyPair keyPair = generator.generateKeyPair();
			byte[] data = keyPair.getPrivate().getEncoded();
			String keyAlgo = Asn1DerDecoder.readPrivateKeyAlgorithm(data);
			assertSynonym("reading private key algorithm failed!", true, keyAlgo, algorithm);
			data = keyPair.getPublic().getEncoded();
			keyAlgo = Asn1DerDecoder.readSubjectPublicKeyAlgorithm(data);
			assertSynonym("reading public key algorithm failed!", true, keyAlgo, algorithm);
		} catch (NoSuchAlgorithmException e) {
			assumeNoException("vm doesn't support " + algorithm + ": " + e.getMessage(), e);
		}
	}

	/**
	 * Assert, that the provided key algorithms are handled as synonyms.
	 * 
	 * @param message message header to fail
	 * @param expected {@code true}, if key algorithms should be valid synonyms,
	 *            {@code false}, otherwise.
	 * @param keyAlgorithm1 key algorithm
	 * @param keyAlgorithm2 key algorithm
	 */
	private void assertSynonym(String message, boolean expected, String keyAlgorithm1, String keyAlgorithm2) {
		if (expected != JceProviderUtil.equalKeyAlgorithmSynonyms(keyAlgorithm1, keyAlgorithm2)) {
			if (expected) {
				fail(message + " " + keyAlgorithm1 + " should be a valid synonym for " + keyAlgorithm2);
			} else {
				fail(message + " " + keyAlgorithm1 + " should not be a valid synonym for " + keyAlgorithm2);
			}
		}
	}

	/**
	 * Test, that an IllegalArgumentException is thrown, if input data is too
	 * short.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testViolatesMinimumEntityLength() {
		byte[] data = { 0x30 };
		DatagramReader reader = new DatagramReader(data);
		Asn1DerDecoder.readSequenceEntity(reader);
	}

	/**
	 * Test, that an IllegalArgumentException is thrown, if input data contains
	 * no sequence.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testNoSequence() {
		byte[] data = { 0x31, 0x01, 0x01 };
		DatagramReader reader = new DatagramReader(data);
		Asn1DerDecoder.readSequenceEntity(reader);
	}

	/**
	 * Test, that an IllegalArgumentException is thrown, if input data contains
	 * a too large length field.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testSequenceExceedsSupportedLengthBytes() {
		byte[] data = { 0x30, (byte) 0x85, 0x01, 0x01 };
		DatagramReader reader = new DatagramReader(data);
		Asn1DerDecoder.readSequenceEntity(reader);
	}

	/**
	 * Test, that an IllegalArgumentException is thrown, if input data contains
	 * a length, which exceeds the provided data.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testSequenceExceedsSupportedLength() {
		byte[] data = { 0x30, (byte) 0x83, 0x01, 0x01, 0x01 };
		DatagramReader reader = new DatagramReader(data);
		Asn1DerDecoder.readSequenceEntity(reader);
	}

	/**
	 * Test, that an IllegalArgumentException is thrown, if input data contains
	 * no OID.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testNoOid() {
		byte[] data = { 0x31, 0x01, 0x01 };
		DatagramReader reader = new DatagramReader(data);
		Asn1DerDecoder.readOidValue(reader);
	}

	/**
	 * Test, that an IllegalArgumentException is thrown, if input data contains
	 * a too large OID.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testOidExceedsSupportedLength() {
		byte[] data = { 0x30, 0x63, 0x01 };
		DatagramReader reader = new DatagramReader(data);
		Asn1DerDecoder.readOidValue(reader);
	}

	@Test
	public void testOidToString() {
		byte[] data1 = { 0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x03, 0x01, 0x07 };
		String oid1 = Asn1DerDecoder.readOidString(new DatagramReader(data1, false));
		assertThat(oid1, is("1.2.840.10045.3.1.7"));

		byte[] data2 = { 0x06, 0x07, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE, 0x3D, 0x02, 0x01 };
		String oid2 = Asn1DerDecoder.readOidString(new DatagramReader(data2, false));
		assertThat(oid2, is("1.2.840.10045.2.1"));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testInvalidOidToString() {
		byte[] data = { 0x06, 0x04, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE };
		Asn1DerDecoder.readOidString(new DatagramReader(data, false));
	}

	@Test
	public void testReadCNFromDN() {
		byte[] dn = StringUtil.base64ToByteArray(PRINCIPAL_BASE64);
		String cn = Asn1DerDecoder.readCNFromDN(dn);
		assertThat(cn, is("cf-server"));
		dn = StringUtil.base64ToByteArray(WILDCARD_PRINCIPAL_BASE64);
		cn = Asn1DerDecoder.readCNFromDN(dn);
		assertThat(cn, is("*.cf-server"));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testInvalidReadCNFromDN() {
		byte[] dn = StringUtil.base64ToByteArray(EC_BASE64);
		Asn1DerDecoder.readCNFromDN(dn);
	}

}
