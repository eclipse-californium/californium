/*******************************************************************************
 * Copyright (c) 2015, 2017 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - adapt to ClientHello changes
 *    Bosch Software Innovations GmbH - add test cases verifying conditional inclusion
 *                                      of extensions
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Tests verifying behavior of {@link ClientHello}.
 *
 */
@Category(Small.class)
public class ClientHelloTest {

	ClientHello clientHello;

	/**
	 * Verifies that the calculated message length is the same as the length
	 * of the serialized message.
	 */
	@Test
	public void testGetMessageLengthEqualsSerializedMessageLength() {
		givenAClientHelloWithEmptyExtensions();
		assertThat("ClientHello's anticipated message length does not match its real length",
				clientHello.getMessageLength(), is(clientHello.fragmentToByteArray().length));
	}

	/**
	 * Verifies that a ClientHello message does not contain point_format and elliptic_curves
	 * extensions if only non-ECC based cipher suites are supported.
	 */
	@Test
	public void testConstructorOmitsEccExtensionsForNonEccBasedCipherSuites() {

		givenAClientHello(
				Collections.singletonList(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256),
				SignatureAndHashAlgorithm.DEFAULT,
				Collections.<CertificateType> emptyList(),
				Collections.<CertificateType> emptyList(),
				Collections.singletonList(SupportedGroup.secp256r1));
		assertNull(
				"ClientHello should not contain elliptic_curves extension for non-ECC based cipher suites",
				clientHello.getSupportedEllipticCurvesExtension());
		assertNull(
				"ClientHello should not contain point_format extension for non-ECC based cipher suites",
				clientHello.getSupportedPointFormatsExtension());
	}

	/**
	 * Verifies that a ClientHello message contains point_format and elliptic_curves
	 * extensions if an ECC based cipher suite is supported.
	 */
	@Test
	public void testConstructorAddsEccExtensionsForEccBasedCipherSuites() {

		givenAClientHello(
				Collections.singletonList(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256),
				SignatureAndHashAlgorithm.DEFAULT,
				Collections.<CertificateType> emptyList(),
				Collections.<CertificateType> emptyList(),
				Collections.singletonList(SupportedGroup.secp256r1));
		assertNotNull(
				"ClientHello should contain elliptic_curves extension for ECC based cipher suites",
				clientHello.getSupportedEllipticCurvesExtension());
		assertNotNull(
				"ClientHello should contain point_format extension for ECC based cipher suites",
				clientHello.getSupportedPointFormatsExtension());
	}

	/**
	 * Verifies updating the Cookie for a ClientHello message.
	 * 
	 * Verifies, that for a ClientHello without a cookie in the message, with a
	 * cookie in the message and with extensions results in the same calculated
	 * cookie.
	 * 
	 * @throws GeneralSecurityException if calculating the cookie fails
	 */
	@Test
	public void testUpdateCookie() throws GeneralSecurityException {
		SecureRandom randomGenerator = new SecureRandom();

		givenAClientHelloWithEmptyExtensions();

		byte[] randomBytes = new byte[32];
		randomGenerator.nextBytes(randomBytes);
		SecretKey key = SecretUtil.create(randomBytes, "MAC");

		// no cookie, no extension
		Mac hmac = CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256.getThreadLocalMac();
		hmac.init(key);
		clientHello.updateForCookie(hmac);
		byte[] mac1 = hmac.doFinal();

		// with cookie, no extension
		randomGenerator.nextBytes(randomBytes);
		clientHello.setCookie(randomBytes);

		hmac.init(key);
		clientHello.updateForCookie(hmac);
		byte[] mac2 = hmac.doFinal();
		Assert.assertArrayEquals(mac1, mac2);

		// with cookie, with extension
		clientHello.addExtension(ExtendedMasterSecretExtension.INSTANCE);
		clientHello.fragmentChanged();

		hmac.init(key);
		clientHello.updateForCookie(hmac);
		mac2 = hmac.doFinal();
		Assert.assertArrayEquals(mac1, mac2);

		SecretUtil.destroy(key);
	}

	private void givenAClientHelloWithEmptyExtensions() {
		clientHello = new ClientHello(ProtocolVersion.VERSION_DTLS_1_2, 
				Collections.singletonList(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256),
				Collections.<SignatureAndHashAlgorithm> emptyList(),
				Collections.<CertificateType> emptyList(),
				Collections.<CertificateType> emptyList(),
				Collections.<SupportedGroup> emptyList());
		clientHello.addCompressionMethod(CompressionMethod.NULL);
	}

	private void givenAClientHello(List<CipherSuite> supportedCipherSuites,
			List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms,
			List<CertificateType> supportedClientCertTypes, List<CertificateType> supportedServerCertTypes,
			List<SupportedGroup> supportedGroups) {

		clientHello = createClientHello(supportedCipherSuites, supportedSignatureAndHashAlgorithms,
				supportedClientCertTypes, supportedServerCertTypes, supportedGroups);
	}

	public static ClientHello createClientHello(List<CipherSuite> supportedCipherSuites,
			List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms,
			List<CertificateType> supportedClientCertTypes, List<CertificateType> supportedServerCertTypes,
			List<SupportedGroup> supportedGroups) {

		return new ClientHello(ProtocolVersion.VERSION_DTLS_1_2, supportedCipherSuites, supportedSignatureAndHashAlgorithms,
				supportedClientCertTypes, supportedServerCertTypes, supportedGroups);
	}

}
