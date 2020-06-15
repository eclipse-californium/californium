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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;

import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.rule.TestTimeRule;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.scandium.CookieGenerator;
import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Tests verifying behavior of {@link CookieGenerator}.
 *
 */
@Category(Small.class)
public class CookieGeneratorTest {

	@Rule
	public TestTimeRule time = new TestTimeRule();

	CookieGenerator generator;
	InetSocketAddress peerAddress;
	InetSocketAddress peerAddress2;

	/**
	 * Sets up fixture.
	 */
	@Before
	public void setUp() {
		peerAddress = new InetSocketAddress("localhost", 5684);
		peerAddress2 = new InetSocketAddress("localhost", 5685);
		generator = new CookieGenerator();
	}

	@Test
	public void testCookieGeneratorGeneratesSameCookie() throws GeneralSecurityException {
		ClientHello clientHello = ClientHelloTest.createClientHello(peerAddress,
				Collections.singletonList(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256),
				SignatureAndHashAlgorithm.DEFAULT, Collections.<CertificateType> emptyList(),
				Collections.<CertificateType> emptyList(), Collections.singletonList(SupportedGroup.secp256r1));
		byte[] cookie1 = generator.generateCookie(clientHello);

		clientHello.setCookie(cookie1);

		byte[] cookie2 = generator.generateCookie(clientHello);
		assertArrayEquals(cookie1, cookie2);
	}

	@Test
	public void testCookieGeneratorGeneratesDifferentCookie() throws GeneralSecurityException, HandshakeException {
		ClientHello clientHello1 = ClientHelloTest.createClientHello(peerAddress,
				Collections.singletonList(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256),
				SignatureAndHashAlgorithm.DEFAULT, Collections.<CertificateType> emptyList(),
				Collections.<CertificateType> emptyList(), Collections.singletonList(SupportedGroup.secp256r1));
		byte[] cookie1 = generator.generateCookie(clientHello1);
		byte[] byteArray = clientHello1.fragmentToByteArray();
		ClientHello clientHello2 = ClientHello.fromReader(new DatagramReader(byteArray), peerAddress);
		clientHello2.setCookie(cookie1);

		byte[] cookie2 = generator.generateCookie(clientHello2);
		assertArrayEquals(cookie1, cookie2);

		ClientHello clientHello3 = ClientHello.fromReader(new DatagramReader(byteArray), peerAddress2);
		clientHello3.setCookie(cookie1);

		byte[] cookie3 = generator.generateCookie(clientHello3);
		assertFalse("byte arrays are equal!", Arrays.equals(cookie1, cookie3));
	}

	@Test
	public void testCookieGeneratorGeneratesDifferentCookieWhenPeriodExpires()
			throws GeneralSecurityException, HandshakeException {
		ClientHello clientHello1 = ClientHelloTest.createClientHello(peerAddress,
				Collections.singletonList(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256),
				SignatureAndHashAlgorithm.DEFAULT, Collections.<CertificateType> emptyList(),
				Collections.<CertificateType> emptyList(), Collections.singletonList(SupportedGroup.secp256r1));
		byte[] cookie1 = generator.generateCookie(clientHello1);
		time.addTestTimeShift(CookieGenerator.COOKIE_LIFE_TIME + 1000, TimeUnit.NANOSECONDS);
		byte[] cookie2 = generator.generateCookie(clientHello1);
		byte[] cookie3 = generator.generatePastCookie(clientHello1);

		assertFalse("byte arrays are equal!", Arrays.equals(cookie1, cookie2));
		assertArrayEquals(cookie1, cookie3);
	}
}
