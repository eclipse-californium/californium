/*******************************************************************************
 * Copyright (c) 2015, 2017 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - adapt to ClientHello changes
 *    Bosch Software Innovations GmbH - add test cases verifying conditional inclusion
 *                                      of extensions
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Tests verifying behavior of {@link ClientHello}.
 *
 */
@Category(Small.class)
public class ClientHelloTest {

	ClientHello clientHello;
	InetSocketAddress peerAddress;

	/**
	 * Sets up fixture.
	 */
	@Before
	public void setUp() {
		peerAddress = new InetSocketAddress("localhost", 5684);
	}

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
				Collections.<CertificateType> emptyList(),
				Collections.<CertificateType> emptyList());
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
				Collections.<CertificateType> emptyList(),
				Collections.<CertificateType> emptyList());
		assertNotNull(
				"ClientHello should contain elliptic_curves extension for ECC based cipher suites",
				clientHello.getSupportedEllipticCurvesExtension());
		assertNotNull(
				"ClientHello should contain point_format extension for ECC based cipher suites",
				clientHello.getSupportedPointFormatsExtension());
	}

	private void givenAClientHelloWithEmptyExtensions() {
		clientHello = new ClientHello(new ProtocolVersion(), new SecureRandom(), Collections.<CipherSuite> emptyList(),
				null, null, peerAddress);
	}

	private void givenAClientHello(
			List<CipherSuite> supportedCipherSuites,
			List<CertificateType> supportedClientCertTypes,
			List<CertificateType> supportedServerCertTypes) {

		clientHello = new ClientHello(new ProtocolVersion(), new SecureRandom(), supportedCipherSuites, null, null,
				peerAddress);
	}
	
}
