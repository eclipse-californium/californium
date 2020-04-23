/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.interoperability.test;

import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeNotNull;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.interoperability.test.OpenSslUtil.AuthenticationMode;
import org.eclipse.californium.interoperability.test.ProcessUtil.ProcessResult;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

/**
 * Test for interoperability with openssl client.
 * 
 * Test several authentication modes.
 *  
 * @see OpenSslUtil
 */
public class OpenSslClientAuthenticationInteroperabilityTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final InetSocketAddress BIND = new InetSocketAddress(InetAddress.getLoopbackAddress(),
			ScandiumUtil.PORT);
	private static final String DESTINATION = "127.0.0.1:" + ScandiumUtil.PORT;
	private static final long TIMEOUT_MILLIS = 2000;

	private static OpenSslProcessUtil processUtil;
	private static ScandiumUtil scandiumUtil;
	private static CipherSuite cipherSuite;

	@BeforeClass
	public static void init() throws IOException, InterruptedException {
		processUtil = new OpenSslProcessUtil();
		ProcessResult result = processUtil.getOpenSslVersion(TIMEOUT_MILLIS);
		assumeNotNull(result);
		assumeTrue(result.contains("OpenSSL 1\\.1\\."));
		scandiumUtil = new ScandiumUtil(false);
		cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
	}

	@AfterClass
	public static void shutdown() throws InterruptedException {
		if (scandiumUtil != null) {
			scandiumUtil.shutdown();
			scandiumUtil = null;
		}
		if (processUtil != null) {
			processUtil.shutdown();
		}
	}

	@After
	public void stop() throws InterruptedException {
		if (scandiumUtil != null) {
			scandiumUtil.shutdown();
		}
		processUtil.shutdown();
	}

	@Test
	public void testOpenSslClientCertTrustAll() throws Exception {
		scandiumUtil.start(BIND, null, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, AuthenticationMode.CERTIFICATE, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientChainTrustAll() throws Exception {
		scandiumUtil.start(BIND, null, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, AuthenticationMode.CHAIN, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientTrustTrustAll() throws Exception {
		scandiumUtil.start(BIND, null, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, AuthenticationMode.TRUST, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientCertTrustCa() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_CA, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, AuthenticationMode.CERTIFICATE, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientChainTrustCa() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_CA, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, AuthenticationMode.CHAIN, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientTrustTrustCa() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_CA, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, AuthenticationMode.TRUST, cipherSuite);
		connect(cipher);
	}

	@Test
	@Ignore // certificate not trusted by root 
	public void testOpenSslClientCertTrustRoot() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, AuthenticationMode.CERTIFICATE, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientChainTrustRoot() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, AuthenticationMode.CHAIN, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientTrustTrustRoot() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, AuthenticationMode.TRUST, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientUnauthenticated() throws Exception {
		DtlsConnectorConfig.Builder dtlsBuilder = new DtlsConnectorConfig.Builder();
		dtlsBuilder.setClientAuthenticationRequired(false);
		
		scandiumUtil.start(BIND, false, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);


		String cipher = processUtil.startupClient(DESTINATION, AuthenticationMode.TRUST, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientX25519() throws Exception {
		assumeTrue("X25519 not support by JRE", XECDHECryptography.SupportedGroup.X25519.isUsable());
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, AuthenticationMode.TRUST, "X25519:prime256v1", null, cipherSuite);
		connect(cipher, "X25519");
	}

	@Test
	public void testOpenSslClientX448() throws Exception {
		assumeTrue("X448 not support by JRE", XECDHECryptography.SupportedGroup.X448.isUsable());
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, AuthenticationMode.TRUST, "X448:prime256v1", null, cipherSuite);
		connect(cipher, "X448");
	}

	@Test
	public void testOpenSslClientPrime256v1() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, AuthenticationMode.TRUST, "prime256v1", null, cipherSuite);
		connect(cipher, "ECDH, P-256");
	}

	@Test
	public void testOpenSslClientSecP384r1() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, AuthenticationMode.TRUST, "secp384r1:prime256v1", null, cipherSuite);
		connect(cipher, "ECDH, P-384");
	}

	@Test
	public void testOpenSslClientMixedCertificatChain() throws Exception {
		scandiumUtil.start(BIND, true, null, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, AuthenticationMode.TRUST, OpenSslProcessUtil.DEFAULT_CURVES,
				OpenSslProcessUtil.DEFAULT_SIGALGS, cipherSuite);
		connect(cipher);
	}

	public void connect(String cipher, String... misc) throws Exception {
		assertTrue(processUtil.waitConsole("Cipher is " + cipher, TIMEOUT_MILLIS));
		if (misc != null) {
			for (String check : misc) {
				assertTrue(processUtil.waitConsole(check, TIMEOUT_MILLIS));
			}
		}

		String message = "Hello Scandium!";
		processUtil.send(message);

		scandiumUtil.assertReceivedData(message, TIMEOUT_MILLIS);
		scandiumUtil.response("ACK-" + message, TIMEOUT_MILLIS);

		assertTrue("openssl is missing ACK!", processUtil.waitConsole("ACK-" + message, TIMEOUT_MILLIS));

		processUtil.stop(TIMEOUT_MILLIS);
	}
}
