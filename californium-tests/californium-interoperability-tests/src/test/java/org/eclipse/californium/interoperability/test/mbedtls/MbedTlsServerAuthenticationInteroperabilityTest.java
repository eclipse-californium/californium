/*******************************************************************************
 * Copyright (c) 2022 Bosch IO GmbH and others.
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
 *    Bosch.IO GmbH - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.interoperability.test.mbedtls;

import static org.eclipse.californium.interoperability.test.ConnectorUtil.HANDSHAKE_TIMEOUT_MILLIS;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.SERVER_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.SERVER_RSA_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.SERVER_CA_RSA_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.ProcessUtil.TIMEOUT_MILLIS;
import static org.eclipse.californium.interoperability.test.mbedtls.MbedTlsProcessUtil.AuthenticationMode.PSK;
import static org.eclipse.californium.interoperability.test.mbedtls.MbedTlsProcessUtil.AuthenticationMode.CHAIN;
import static org.eclipse.californium.interoperability.test.mbedtls.MbedTlsProcessUtil.AuthenticationMode.TRUST;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.interoperability.test.ConnectorUtil;
import org.eclipse.californium.interoperability.test.ScandiumUtil;
import org.eclipse.californium.interoperability.test.ShutdownUtil;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

/**
 * Test for interoperability with Mbed TLS .
 * 
 * Test several authentication modes.
 * 
 * @see MbedTlsUtil
 * @since 3.3
 */
public class MbedTlsServerAuthenticationInteroperabilityTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final InetSocketAddress BIND = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
	private static final InetSocketAddress DESTINATION = new InetSocketAddress(InetAddress.getLoopbackAddress(),
			ScandiumUtil.PORT);
	private static final String ACCEPT = "127.0.0.1";

	private static MbedTlsProcessUtil processUtil;
	private static ScandiumUtil scandiumUtil;
	private static CipherSuite cipherSuite;

	@BeforeClass
	public static void init() throws IOException, InterruptedException {
		processUtil = new MbedTlsProcessUtil();
		processUtil.assumeMinVersion("3.2.");
		scandiumUtil = new ScandiumUtil(true);
		cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
	}

	@AfterClass
	public static void shutdown() throws InterruptedException {
		ShutdownUtil.shutdown(scandiumUtil, processUtil);
	}

	@Before
	public void start() {
		processUtil.setTag(name.getName());
	}

	@After
	public void stop() throws InterruptedException {
		ShutdownUtil.shutdown(scandiumUtil, processUtil);
	}

	@Test
	public void testMbedTlsServerPsk() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		String cipher = processUtil.startupServer(ACCEPT, ScandiumUtil.PORT, PSK, cipherSuite);

		scandiumUtil.start(BIND, null, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testMbedTlsServerChainTrustAll() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, ScandiumUtil.PORT, CHAIN, cipherSuite);

		scandiumUtil.start(BIND, null, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testMbedTlsServerTrustTrustAll() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, ScandiumUtil.PORT, TRUST, cipherSuite);

		scandiumUtil.start(BIND, null, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testMbedTlsServerFullTrustTrustAll() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, ScandiumUtil.PORT, TRUST, cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.set(DtlsConfig.DTLS_TRUNCATE_CLIENT_CERTIFICATE_PATH, false);
		scandiumUtil.start(BIND, dtlsBuilder, null, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testMbedTlsServerChainTrustCa() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, ScandiumUtil.PORT, CHAIN, cipherSuite);

		scandiumUtil.start(BIND, ScandiumUtil.TRUST_CA, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testMbedTlsServerTrustTrustCa() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, ScandiumUtil.PORT, TRUST, cipherSuite);

		scandiumUtil.start(BIND, ScandiumUtil.TRUST_CA, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testMbedTlsServerChainTrustRoot() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, ScandiumUtil.PORT, CHAIN, cipherSuite);

		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testMbedTlsServerTrustTrustRoot() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, ScandiumUtil.PORT, TRUST, cipherSuite);

		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testMbedTlsServerX25519() throws Exception {
		assumeTrue("X25519 not support by JCE", XECDHECryptography.SupportedGroup.X25519.isUsable());
		processUtil.setVerboseLevel("2");
		String cipher = processUtil.startupServer(ACCEPT, ScandiumUtil.PORT, TRUST, cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.setAsList(DtlsConfig.DTLS_CURVES, SupportedGroup.X25519, SupportedGroup.secp256r1);

		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(cipher, "ECDHE curve: x25519");
	}

	@Test
	public void testMbedTlsServerX448() throws Exception {
		assumeTrue("X448 not support by JCE", XECDHECryptography.SupportedGroup.X448.isUsable());
		processUtil.setVerboseLevel("2");
		String cipher = processUtil.startupServer(ACCEPT, ScandiumUtil.PORT, TRUST, SERVER_CERTIFICATE, "x448,secp256r1", cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.setAsList(DtlsConfig.DTLS_CURVES, SupportedGroup.X448, SupportedGroup.secp256r1);

		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(cipher, "ECDHE curve: x448");
	}

	@Test
	public void testMbedTlsServerPrime256v1() throws Exception {
		processUtil.setVerboseLevel("2");
		String cipher = processUtil.startupServer(ACCEPT, ScandiumUtil.PORT, TRUST, cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.setAsList(DtlsConfig.DTLS_CURVES, SupportedGroup.secp256r1);

		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(cipher, "ECDHE curve: secp256r1");
	}

	@Test
	public void testMbedTlsServerSecP384r1() throws Exception {
		processUtil.setVerboseLevel("2");
		String cipher = processUtil.startupServer(ACCEPT, ScandiumUtil.PORT, TRUST, SERVER_CERTIFICATE, "secp384r1,secp256r1", cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.setAsList(DtlsConfig.DTLS_CURVES, SupportedGroup.secp384r1, SupportedGroup.secp256r1);

		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(cipher, "ECDHE curve: secp384r1");
	}

	@Test
	public void testMbedTlsServerBrainpoolP384r1() throws Exception {
		assumeTrue("BrainpoolP384r1 not support by JCE", XECDHECryptography.SupportedGroup.brainpoolP384r1.isUsable());
		processUtil.setVerboseLevel("2");
		String cipher = processUtil.startupServer(ACCEPT, ScandiumUtil.PORT, TRUST, SERVER_CERTIFICATE, "brainpoolP384r1,secp256r1", 
				cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.set(DtlsConfig.DTLS_RECOMMENDED_CURVES_ONLY, false)
				.setAsList(DtlsConfig.DTLS_CURVES, SupportedGroup.brainpoolP384r1, SupportedGroup.secp256r1)
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, SignatureAndHashAlgorithm.SHA384_WITH_ECDSA,
						SignatureAndHashAlgorithm.SHA256_WITH_ECDSA);

		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(cipher, "ECDHE curve: brainpoolP384r1");
	}

	@Test
	public void testMbedTlsServerRsaTrustTrustRoot() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, ScandiumUtil.PORT, TRUST, SERVER_CA_RSA_CERTIFICATE,
				MbedTlsProcessUtil.DEFAULT_CURVES, cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA,
						SignatureAndHashAlgorithm.SHA256_WITH_RSA);
		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testMbedTlsServerRsaChainTrustRoot() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, ScandiumUtil.PORT, CHAIN, SERVER_CA_RSA_CERTIFICATE, null, cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA,
						SignatureAndHashAlgorithm.SHA256_WITH_RSA);
		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testMbedTlsServerRsaTrustRoot() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.isSupported()
				? CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
				: CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
		assumeTrue(cipherSuite.name() + " not support by JCE", cipherSuite.isSupported());
		String cipher = processUtil.startupServer(ACCEPT, ScandiumUtil.PORT,  CHAIN, SERVER_RSA_CERTIFICATE, null, cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA,
						SignatureAndHashAlgorithm.SHA256_WITH_RSA);
		scandiumUtil.loadCredentials(ConnectorUtil.CLIENT_RSA_NAME);
		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(cipher);
	}

	public void connect(String cipher, String... misc) throws Exception {
		String message = "Hello OpenSSL!";
		scandiumUtil.send(message, DESTINATION, HANDSHAKE_TIMEOUT_MILLIS);

		assertTrue("handshake failed!", processUtil.waitConsole("Ciphersuite is ", TIMEOUT_MILLIS));
		assertTrue("wrong cipher suite!", processUtil.waitConsole("Ciphersuite is " + cipher, TIMEOUT_MILLIS));
		if (misc != null) {
			for (String check : misc) {
				assertTrue("missing " + check, processUtil.waitConsole(check, TIMEOUT_MILLIS));
			}
		}
		assertTrue("openssl missing message!", processUtil.waitConsole(message, TIMEOUT_MILLIS));
		processUtil.send("ACK-" + message);

		scandiumUtil.assertContainsReceivedData("HTTP/1.0 200 OK", TIMEOUT_MILLIS);

		processUtil.stop(200);
	}
}
