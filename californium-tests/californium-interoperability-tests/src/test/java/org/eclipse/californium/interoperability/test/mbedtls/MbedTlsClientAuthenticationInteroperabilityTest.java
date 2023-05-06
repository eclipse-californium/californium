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
import static org.eclipse.californium.interoperability.test.CredentialslUtil.CLIENT_RSA_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.ProcessUtil.TIMEOUT_MILLIS;
import static org.eclipse.californium.interoperability.test.mbedtls.MbedTlsProcessUtil.AuthenticationMode.CHAIN;
import static org.eclipse.californium.interoperability.test.mbedtls.MbedTlsProcessUtil.AuthenticationMode.TRUST;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

import org.eclipse.californium.elements.config.CertificateAuthenticationMode;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.JceNames;
import org.eclipse.californium.elements.util.JceProviderUtil;
import org.eclipse.californium.interoperability.test.ConnectorUtil;
import org.eclipse.californium.interoperability.test.ScandiumUtil;
import org.eclipse.californium.interoperability.test.ShutdownUtil;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
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
public class MbedTlsClientAuthenticationInteroperabilityTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final InetSocketAddress BIND = new InetSocketAddress(InetAddress.getLoopbackAddress(),
			ScandiumUtil.PORT);
	private static final String DESTINATION = "127.0.0.1";

	private static MbedTlsProcessUtil processUtil;
	private static ScandiumUtil scandiumUtil;
	private static CipherSuite cipherSuite;

	@BeforeClass
	public static void init() throws IOException, InterruptedException {
		processUtil = new MbedTlsProcessUtil();
		processUtil.assumeMinVersion("3.2.");
		scandiumUtil = new ScandiumUtil(false);
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
	public void testMbedTlsClientChainTrustAll() throws Exception {
		scandiumUtil.start(BIND, null, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, ScandiumUtil.PORT, CHAIN, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testMbedTlsClientTrustTrustAll() throws Exception {
		scandiumUtil.start(BIND, null, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, ScandiumUtil.PORT, TRUST, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testMbedTlsClientChainTrustCa() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_CA, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, ScandiumUtil.PORT, CHAIN, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testMbedTlsClientTrustTrustCa() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_CA, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, ScandiumUtil.PORT, TRUST, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testMbedTlsClientChainTrustRoot() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, ScandiumUtil.PORT, CHAIN, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testMbedTlsClientTrustTrustRoot() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, ScandiumUtil.PORT, TRUST, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testMbedTlsClientUnauthenticated() throws Exception {
		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);

		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, ScandiumUtil.PORT, TRUST, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testMbedTlsClientX25519() throws Exception {
		assumeTrue("X25519 not support by JCE", XECDHECryptography.SupportedGroup.X25519.isUsable());
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);
		processUtil.setVerboseLevel("2");
		String cipher = processUtil.startupClient(DESTINATION, ScandiumUtil.PORT, TRUST, "x25519,secp256r1",
				cipherSuite);
		connect(cipher, "ECDH curve: x25519");
	}

	@Test
	public void testMbedTlsClientX448() throws Exception {
		assumeTrue("X448 not support by JCE", XECDHECryptography.SupportedGroup.X448.isUsable());
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);
		processUtil.setVerboseLevel("2");
		String cipher = processUtil.startupClient(DESTINATION, ScandiumUtil.PORT, TRUST, "x448,secp256r1", cipherSuite);
		connect(cipher, "ECDH curve: x448");
	}

	@Test
	public void testMbedTlsClientPrime256v1() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);
		processUtil.setVerboseLevel("2");
		String cipher = processUtil.startupClient(DESTINATION, ScandiumUtil.PORT, TRUST, "secp256r1", cipherSuite);
		connect(cipher, "ECDH curve: secp256r1");
	}

	@Test
	public void testMbedTlsClientSecP384r1() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);
		processUtil.setVerboseLevel("2");
		String cipher = processUtil.startupClient(DESTINATION, ScandiumUtil.PORT, TRUST, "secp384r1,secp256r1",
				cipherSuite);
		connect(cipher, "ECDH curve: secp384r1");
	}

	@Test
	public void testMbedTlsClientMixedCertificatChain() throws Exception {
		scandiumUtil.loadCredentials(ConnectorUtil.SERVER_CA_RSA_NAME);
		scandiumUtil.start(BIND, null, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, ScandiumUtil.PORT, TRUST,
				MbedTlsProcessUtil.DEFAULT_CURVES, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testMbedTlsClientRsaCertificatChain() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.isSupported()
				? CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
				: CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
		assumeTrue(cipherSuite.name() + " not support by JCE", cipherSuite.isSupported());
		scandiumUtil.loadCredentials(ConnectorUtil.SERVER_RSA_NAME);
		scandiumUtil.start(BIND, null, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, ScandiumUtil.PORT, TRUST,
				MbedTlsProcessUtil.DEFAULT_CURVES, CLIENT_RSA_CERTIFICATE, cipherSuite);
		connect(cipher);
	}

	/**
	 * Mbed TLS 3.1.0 doesn't support Ed25519.
	 * 
	 * @throws Exception if an error occurs
	 */
	@Test
	@Ignore
	public void testMbedTlsClientEdDsaCertificatChain() throws Exception {
		assumeTrue("X25519 not support by JCE", XECDHECryptography.SupportedGroup.X25519.isUsable());
		assumeTrue("Ed25519 not support by JCE", JceProviderUtil.isSupported(JceNames.ED25519));
		assumeTrue("Ed25519 certificate missing", new File("clientEdDsa.pem").exists());

		List<SignatureAndHashAlgorithm> defaults = new ArrayList<>(SignatureAndHashAlgorithm.DEFAULT);
		defaults.add(SignatureAndHashAlgorithm.INTRINSIC_WITH_ED25519);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.set(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, defaults);
		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, ScandiumUtil.PORT, TRUST, "x25519,secp256r1",
				"clientEdDsa.pem", cipherSuite);
		connect(cipher);
	}

	public void connect(String cipher, String... misc) throws Exception {
		assertTrue("handshake failed!", processUtil.waitConsole("Ciphersuite is ", HANDSHAKE_TIMEOUT_MILLIS));
		assertTrue("wrong cipher suite!", processUtil.waitConsole("Ciphersuite is " + cipher, TIMEOUT_MILLIS));
		if (misc != null) {
			for (String check : misc) {
				assertTrue("missing " + check, processUtil.waitConsole(check, TIMEOUT_MILLIS));
			}
		}

		String message = "Hello Scandium!";

		// Mbed TLS client sends a HTTP GET request, even in DTLS mode
		scandiumUtil.assertContainsReceivedData("GET / HTTP/1.0", TIMEOUT_MILLIS);
		scandiumUtil.response("ACK-" + message, TIMEOUT_MILLIS);

		assertTrue("mbedTls is missing ACK!", processUtil.waitConsole("ACK-" + message, TIMEOUT_MILLIS));

		processUtil.stop(TIMEOUT_MILLIS);
	}
}
