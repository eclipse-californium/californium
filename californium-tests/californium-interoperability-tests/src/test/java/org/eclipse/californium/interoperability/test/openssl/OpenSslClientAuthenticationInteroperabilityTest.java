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
package org.eclipse.californium.interoperability.test.openssl;

import static org.eclipse.californium.interoperability.test.ConnectorUtil.HANDSHAKE_TIMEOUT_MILLIS;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.CLIENT_EDDSA_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.CLIENT_RSA_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.ProcessUtil.TIMEOUT_MILLIS;
import static org.eclipse.californium.interoperability.test.ProcessUtil.FOLLOW_UP_TIMEOUT_MILLIS;
import static org.eclipse.californium.interoperability.test.openssl.OpenSslProcessUtil.DEFAULT_CURVES;
import static org.eclipse.californium.interoperability.test.openssl.OpenSslProcessUtil.DEFAULT_EDDSA_SIGALGS;
import static org.eclipse.californium.interoperability.test.openssl.OpenSslProcessUtil.AuthenticationMode.CERTIFICATE;
import static org.eclipse.californium.interoperability.test.openssl.OpenSslProcessUtil.AuthenticationMode.CHAIN;
import static org.eclipse.californium.interoperability.test.openssl.OpenSslProcessUtil.AuthenticationMode.TRUST;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;

import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.config.CertificateAuthenticationMode;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.JceNames;
import org.eclipse.californium.elements.util.JceProviderUtil;
import org.eclipse.californium.elements.util.StandardCharsets;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.interoperability.test.ConnectorUtil;
import org.eclipse.californium.interoperability.test.ProcessUtil.ProcessResult;
import org.eclipse.californium.interoperability.test.ScandiumUtil;
import org.eclipse.californium.interoperability.test.ShutdownUtil;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.DTLSContext;
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

	private static OpenSslProcessUtil processUtil;
	private static ScandiumUtil scandiumUtil;
	private static CipherSuite cipherSuite;

	@BeforeClass
	public static void init() throws IOException, InterruptedException {
		processUtil = new OpenSslProcessUtil();
		processUtil.assumeMinVersion("1.1.");
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
	public void testOpenSslClientCertTrustAll() throws Exception {
		scandiumUtil.start(BIND, null, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, CERTIFICATE, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientChainTrustAll() throws Exception {
		scandiumUtil.start(BIND, null, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, CHAIN, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientTrustTrustAll() throws Exception {
		scandiumUtil.start(BIND, null, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, TRUST, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientCertTrustCa() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_CA, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, CERTIFICATE, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientChainTrustCa() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_CA, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, CHAIN, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientTrustTrustCa() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_CA, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, TRUST, cipherSuite);
		connect(cipher);
	}

	@Test
	@Ignore // certificate not trusted by root
	public void testOpenSslClientCertTrustRoot() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, CERTIFICATE, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientChainTrustRoot() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, CHAIN, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientTrustTrustRoot() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, TRUST, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientBothRawPublicKey() throws Exception {
		processUtil.assumeMinVersion("3.2.");
		processUtil.addExtraArgs("-enable_server_rpk", "-enable_client_rpk");
		scandiumUtil.start(BIND, null, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, CERTIFICATE, cipherSuite);
		connect(cipher, "Server raw public key");
		scandiumUtil.assertPrincipalType(HANDSHAKE_TIMEOUT_MILLIS, RawPublicKeyIdentity.class);
	}

	@Test
	public void testOpenSslClientClientRawPublicKey() throws Exception {
		processUtil.assumeMinVersion("3.2.");
		processUtil.addExtraArgs("-enable_client_rpk");
		scandiumUtil.start(BIND, null, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, CERTIFICATE, cipherSuite);
		connect(cipher, "Server certificate");
		scandiumUtil.assertPrincipalType(HANDSHAKE_TIMEOUT_MILLIS, RawPublicKeyIdentity.class);
	}

	@Test
	public void testOpenSslClientServerRawPublicKey() throws Exception {
		processUtil.assumeMinVersion("3.2.");
		processUtil.addExtraArgs("-enable_server_rpk");
		scandiumUtil.start(BIND, null, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, CERTIFICATE, cipherSuite);
		connect(cipher, "Server raw public key");
		scandiumUtil.assertPrincipalType(HANDSHAKE_TIMEOUT_MILLIS, X509CertPath.class);
	}

	@Test
	public void testOpenSslClientBothRawPublicKeyEd25519() throws Exception {
		assumeTrue("X25519 not support by JCE", XECDHECryptography.SupportedGroup.X25519.isUsable());
		processUtil.assumeMinVersion("3.2.");
		processUtil.addExtraArgs("-enable_server_rpk", "-enable_client_rpk");
		scandiumUtil.loadEdDsaCredentials(ConnectorUtil.SERVER_EDDSA_NAME);
		scandiumUtil.start(BIND, null, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, CERTIFICATE, DEFAULT_CURVES, DEFAULT_EDDSA_SIGALGS,
				CLIENT_EDDSA_CERTIFICATE, cipherSuite);
		connect(cipher, "Server raw public key", "X25519");
		scandiumUtil.assertPrincipalType(HANDSHAKE_TIMEOUT_MILLIS, RawPublicKeyIdentity.class);
	}

	@Test
	public void testOpenSslClientBothRawPublicKeyEmptyCertificate() throws Exception {
		processUtil.assumeMinVersion("3.2.");
		processUtil.addExtraArgs("-enable_server_rpk", "-enable_client_rpk");
		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
				.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.WANTED);
		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, CERTIFICATE, DEFAULT_CURVES, null,
				CLIENT_RSA_CERTIFICATE, cipherSuite);
		connect(cipher, "Server raw public key");
		scandiumUtil.assertPrincipalType(HANDSHAKE_TIMEOUT_MILLIS, null);
	}

	@Test
	public void testOpenSslClientBothRawPublicKeyClientUnauthenticated() throws Exception {
		processUtil.assumeMinVersion("3.2.");
		processUtil.addExtraArgs("-enable_server_rpk", "-enable_client_rpk");
		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);

		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, CERTIFICATE, cipherSuite);
		connect(cipher, "Server raw public key");
		scandiumUtil.assertPrincipalType(HANDSHAKE_TIMEOUT_MILLIS, null);
	}

	@Test
	public void testOpenSslClientUnauthenticated() throws Exception {
		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);

		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, TRUST, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientEd25519() throws Exception {
		assumeTrue("X25519 not support by JCE", XECDHECryptography.SupportedGroup.X25519.isUsable());
		scandiumUtil.loadEdDsaCredentials(ConnectorUtil.SERVER_EDDSA_NAME);
		scandiumUtil.start(BIND, null, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, CERTIFICATE, DEFAULT_CURVES, DEFAULT_EDDSA_SIGALGS,
				CLIENT_EDDSA_CERTIFICATE, cipherSuite);
		connect(cipher, "X25519");
	}

	@Test
	public void testOpenSslClientX25519() throws Exception {
		assumeTrue("X25519 not support by JCE", XECDHECryptography.SupportedGroup.X25519.isUsable());
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, TRUST, DEFAULT_CURVES, null, cipherSuite);
		connect(cipher, "X25519");
	}

	@Test
	public void testOpenSslClientX448() throws Exception {
		assumeTrue("X448 not support by JCE", XECDHECryptography.SupportedGroup.X448.isUsable());
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, TRUST, "X448:prime256v1", null, cipherSuite);
		connect(cipher, "X448");
	}

	@Test
	public void testOpenSslClientPrime256v1() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, TRUST, "prime256v1", null, cipherSuite);
		connect(cipher, "ECDH, (P-256|prime256v1),");
	}

	@Test
	public void testOpenSslClientSecP384r1() throws Exception {
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, TRUST, "secp384r1:prime256v1", null, cipherSuite);
		connect(cipher, "ECDH, (P-384|secp384r1),");
	}

	@Test
	public void testOpenSslClientMixedCertificatChain() throws Exception {
		scandiumUtil.loadCredentials(ConnectorUtil.SERVER_CA_RSA_NAME);
		scandiumUtil.start(BIND, null, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, TRUST, OpenSslProcessUtil.DEFAULT_CURVES,
				OpenSslProcessUtil.DEFAULT_SIGALGS, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientRsaCertificatChain() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.isSupported()
				? CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
				: CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
		assumeTrue(cipherSuite.name() + " not support by JCE", cipherSuite.isSupported());
		scandiumUtil.loadCredentials(ConnectorUtil.SERVER_RSA_NAME);
		scandiumUtil.start(BIND, null, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, TRUST, OpenSslProcessUtil.DEFAULT_CURVES,
				OpenSslProcessUtil.DEFAULT_SIGALGS, CLIENT_RSA_CERTIFICATE, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientEdDsaCertificatChain() throws Exception {
		assumeTrue("X25519 not support by JCE", XECDHECryptography.SupportedGroup.X25519.isUsable());
		assumeTrue("Ed25519 not support by JCE", JceProviderUtil.isSupported(JceNames.ED25519));
		assumeTrue("Ed25519 certificate missing", new File("clientEdDsa.pem").exists());

		List<SignatureAndHashAlgorithm> defaults = new ArrayList<>(SignatureAndHashAlgorithm.DEFAULT);
		defaults.add(SignatureAndHashAlgorithm.INTRINSIC_WITH_ED25519);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.set(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, defaults);
		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, TRUST, DEFAULT_CURVES, "ed25519:ECDSA+SHA256",
				"clientEdDsa.pem", cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientUnauthenticatedResumes() throws Exception {
		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);

		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);

		processUtil.addExtraArgs("-sess_out", "sess.pem", "-no_ticket");
		String cipher = processUtil.startupClient(DESTINATION, TRUST, cipherSuite);
		connect(cipher);

		processUtil.addExtraArgs("-sess_in", "sess.pem", "-no_ticket");
		cipher = processUtil.startupClient(DESTINATION, TRUST, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientUnauthenticatedFullhandshake() throws Exception {
		CipherSuite cipherSuite2 = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM;
		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);

		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite, cipherSuite2);

		processUtil.addExtraArgs("-sess_out", "sess.pem", "-no_ticket");
		String cipher = processUtil.startupClient(DESTINATION, TRUST, cipherSuite);
		connect(cipher);

		processUtil.addExtraArgs("-sess_in", "sess.pem", "-no_ticket");
		cipher = processUtil.startupClient(DESTINATION, TRUST, cipherSuite2);
		connect(cipher);
	}

	@Test
	public void testOpenSslClientExportKeyMaterial() throws Exception {
		String exportLabel = "EXPERIMENTAL_TEST";

		processUtil.addExtraArgs("-keymatexport", exportLabel);
		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.set(DtlsConfig.DTLS_SUPPORT_KEY_MATERIAL_EXPORT, true);

		scandiumUtil.start(BIND, dtlsBuilder, null, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, CERTIFICATE, cipherSuite);

		ProcessResult result = connect(cipher);
		assertNotNull("missing openssl result", result);
		Matcher match = result.match("Keying material: ([\\dABCDEFabcdef]+)");
		assertNotNull("missing keying material", match);
		String opensslMaterial = match.group(1);
		DTLSContext dtlsContext = scandiumUtil.getDTLSContext(TIMEOUT_MILLIS);
		assertNotNull("missing DTLS context", dtlsContext);
		byte[] keyMaterial = dtlsContext.exportKeyMaterial(exportLabel.getBytes(StandardCharsets.UTF_8), null, 20);
		String scandiumMaterial = StringUtil.byteArray2Hex(keyMaterial);
		assertEquals(opensslMaterial, scandiumMaterial);
		Bytes.clear(keyMaterial);
	}

	public ProcessResult connect(String cipher, String... misc) throws Exception {
		assertTrue("handshake failed!", processUtil.waitConsole("Cipher is ", HANDSHAKE_TIMEOUT_MILLIS));
		assertTrue("wrong cipher suite!", processUtil.waitConsole("Cipher is " + cipher, FOLLOW_UP_TIMEOUT_MILLIS));
		if (misc != null) {
			for (String check : misc) {
				assertTrue("missing " + check, processUtil.waitConsole(check, TIMEOUT_MILLIS));
			}
		}

		String message = "Hello Scandium!";
		processUtil.send(message);

		scandiumUtil.assertReceivedData(message, TIMEOUT_MILLIS);
		scandiumUtil.response("ACK-" + message, TIMEOUT_MILLIS);

		assertTrue("openssl is missing ACK!", processUtil.waitConsole("ACK-" + message, TIMEOUT_MILLIS));

		return processUtil.stop(TIMEOUT_MILLIS);
	}
}
