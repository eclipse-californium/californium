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
import static org.eclipse.californium.interoperability.test.CredentialslUtil.SERVER_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.SERVER_RSA_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.SERVER_EDDSA_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.SERVER_CA_RSA_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.ProcessUtil.TIMEOUT_MILLIS;
import static org.eclipse.californium.interoperability.test.ProcessUtil.FOLLOW_UP_TIMEOUT_MILLIS;
import static org.eclipse.californium.interoperability.test.openssl.OpenSslProcessUtil.AuthenticationMode.PSK;
import static org.eclipse.californium.interoperability.test.openssl.OpenSslProcessUtil.AuthenticationMode.CERTIFICATE;
import static org.eclipse.californium.interoperability.test.openssl.OpenSslProcessUtil.AuthenticationMode.CHAIN;
import static org.eclipse.californium.interoperability.test.openssl.OpenSslProcessUtil.AuthenticationMode.TRUST;
import static org.eclipse.californium.interoperability.test.openssl.OpenSslProcessUtil.DEFAULT_CURVES;
import static org.eclipse.californium.interoperability.test.openssl.OpenSslProcessUtil.DEFAULT_SIGALGS;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.regex.Matcher;

import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StandardCharsets;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.interoperability.test.ConnectorUtil;
import org.eclipse.californium.interoperability.test.ScandiumUtil;
import org.eclipse.californium.interoperability.test.ShutdownUtil;
import org.eclipse.californium.interoperability.test.ProcessUtil.ProcessResult;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.DTLSContext;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

/**
 * Test for interoperability with openssl server.
 * 
 * Test several authentication modes.
 * 
 * Note: the windows version 1.1.1a to 1.1.1d of the openssl s_server seems to
 * be broken. It starts only to accept, when the first message is entered.
 * Therefore the test are skipped on windows.
 * 
 * @see OpenSslUtil
 */
public class OpenSslServerAuthenticationInteroperabilityTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final InetSocketAddress BIND = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
	private static final InetSocketAddress DESTINATION = new InetSocketAddress(InetAddress.getLoopbackAddress(),
			ScandiumUtil.PORT);
	private static final String ACCEPT = "127.0.0.1:" + ScandiumUtil.PORT;

	private static OpenSslProcessUtil processUtil;
	private static ScandiumUtil scandiumUtil;
	private static CipherSuite cipherSuite;

	@BeforeClass
	public static void init() throws IOException, InterruptedException {
		processUtil = new OpenSslProcessUtil();
		processUtil.assumeMinVersion("1.1.");
		processUtil.assumeServerVersion();
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
	public void testOpenSslServerPsk() throws Exception {
		processUtil.assumePskServerVersion();
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		String cipher = processUtil.startupServer(ACCEPT, PSK, cipherSuite);

		scandiumUtil.start(BIND, null, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslServerCertTrustAll() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, CERTIFICATE, cipherSuite);

		scandiumUtil.start(BIND, null, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslServerChainTrustAll() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, CHAIN, cipherSuite);

		scandiumUtil.start(BIND, null, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslServerTrustTrustAll() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		scandiumUtil.start(BIND, null, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslServerFullTrustTrustAll() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.set(DtlsConfig.DTLS_TRUNCATE_CLIENT_CERTIFICATE_PATH, false);
		scandiumUtil.start(BIND, dtlsBuilder, null, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslServerCertTrustCa() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, CERTIFICATE, cipherSuite);

		scandiumUtil.start(BIND, ScandiumUtil.TRUST_CA, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslServerChainTrustCa() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, CHAIN, cipherSuite);

		scandiumUtil.start(BIND, ScandiumUtil.TRUST_CA, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslServerTrustTrustCa() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		scandiumUtil.start(BIND, ScandiumUtil.TRUST_CA, cipherSuite);
		connect(cipher);
	}

	@Test
	@Ignore // certificate not trusted by root
	public void testOpenSslServerCertTrustRoot() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, CERTIFICATE, cipherSuite);

		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslServerChainTrustRoot() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, CHAIN, cipherSuite);

		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslServerTrustTrustRoot() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslServerBothRawPublicKey() throws Exception {
		processUtil.assumeMinVersion("3.2.");
		processUtil.addExtraArgs("-enable_server_rpk", "-enable_client_rpk");
		String cipher = processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		scandiumUtil.setCertificateTypes(CertificateType.RAW_PUBLIC_KEY, CertificateType.X_509);
		scandiumUtil.start(BIND, ScandiumUtil.TRUST_ROOT, cipherSuite);

		connect(cipher, "Client raw public key");
		scandiumUtil.assertPrincipalType(HANDSHAKE_TIMEOUT_MILLIS, RawPublicKeyIdentity.class);
	}

	@Test
	public void testOpenSslServerBothRawPublicKeyEmptyCertificate() throws Exception {
		processUtil.assumeMinVersion("3.2.");
		processUtil.addExtraArgs("-enable_server_rpk", "-enable_client_rpk");
		String cipher = processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA);
		scandiumUtil.setAnonymous();
		scandiumUtil.setCertificateTypes(CertificateType.RAW_PUBLIC_KEY, CertificateType.X_509);
		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);

		connect(cipher);
		scandiumUtil.assertPrincipalType(HANDSHAKE_TIMEOUT_MILLIS, RawPublicKeyIdentity.class);
	}

	/**
	 * @see <a href="https://github.com/openssl/openssl/issues/20122" target="_blank">
	 * OpenSSL - State of support for Ed25519 certificates with DTLS 1.2?</a>
	 */
	@Test
	@Ignore // Ed25519 fails on server side
	public void testOpenSslServerBothRawPublicKeyEd25519() throws Exception {
		assumeTrue("X25519 not support by JCE", XECDHECryptography.SupportedGroup.X25519.isUsable());
		processUtil.assumeMinVersion("3.2.");
		processUtil.addExtraArgs("-enable_server_rpk", "-enable_client_rpk");
		String cipher = processUtil.startupServer(ACCEPT, TRUST, SERVER_EDDSA_CERTIFICATE, DEFAULT_CURVES, null,
				cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.setAsList(DtlsConfig.DTLS_CURVES, SupportedGroup.X25519, SupportedGroup.secp256r1);

		scandiumUtil.loadEdDsaCredentials(ConnectorUtil.CLIENT_EDDSA_NAME);
		scandiumUtil.setCertificateTypes(CertificateType.RAW_PUBLIC_KEY, CertificateType.X_509);
		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);

		connect(cipher, "Shared (Elliptic )?groups: [xX]25519", "Client raw public key");
		scandiumUtil.assertPrincipalType(HANDSHAKE_TIMEOUT_MILLIS, RawPublicKeyIdentity.class);
	}

	/**
	 * @see <a href="https://github.com/openssl/openssl/issues/20122" target="_blank">
	 * OpenSSL - State of support for Ed25519 certificates with DTLS 1.2?</a>
	 */
	@Test
	@Ignore // Ed25519 fails on server side
	public void testOpenSslServerEd25519() throws Exception {
		assumeTrue("X25519 not support by JCE", XECDHECryptography.SupportedGroup.X25519.isUsable());
		String cipher = processUtil.startupServer(ACCEPT, TRUST, SERVER_EDDSA_CERTIFICATE, DEFAULT_CURVES, "ed25519:" + DEFAULT_SIGALGS,
				cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.setAsList(DtlsConfig.DTLS_CURVES, SupportedGroup.X25519, SupportedGroup.secp256r1);

		scandiumUtil.loadEdDsaCredentials(ConnectorUtil.CLIENT_EDDSA_NAME);
		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);

		connect(cipher, "Shared (Elliptic )?groups: [xX]25519");
	}

	@Test
	public void testOpenSslServerX25519() throws Exception {
		assumeTrue("X25519 not support by JCE", XECDHECryptography.SupportedGroup.X25519.isUsable());
		String cipher = processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.setAsList(DtlsConfig.DTLS_CURVES, SupportedGroup.X25519, SupportedGroup.secp256r1);

		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(cipher, "Shared (Elliptic )?groups: [xX]25519");
	}

	@Test
	public void testOpenSslServerX448() throws Exception {
		assumeTrue("X448 not support by JCE", XECDHECryptography.SupportedGroup.X448.isUsable());
		String cipher = processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.setAsList(DtlsConfig.DTLS_CURVES, SupportedGroup.X448, SupportedGroup.secp256r1);

		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(cipher, "Shared (Elliptic )?groups: [xX]448");
	}

	@Test
	public void testOpenSslServerPrime256v1() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.setAsList(DtlsConfig.DTLS_CURVES, SupportedGroup.secp256r1);

		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(cipher, "Shared (Elliptic )?(groups|curves): (P-256|secp256r1)");
	}

	@Test
	public void testOpenSslServerSecP384r1() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.setAsList(DtlsConfig.DTLS_CURVES, SupportedGroup.secp384r1, SupportedGroup.secp256r1);

		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(cipher, "Shared (Elliptic )?(groups|curves): (P-384|secp384r1)");
	}

	@Test
	public void testOpenSslServerBrainpoolP384r1() throws Exception {
		assumeTrue("BrainpoolP384r1 not support by JCE", XECDHECryptography.SupportedGroup.brainpoolP384r1.isUsable());
		String cipher = processUtil.startupServer(ACCEPT, TRUST, SERVER_CERTIFICATE, "brainpoolP384r1:prime256v1", null,
				cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.set(DtlsConfig.DTLS_RECOMMENDED_CURVES_ONLY, false)
				.setAsList(DtlsConfig.DTLS_CURVES, SupportedGroup.brainpoolP384r1, SupportedGroup.secp256r1)
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, SignatureAndHashAlgorithm.SHA384_WITH_ECDSA,
						SignatureAndHashAlgorithm.SHA256_WITH_ECDSA);

		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(cipher, "Shared (Elliptic )?(groups|curves): brainpoolP384r1:(P-256|secp256r1)");
	}

	@Test
	public void testOpenSslServerRsaTrustTrustRoot() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, TRUST, SERVER_CA_RSA_CERTIFICATE,
				OpenSslProcessUtil.DEFAULT_CURVES, OpenSslProcessUtil.DEFAULT_SIGALGS, cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA,
						SignatureAndHashAlgorithm.SHA256_WITH_RSA);
		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(cipher);
	}

	@Test
	public void testOpenSslServerRsaChainTrustRoot() throws Exception {
		CipherSuite[] ciphers = { CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
				CipherSuite.TLS_PSK_WITH_AES_128_CCM_8 };
		String cipher = processUtil.startupServer(ACCEPT, CHAIN, SERVER_CA_RSA_CERTIFICATE, null, null, ciphers);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA,
						SignatureAndHashAlgorithm.SHA256_WITH_RSA);
		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, ciphers);
		connect(cipher);
	}

	@Test
	public void testOpenSslServerRsaTrustRoot() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.isSupported()
				? CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
				: CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
		assumeTrue(cipherSuite.name() + " not support by JCE", cipherSuite.isSupported());
		CipherSuite[] ciphers = { cipherSuite, CipherSuite.TLS_PSK_WITH_AES_128_CCM_8 };
		String cipher = processUtil.startupServer(ACCEPT, CHAIN, SERVER_RSA_CERTIFICATE, null, null, ciphers);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA,
						SignatureAndHashAlgorithm.SHA256_WITH_RSA);
		scandiumUtil.loadCredentials(ConnectorUtil.CLIENT_RSA_NAME);
		scandiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, ciphers);
		connect(cipher);
	}

	@Test
	public void testOpenSslServerExportKeyMaterial() throws Exception {
		String exportLabel = "EXPERIMENTAL_TEST";

		processUtil.assumePskServerVersion();
		processUtil.addExtraArgs("-keymatexport",exportLabel);

		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		String cipher = processUtil.startupServer(ACCEPT, PSK, cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.set(DtlsConfig.DTLS_SUPPORT_KEY_MATERIAL_EXPORT, true);

		scandiumUtil.start(BIND, dtlsBuilder, null, cipherSuite);

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
		String message = "Hello OpenSSL!";
		scandiumUtil.send(message, DESTINATION, HANDSHAKE_TIMEOUT_MILLIS);

		assertTrue("handshake failed!", processUtil.waitConsole("CIPHER is ", TIMEOUT_MILLIS));
		assertTrue("wrong cipher suite!", processUtil.waitConsole("CIPHER is " + cipher, FOLLOW_UP_TIMEOUT_MILLIS));
		if (misc != null) {
			for (String check : misc) {
				assertTrue("missing " + check, processUtil.waitConsole(check, TIMEOUT_MILLIS));
			}
		}
		assertTrue("openssl missing message!", processUtil.waitConsole(message, TIMEOUT_MILLIS));
		processUtil.send("ACK-" + message);

		scandiumUtil.assertReceivedData("ACK-" + message, TIMEOUT_MILLIS);

		return processUtil.stop(TIMEOUT_MILLIS);
	}
}
