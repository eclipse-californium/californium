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
 *    Achim Kraus (Bosch.IO GmbH) - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.interoperability.test.libcoap.gnutls;

import static org.eclipse.californium.interoperability.test.ConnectorUtil.CLIENT_RSA_NAME;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.SERVER_RSA_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.SERVER_CA_RSA_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.ProcessUtil.TIMEOUT_MILLIS;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.REQUEST_TIMEOUT_MILLIS;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.LibCoapAuthenticationMode.CA;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.LibCoapAuthenticationMode.CHAIN;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.LibCoapAuthenticationMode.TRUST;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeNotNull;
import static org.junit.Assume.assumeTrue;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.auth.PreSharedKeyIdentity;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.interoperability.test.CaliforniumUtil;
import org.eclipse.californium.interoperability.test.ProcessUtil.ProcessResult;
import org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil;
import org.eclipse.californium.interoperability.test.ScandiumUtil;
import org.eclipse.californium.interoperability.test.ShutdownUtil;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

/**
 * Test for interoperability with libcoap server using gnutls.
 * 
 * @see LibCoapProcessUtil
 */
public class LibCoapServerGnuTlsInteroperabilityTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	/**
	 * Gnutls seems to require a encoded private key with the optional public
	 * key. <a href="https://tools.ietf.org/html/rfc5915#section-3" target="_blank">RFC 5915 -
	 * Section 3</a> Unclear, how to achieve that with openssl 1.1.1, seems to
	 * be the output of openssl 1.0
	 */
	private static final String SERVER_PRIVATE_KEY = "serverPrivateKey.pem";
	private static final String SERVER_RSA_PRIVATE_KEY = "serverRsaPrivateKey.pem";
	private static final String SERVER_CA_RSA_PRIVATE_KEY = "serverCaRsaPrivateKey.pem";

	private static final InetSocketAddress BIND = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
	private static final InetSocketAddress DESTINATION = new InetSocketAddress(InetAddress.getLoopbackAddress(),
			ScandiumUtil.PORT);
	private static final String ACCEPT = "127.0.0.1:" + ScandiumUtil.PORT;

	private static LibCoapProcessUtil processUtil;
	private static CaliforniumUtil californiumUtil;
	private static String serverPrivateKey;
	private static String serverRsaPrivateKey;
	private static String serverCaRsaPrivateKey;

	@BeforeClass
	public static void init() throws IOException, InterruptedException {
		processUtil = new LibCoapProcessUtil();
		ProcessResult result = processUtil.prepareLibCoapServerGnuTls(TIMEOUT_MILLIS);
		assumeNotNull(result);
		processUtil.assumeMinVersion("4.2.1");
		processUtil.assumeMinDtlsVersion("3.5.18");
		californiumUtil = new CaliforniumUtil(true);
		if (processUtil.compareVersion("4.3.0") >= 0) {
			File privatekey = new File(SERVER_PRIVATE_KEY);
			if (privatekey.isFile() && privatekey.canRead()) {
				serverPrivateKey = SERVER_PRIVATE_KEY;
			}
			privatekey = new File(SERVER_RSA_PRIVATE_KEY);
			if (privatekey.isFile() && privatekey.canRead()) {
				serverRsaPrivateKey = SERVER_RSA_PRIVATE_KEY;
			}
			privatekey = new File(SERVER_CA_RSA_PRIVATE_KEY);
			if (privatekey.isFile() && privatekey.canRead()) {
				serverCaRsaPrivateKey = SERVER_CA_RSA_PRIVATE_KEY;
			}
		}
	}

	@AfterClass
	public static void shutdown() throws InterruptedException {
		ShutdownUtil.shutdown(californiumUtil, processUtil);
	}

	@Before
	public void start() {
		processUtil.setTag(name.getName());
	}

	@After
	public void stop() throws InterruptedException {
		ShutdownUtil.shutdown(californiumUtil, processUtil);
	}

	@Test
	public void testLibCoapServerPskGCM() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256;
		assumeTrue("GCM not support by JCE", cipherSuite.isSupported());
		processUtil.startupServer(ACCEPT, CHAIN, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect(true);
		californiumUtil.assertPrincipalType(PreSharedKeyIdentity.class);
	}

	@Test
	public void testLibCoapServerPsk() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		processUtil.startupServer(ACCEPT, CHAIN, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect(true);
		californiumUtil.assertPrincipalType(PreSharedKeyIdentity.class);
	}

	@Ignore
	@Test
	public void testLibCoapServerPsk2FullHandshake() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		processUtil.startupServer(ACCEPT, CHAIN, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);

		// first handshake
		Request request = Request.newGet();
		request.setURI("coaps://" + StringUtil.toString(DESTINATION) + "/time");
		CoapResponse response = californiumUtil.send(request);
		assertNotNull(response);
		assertEquals(CoAP.ResponseCode.CONTENT, response.getCode());

		// second handshake
		request = Request.newGet();
		request.setURI("coaps://" + StringUtil.toString(DESTINATION) + "/time");
		response = californiumUtil.sendWithFullHandshake(request);
		assertNotNull(response);
		assertEquals(CoAP.ResponseCode.CONTENT, response.getCode());

		connect(true);
		californiumUtil.assertPrincipalType(PreSharedKeyIdentity.class);
	}

	@Test
	public void testLibCoapServerEcdsaGCM() throws Exception {
		assumeNotNull(serverPrivateKey);
		processUtil.setPrivateKey(serverPrivateKey);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
		assumeTrue("GCM not support by JCE", cipherSuite.isSupported());
		processUtil.startupServer(ACCEPT, CHAIN, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		ProcessResult result = connect(true);
		assertFalse(result.contains("write certificate request"));
		assertFalse(result.contains("'cf-client'"));
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapServerEcdsa() throws Exception {
		assumeNotNull(serverPrivateKey);
		processUtil.setPrivateKey(serverPrivateKey);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.startupServer(ACCEPT, CHAIN, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		ProcessResult result = connect(true);
		assertFalse(result.contains("write certificate request"));
		assertFalse(result.contains("'cf-client'"));
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapServerEcdsaRsa() throws Exception {
		assumeNotNull(serverCaRsaPrivateKey);
		processUtil.setPrivateKey(serverCaRsaPrivateKey);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.setCertificate(SERVER_CA_RSA_CERTIFICATE);
		processUtil.startupServer(ACCEPT, CHAIN, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect(true);
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapServerEcdsaRsaSigAlg() throws Exception {
		assumeNotNull(serverCaRsaPrivateKey);
		processUtil.setPrivateKey(serverCaRsaPrivateKey);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.setCertificate(SERVER_CA_RSA_CERTIFICATE);
		processUtil.startupServer(ACCEPT, CHAIN, cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA);
		californiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(true);
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapServerEcdsaTrust() throws Exception {
		assumeNotNull(serverPrivateKey);
		processUtil.setPrivateKey(serverPrivateKey);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);

		if (processUtil.compareVersion("4.3.0") >= 0) {
			connect(true, "'cf-client'");
		} else {
			connect(true);
		}

		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapServerEcdsaCa() throws Exception {
		assumeNotNull(serverPrivateKey);
		processUtil.setPrivateKey(serverPrivateKey);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.startupServer(ACCEPT, CA, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect(true, "'cf-client'");
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapServerEcdsaCaFails() throws Exception {
		assumeNotNull(serverPrivateKey);
		processUtil.setPrivateKey(serverPrivateKey);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.setCa(SERVER_CA_RSA_CERTIFICATE);
		// mbedtls uses -R also for accepted issuers list. Therefore only use -C
		processUtil.startupServer(ACCEPT, CA, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect(false, "Client Certificate requested and required, but not provided");
		californiumUtil.assertAlert(TIMEOUT_MILLIS, new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE));
	}

	@Test
	public void testLibCoapServerEcdsaTrustFails() throws Exception {
		assumeNotNull(serverPrivateKey);
		processUtil.setPrivateKey(serverPrivateKey);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.setTrusts(SERVER_CA_RSA_CERTIFICATE);
		processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect(false, "The peer certificate's CA is unknown");
		californiumUtil.assertAlert(TIMEOUT_MILLIS, new AlertMessage(AlertLevel.FATAL, AlertDescription.UNKNOWN_CA));
	}

	@Test
	public void testLibCoapServerEcdsaRsaTrust() throws Exception {
		assumeNotNull(serverCaRsaPrivateKey);
		processUtil.setPrivateKey(serverCaRsaPrivateKey);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.setCertificate(SERVER_CA_RSA_CERTIFICATE);
		processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		if (processUtil.compareVersion("4.3.0") >= 0) {
			connect(true, "'cf-client'");
		} else {
			connect(true);
		}
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapServerEcdsaRsaCa() throws Exception {
		assumeNotNull(serverCaRsaPrivateKey);
		processUtil.setPrivateKey(serverCaRsaPrivateKey);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.setCertificate(SERVER_CA_RSA_CERTIFICATE);
		processUtil.startupServer(ACCEPT, CA, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect(true, "'cf-client'");
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapServerRsa() throws Exception {
		assumeNotNull(serverRsaPrivateKey);
		processUtil.setPrivateKey(serverRsaPrivateKey);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.isSupported()
				? CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
				: CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384;
		assumeTrue(cipherSuite.name() + " not support by JCE", cipherSuite.isSupported());
		processUtil.setCertificate(SERVER_RSA_CERTIFICATE);
		processUtil.startupServer(ACCEPT, CA, cipherSuite);

		californiumUtil.loadCredentials(CLIENT_RSA_NAME);
		californiumUtil.start(BIND, null, cipherSuite);
		connect(true, "'cf-client-rsa'");
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapServerEcdsaRsaSigAlgTrust() throws Exception {
		assumeNotNull(serverCaRsaPrivateKey);
		processUtil.setPrivateKey(serverCaRsaPrivateKey);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.setCertificate(SERVER_CA_RSA_CERTIFICATE);
		processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		Configuration configuration = new Configuration();
		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(configuration);
		dtlsBuilder.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA);
		californiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(true);
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	public ProcessResult connect(boolean success, String... patterns) throws Exception {
		Request request = Request.newGet();
		request.setURI("coaps://" + StringUtil.toString(DESTINATION) + "/time");
		CoapResponse response = californiumUtil.send(request);
		if (success) {
			if (response != null) {
				System.out.println(Utils.prettyPrint(response));
				assertEquals(CoAP.ResponseCode.CONTENT, response.getCode());
			} else if (request.getSendError() != null) {
				fail("error " + request.getSendError());
			} else if (request.isTimedOut()) {
				fail("timeout!");
			} else {
				fail("unknown cause!");
			}
		} else {
			if (response != null) {
				System.out.println(Utils.prettyPrint(response));
				fail("unexpected response!");
			} else if (request.getSendError() != null) {
				System.out.println("expected error: " + request.getSendError());
			} else if (request.isTimedOut()) {
				fail("timeout!");
			} else {
				fail("unknown cause!");
			}
		}
		if (patterns != null) {
			for (String check : patterns) {
				assertTrue("missing " + check, processUtil.waitConsole(check, REQUEST_TIMEOUT_MILLIS.get()));
			}
		}
		return processUtil.stop(TIMEOUT_MILLIS);
	}
}
