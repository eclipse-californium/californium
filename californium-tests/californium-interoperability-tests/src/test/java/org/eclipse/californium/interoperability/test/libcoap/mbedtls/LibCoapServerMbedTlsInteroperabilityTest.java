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
package org.eclipse.californium.interoperability.test.libcoap.mbedtls;

import static org.eclipse.californium.interoperability.test.ConnectorUtil.CLIENT_RSA_NAME;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.SERVER_CA_RSA_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.SERVER_RSA_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.ProcessUtil.TIMEOUT_MILLIS;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.REQUEST_TIMEOUT_MILLIS;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.LibCoapAuthenticationMode.CA;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.LibCoapAuthenticationMode.CHAIN;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.LibCoapAuthenticationMode.TRUST;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeNotNull;
import static org.junit.Assume.assumeTrue;

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
import org.junit.Rule;
import org.junit.Test;

/**
 * Test for interoperability with libcoap server using mbedtls.
 * 
 * @see LibCoapProcessUtil
 */
public class LibCoapServerMbedTlsInteroperabilityTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final InetSocketAddress BIND = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
	private static final InetSocketAddress DESTINATION = new InetSocketAddress(InetAddress.getLoopbackAddress(),
			ScandiumUtil.PORT);
	private static final String ACCEPT = "127.0.0.1:" + ScandiumUtil.PORT;

	private static LibCoapProcessUtil processUtil;
	private static CaliforniumUtil californiumUtil;

	@BeforeClass
	public static void init() throws IOException, InterruptedException {
		processUtil = new LibCoapProcessUtil();
		ProcessResult result = processUtil.prepareLibCoapServerMbedTls(TIMEOUT_MILLIS);
		assumeNotNull(result);
		processUtil.assumeMinVersion("4.3.0");
		processUtil.assumeMinDtlsVersion("2.16.5");
		californiumUtil = new CaliforniumUtil(true);
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
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
		assumeTrue("GCM not support by JCE", cipherSuite.isSupported());
		processUtil.startupServer(ACCEPT, CHAIN, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect(true);
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapServerEcdsa() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.startupServer(ACCEPT, CHAIN, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect(true);
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapServerEcdsaRsa() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.setCertificate(SERVER_CA_RSA_CERTIFICATE);
		processUtil.startupServer(ACCEPT, CHAIN, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect(true);
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapServerEcdsaRsaSigAlg() throws Exception {
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
		processUtil.setVerboseLevel("9");
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect(true, "parse certificate verify", "CN=cf-client,");

		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapServerEcdsaCa() throws Exception {
		processUtil.setVerboseLevel("9");
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.startupServer(ACCEPT, CA, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect(true, "parse certificate verify", "CN=cf-client,");
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapServerEcdsaCaFails() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.setCa(SERVER_CA_RSA_CERTIFICATE);
		// mbedtls uses -R also for accepted issuers list. Therefore only use -C
		processUtil.startupServer(ACCEPT, CA, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect(false, "No client certification received from the client");
		californiumUtil.assertAlert(TIMEOUT_MILLIS,
				new AlertMessage(AlertLevel.FATAL, AlertDescription.NO_CERTIFICATE_RESERVED));
	}

	@Test
	public void testLibCoapServerEcdsaTrustFails() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.setTrusts(SERVER_CA_RSA_CERTIFICATE);
		processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect(false, "The certificate is not correctly signed by the trusted CA");
		californiumUtil.assertAlert(TIMEOUT_MILLIS, new AlertMessage(AlertLevel.FATAL, AlertDescription.UNKNOWN_CA));
	}

	@Test
	public void testLibCoapServerEcdsaRsaTrust() throws Exception {
		processUtil.setVerboseLevel("9");
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.setCertificate(SERVER_CA_RSA_CERTIFICATE);
		processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect(true, "parse certificate verify", "CN=cf-client,");
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapServerEcdsaRsaCa() throws Exception {
		processUtil.setVerboseLevel("9");
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.setCertificate(SERVER_CA_RSA_CERTIFICATE);
		processUtil.startupServer(ACCEPT, CA, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect(true, "parse certificate verify", "CN=cf-client,");
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapServerRsa() throws Exception {
		processUtil.setVerboseLevel("9");
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.isSupported()
				? CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
				: CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
		processUtil.setCertificate(SERVER_RSA_CERTIFICATE);
		processUtil.startupServer(ACCEPT, CA, cipherSuite);

		californiumUtil.loadCredentials(CLIENT_RSA_NAME);
		californiumUtil.start(BIND, null, cipherSuite);
		connect(true, "parse certificate verify", "CN=cf-client-rsa,");
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapServerEcdsaRsaSigAlgTrust() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.setCertificate(SERVER_CA_RSA_CERTIFICATE);
		processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = DtlsConnectorConfig.builder(new Configuration())
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA);
		californiumUtil.start(BIND, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect(true);
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapEcdsa() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		LibCoapProcessUtil clientProcessUtil = new LibCoapProcessUtil();
		clientProcessUtil.prepareLibCoapClientMbedTls(TIMEOUT_MILLIS);
		clientProcessUtil.startupClient("coaps://" + ACCEPT + "/time", TRUST, null, cipherSuite);
		String check = "\\d+:\\d+:\\d+";
		assertTrue(clientProcessUtil.waitConsole(check, REQUEST_TIMEOUT_MILLIS.get()));
		System.out.println("match: " + check);
		clientProcessUtil.stop(TIMEOUT_MILLIS);
		processUtil.stop(TIMEOUT_MILLIS);
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
