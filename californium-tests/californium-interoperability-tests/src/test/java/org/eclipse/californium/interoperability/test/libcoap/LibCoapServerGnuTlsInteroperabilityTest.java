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
package org.eclipse.californium.interoperability.test.libcoap;

import static org.eclipse.californium.interoperability.test.OpenSslUtil.SERVER_RSA_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.LibCoapAuthenticationMode.CA;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.LibCoapAuthenticationMode.CHAIN;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.LibCoapAuthenticationMode.TRUST;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeNotNull;

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
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.interoperability.test.CaliforniumUtil;
import org.eclipse.californium.interoperability.test.ProcessUtil.ProcessResult;
import org.eclipse.californium.interoperability.test.ScandiumUtil;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
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
	 * key. <a href="https://tools.ietf.org/html/rfc5915#section-3">RFC 5915 -
	 * Section 3</a> Unclear, how to achieve that with openssl 1.1.1, seems to
	 * be the output of openssl 1.0
	 */
	private static final String SERVER_PRIVATE_KEY = "serverPrivateKey.pem";
	private static final String SERVER_RSA_PRIVATE_KEY = "serverRsaPrivateKey.pem";

	private static final InetSocketAddress BIND = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
	private static final InetSocketAddress DESTINATION = new InetSocketAddress(InetAddress.getLoopbackAddress(),
			ScandiumUtil.PORT);
	private static final String ACCEPT = "127.0.0.1:" + ScandiumUtil.PORT;
	private static final long TIMEOUT_MILLIS = 2000;

	private static LibCoapProcessUtil processUtil;
	private static CaliforniumUtil californiumUtil;
	private static String serverPrivateKey;
	private static String serverRsaPrivateKey;

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
		}
	}

	@AfterClass
	public static void shutdown() throws InterruptedException {
		if (californiumUtil != null) {
			californiumUtil.shutdown();
			californiumUtil = null;
		}
		if (processUtil != null) {
			processUtil.shutdown();
		}
	}

	@After
	public void stop() throws InterruptedException {
		if (californiumUtil != null) {
			californiumUtil.shutdown();
		}
		processUtil.shutdown();
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
		assumeNotNull(serverRsaPrivateKey);
		processUtil.setPrivateKey(serverRsaPrivateKey);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.setCertificate(SERVER_RSA_CERTIFICATE);
		processUtil.startupServer(ACCEPT, CHAIN, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect(true);
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapServerEcdsaRsaSigAlg() throws Exception {
		assumeNotNull(serverRsaPrivateKey);
		processUtil.setPrivateKey(serverRsaPrivateKey);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.setCertificate(SERVER_RSA_CERTIFICATE);
		processUtil.startupServer(ACCEPT, CHAIN, cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = new DtlsConnectorConfig.Builder();
		dtlsBuilder.setSupportedSignatureAlgorithms(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA);
		californiumUtil.start(BIND, false, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);
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
		ProcessResult result = connect(true);

		if (processUtil.compareVersion("4.3.0") >= 0) {
			assertTrue(result.contains("'cf-client'"));
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
		processUtil.setCa(SERVER_RSA_CERTIFICATE);
		// mbedtls uses -R also for accepted issuers list. Therefore only use -C
		processUtil.startupServer(ACCEPT, CA, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect(false, "Client Certificate requested and required, but not provided");
		californiumUtil.assertAlert(new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE));
	}

	@Test
	public void testLibCoapServerEcdsaTrustFails() throws Exception {
		assumeNotNull(serverPrivateKey);
		processUtil.setPrivateKey(serverPrivateKey);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.setTrusts(SERVER_RSA_CERTIFICATE);
		processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect(false, "The peer certificate's CA is unknown");
		californiumUtil.assertAlert(new AlertMessage(AlertLevel.FATAL, AlertDescription.UNKNOWN_CA));
	}

	@Test
	public void testLibCoapServerEcdsaRsaTrust() throws Exception {
		assumeNotNull(serverRsaPrivateKey);
		processUtil.setPrivateKey(serverRsaPrivateKey);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.setCertificate(SERVER_RSA_CERTIFICATE);
		processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		ProcessResult result = connect(true);
		if (processUtil.compareVersion("4.3.0") >= 0) {
			assertTrue(result.contains("'cf-client'"));
		}
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapServerEcdsaRsaCa() throws Exception {
		assumeNotNull(serverRsaPrivateKey);
		processUtil.setPrivateKey(serverRsaPrivateKey);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.setCertificate(SERVER_RSA_CERTIFICATE);
		processUtil.startupServer(ACCEPT, CA, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect(true, "'cf-client'");
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapServerEcdsaRsaSigAlgTrust() throws Exception {
		assumeNotNull(serverRsaPrivateKey);
		processUtil.setPrivateKey(serverRsaPrivateKey);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.setCertificate(SERVER_RSA_CERTIFICATE);
		processUtil.startupServer(ACCEPT, TRUST, cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = new DtlsConnectorConfig.Builder();
		dtlsBuilder.setSupportedSignatureAlgorithms(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA);
		californiumUtil.start(BIND, false, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);
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
				assertTrue("missing " + check, processUtil.waitConsole(check, TIMEOUT_MILLIS));
			}
		}
		processUtil.stop();
		return processUtil.stop(TIMEOUT_MILLIS);
	}
}
