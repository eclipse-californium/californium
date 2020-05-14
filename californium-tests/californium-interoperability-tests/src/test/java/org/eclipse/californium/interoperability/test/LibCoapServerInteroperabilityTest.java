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
package org.eclipse.californium.interoperability.test;

import static org.junit.Assert.assertEquals;
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
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.interoperability.test.OpenSslUtil.AuthenticationMode;
import org.eclipse.californium.interoperability.test.ProcessUtil.ProcessResult;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

/**
 * Test for interoperability with libcoap server.
 * 
 * @see LibCoapProcessUtil
 */
public class LibCoapServerInteroperabilityTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final InetSocketAddress BIND = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
	private static final InetSocketAddress DESTINATION = new InetSocketAddress(InetAddress.getLoopbackAddress(),
			ScandiumUtil.PORT);
	private static final String ACCEPT = "127.0.0.1:" + ScandiumUtil.PORT;
	private static final long TIMEOUT_MILLIS = 2000;

	private static LibCoapProcessUtil processUtil;
	private static CaliforniumUtil californiumUtil;

	@BeforeClass
	public static void init() throws IOException, InterruptedException {
		processUtil = new LibCoapProcessUtil();
		ProcessResult result = processUtil.getLibCoapVersion(TIMEOUT_MILLIS);
		assumeNotNull(result);
		assumeTrue(result.contains("coap-client v4\\.2\\.1 "));
		assumeTrue(result.contains("OpenSSL - runtime 1\\.1\\.1,"));
		californiumUtil = new CaliforniumUtil(true);
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
	public void testLibCoapServertPsk() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		processUtil.startupServer(ACCEPT, AuthenticationMode.CERTIFICATE, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect();
	}

	@Test
	public void testLibCoapServerEcdsa() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.startupServer(ACCEPT, AuthenticationMode.CERTIFICATE, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect();
	}

	@Test
	public void testLibCoapServerEcdsaRsa() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.startupServer(ACCEPT, AuthenticationMode.CERTIFICATE, OpenSslProcessUtil.SERVER_RSA_CERTIFICATE,
				cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect();
	}

	@Test
	public void testLibCoapServerEcdsaRsaSigAlg() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.startupServer(ACCEPT, AuthenticationMode.CERTIFICATE, OpenSslProcessUtil.SERVER_RSA_CERTIFICATE,
				cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = new DtlsConnectorConfig.Builder();
		dtlsBuilder.setSupportedSignatureAlgorithms(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA);
		californiumUtil.start(BIND, false, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect();
	}

	@Test
	public void testLibCoapServerEcdsaTrust() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.startupServer(ACCEPT, AuthenticationMode.TRUST, cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect();
	}

	@Test
	public void testLibCoapServerEcdsaRsaTrust() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.startupServer(ACCEPT, AuthenticationMode.TRUST, OpenSslProcessUtil.SERVER_RSA_CERTIFICATE,
				cipherSuite);

		californiumUtil.start(BIND, null, cipherSuite);
		connect();
	}

	@Test
	public void testLibCoapServerEcdsaRsaSigAlgTrust() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.startupServer(ACCEPT, AuthenticationMode.TRUST, OpenSslProcessUtil.SERVER_RSA_CERTIFICATE,
				cipherSuite);

		DtlsConnectorConfig.Builder dtlsBuilder = new DtlsConnectorConfig.Builder();
		dtlsBuilder.setSupportedSignatureAlgorithms(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA);
		californiumUtil.start(BIND, false, dtlsBuilder, ScandiumUtil.TRUST_ROOT, cipherSuite);
		connect();
	}

	@Test
	public void testLibCoapEcdsa() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		processUtil.startupServer(ACCEPT, AuthenticationMode.TRUST, cipherSuite);

		LibCoapProcessUtil clientProcessUtil = new LibCoapProcessUtil();
		clientProcessUtil.startupClient("coaps://" + ACCEPT + "/time", AuthenticationMode.TRUST, null, cipherSuite);
		String check = "\\d+:\\d+:\\d+";
		assertTrue(clientProcessUtil.waitConsole(check, TIMEOUT_MILLIS));
		System.out.println("match: " + check);
		clientProcessUtil.stop(TIMEOUT_MILLIS);
		processUtil.stop();
		processUtil.stop(TIMEOUT_MILLIS);
	}

	public void connect() throws Exception {
		Request request = Request.newGet();
		request.setURI("coaps://" + StringUtil.toString(DESTINATION) + "/time");
		CoapResponse response = californiumUtil.send(request);
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
		processUtil.stop();
		processUtil.stop(TIMEOUT_MILLIS);
	}
}
