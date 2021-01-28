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
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.LibCoapAuthenticationMode.PSK;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.LibCoapAuthenticationMode.TRUST;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeNotNull;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.elements.auth.PreSharedKeyIdentity;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.interoperability.test.CaliforniumUtil;
import org.eclipse.californium.interoperability.test.ProcessUtil.ProcessResult;
import org.eclipse.californium.interoperability.test.ScandiumUtil;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

/**
 * Test for interoperability with libcoap client using openssl.
 * 
 * @see LibCoapProcessUtil
 */
public class LibCoapClientInteroperabilityTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final InetSocketAddress BIND = new InetSocketAddress(InetAddress.getLoopbackAddress(),
			ScandiumUtil.PORT);
	private static final String DESTINATION = "127.0.0.1:" + ScandiumUtil.PORT;
	private static final String DESTINATION_URL = "coaps://" + DESTINATION + "/";
	private static final long TIMEOUT_MILLIS = 2000;

	private static LibCoapProcessUtil processUtil;
	private static CaliforniumUtil californiumUtil;

	@BeforeClass
	public static void init() throws IOException, InterruptedException {
		processUtil = new LibCoapProcessUtil();
		ProcessResult result = processUtil.prepareLibCoapClient(TIMEOUT_MILLIS);
		assumeNotNull(result);
		processUtil.assumeMinVersion("4.2.1");
		processUtil.assumeMinDtlsVersion("1.1.1");
		californiumUtil = new CaliforniumUtil(false);
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
	public void testLibCoapClientPsk() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", PSK, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
		californiumUtil.assertPrincipalType(PreSharedKeyIdentity.class);
	}

	@Test
	public void testLibCoapClientPskMultiFragment() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
		builder.setEnableMultiHandshakeMessageRecords(true);
		californiumUtil.start(BIND, false, builder, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", PSK, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
		californiumUtil.assertPrincipalType(PreSharedKeyIdentity.class);
	}

	@Test
	public void testLibCoapClientPskNoSessionId() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
		builder.setNoServerSessionId(true);
		californiumUtil.start(BIND, false, builder, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", PSK, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
		californiumUtil.assertPrincipalType(PreSharedKeyIdentity.class);
	}

	@Test
	public void testLibCoapClientPsk1k() throws Exception {
		processUtil.setVerboseLevel(null);
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "large", PSK, "Hello, CoAP!", cipherSuite);
		ProcessResult result = connect("Hello, CoAP!",
				"###############################################################");
		assertThat(result, is(notNullValue()));
		assertThat(result.console, is(notNullValue()));
		assertThat(result.console.length(), is(greaterThan(1024)));
		californiumUtil.assertPrincipalType(PreSharedKeyIdentity.class);
	}

	@Test
	public void testLibCoapClientPsk4k() throws Exception {
		processUtil.setVerboseLevel(null);
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "large?size=4096", PSK, "Hello, CoAP!", cipherSuite);
		ProcessResult result = connect("Hello, CoAP!",
				"###############################################################");
		assertThat(result, is(notNullValue()));
		assertThat(result.console, is(notNullValue()));
		assertThat(result.console.length(), is(greaterThan(4096)));
		californiumUtil.assertPrincipalType(PreSharedKeyIdentity.class);
	}

	@Test
	public void testLibCoapClientEcdsa() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", CHAIN, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapClientEcdsaRsa() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, true, null, ScandiumUtil.TRUST_ROOT, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", CHAIN, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapClientEcdsaTrust() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", TRUST, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapClientEcdsaTrustFails() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, null, cipherSuite);
		processUtil.setTrusts(SERVER_RSA_CERTIFICATE);
		processUtil.startupClient(DESTINATION_URL + "test", TRUST, "Hello, CoAP!", cipherSuite);
		connect(null, "SSL3 alert write:fatal:unknown CA");
		californiumUtil.assertAlert(new AlertMessage(AlertLevel.FATAL, AlertDescription.UNKNOWN_CA));
	}

	@Test
	public void testLibCoapClientEcdsaCaFails() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, null, cipherSuite);
		processUtil.setCa(SERVER_RSA_CERTIFICATE);
		processUtil.startupClient(DESTINATION_URL + "test", CA, "Hello, CoAP!", cipherSuite);
		connect(null, "SSL3 alert write:fatal:unknown CA");
		californiumUtil.assertAlert(new AlertMessage(AlertLevel.FATAL, AlertDescription.UNKNOWN_CA));
	}

	@Test
	public void testLibCoapClientEcdsaRsaTrust() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, true, null, ScandiumUtil.TRUST_ROOT, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", TRUST, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapClientCustomOptions() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "custom", PSK, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Content-Format:65525", "65022:\\\\x74\\\\x65\\\\x73\\\\x74", "Custom Greetings!");
		californiumUtil.assertPrincipalType(PreSharedKeyIdentity.class);
	}

	@Test
	public void testLibCoapClientLocation() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "event", PSK, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Response!", "Location-Path:command", "Location-Path:1234-abcde",
				"Location-Query:hono-command=blink");
		californiumUtil.assertPrincipalType(PreSharedKeyIdentity.class);
	}

	public ProcessResult connect(String sendMessage, String... patterns) throws Exception {
		if (patterns != null) {
			for (String check : patterns) {
				assertTrue("missing " + check, processUtil.waitConsole(check, TIMEOUT_MILLIS));
			}
		}
		if (sendMessage != null) {
			californiumUtil.assertReceivedData(sendMessage, TIMEOUT_MILLIS);
		}
		return processUtil.stop(TIMEOUT_MILLIS);
	}
}
