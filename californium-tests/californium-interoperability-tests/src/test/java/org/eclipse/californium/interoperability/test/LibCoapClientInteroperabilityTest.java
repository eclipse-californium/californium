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

import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeNotNull;
import static org.junit.Assume.assumeTrue;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.number.OrderingComparison.greaterThan;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.interoperability.test.OpenSslUtil.AuthenticationMode;
import org.eclipse.californium.interoperability.test.ProcessUtil.ProcessResult;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

/**
 * Test for interoperability with libcoap client.
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
		ProcessResult result = processUtil.getLibCoapClientVersion(TIMEOUT_MILLIS);
		assumeNotNull(result);
		assumeTrue(result.contains(LibCoapProcessUtil.LIBCOAP_CLIENT + " v4\\.2\\.1 "));
		assumeTrue(result.contains("OpenSSL - runtime 1\\.1\\.1,"));
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
		processUtil.setVerboseLevel(null);
	}

	@Test
	public void testLibCoapClientPsk() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", AuthenticationMode.PSK, "Hello, CoAP!",
				cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
	}

	@Test
	public void testLibCoapClientPskMultiFragment() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
		builder.setEnableMultiHandshakeMessageRecords(true);
		californiumUtil.start(BIND, false, builder, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", AuthenticationMode.PSK, "Hello, CoAP!",
				cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
	}

	@Test
	public void testLibCoapClientPskNoSessionId() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
		builder.setNoServerSessionId(true);
		californiumUtil.start(BIND, false, builder, null, cipherSuite);

		processUtil.startupClientTinyDtls(DESTINATION_URL + "test", AuthenticationMode.PSK, "Hello, CoAP!",
				cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
	}

	@Test
	public void testLibCoapClientPsk1k() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "large", AuthenticationMode.PSK, "Hello, CoAP!",
				cipherSuite);
		ProcessResult result = connect("Hello, CoAP!",
				"###############################################################");
		assertThat(result, is(notNullValue()));
		assertThat(result.console, is(notNullValue()));
		assertThat(result.console.length(), is(greaterThan(1024)));
	}

	@Test
	public void testLibCoapClientPsk4k() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "large?size=4096", AuthenticationMode.PSK, "Hello, CoAP!",
				cipherSuite);
		ProcessResult result = connect("Hello, CoAP!",
				"###############################################################");
		assertThat(result, is(notNullValue()));
		assertThat(result.console, is(notNullValue()));
		assertThat(result.console.length(), is(greaterThan(4096)));
	}

	@Test
	public void testLibCoapClientEcdsa() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", AuthenticationMode.CERTIFICATE, "Hello, CoAP!",
				cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
	}

	@Test
	public void testLibCoapClientEcdsaRsa() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, true, null, ScandiumUtil.TRUST_ROOT, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", AuthenticationMode.CERTIFICATE, "Hello, CoAP!",
				cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
	}

	@Test
	public void testLibCoapClientEcdsaTrust() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", AuthenticationMode.TRUST, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
	}

	@Test
	public void testLibCoapClientEcdsaRsaTrust() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, true, null, ScandiumUtil.TRUST_ROOT, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", AuthenticationMode.TRUST, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
	}

	@Test
	public void testLibCoapClientCustomOptions() throws Exception {
		processUtil.setVerboseLevel("6");
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "custom", AuthenticationMode.PSK, "Hello, CoAP!",
				cipherSuite);
		connect("Hello, CoAP!", "Content-Format:65525", "65022:\\\\x74\\\\x65\\\\x73\\\\x74", "Custom Greetings!");
	}

	@Test
	public void testLibCoapClientLocation() throws Exception {
		processUtil.setVerboseLevel("6");
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "event", AuthenticationMode.PSK, "Hello, CoAP!",
				cipherSuite);
		connect("Hello, CoAP!", "Response!", "Location-Path:command", "Location-Path:1234-abcde", "Location-Query:hono-command=blink");
	}

	public ProcessResult connect(String sendMessage, String... patterns) throws Exception {
		if (patterns != null) {
			for (String check : patterns) {
				assertTrue("missing " + check, processUtil.waitConsole(check, TIMEOUT_MILLIS));
			}
		}
		californiumUtil.assertReceivedData(sendMessage, TIMEOUT_MILLIS);
		return processUtil.stop(TIMEOUT_MILLIS);
	}
}
