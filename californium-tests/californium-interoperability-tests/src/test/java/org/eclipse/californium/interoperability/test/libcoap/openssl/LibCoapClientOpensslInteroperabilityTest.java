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
package org.eclipse.californium.interoperability.test.libcoap.openssl;

import static org.eclipse.californium.interoperability.test.CredentialslUtil.CLIENT_RSA_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.SERVER_CA_RSA_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.ProcessUtil.TIMEOUT_MILLIS;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.REQUEST_TIMEOUT_MILLIS;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.LibCoapAuthenticationMode.CA;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.LibCoapAuthenticationMode.CHAIN;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.LibCoapAuthenticationMode.PSK;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.LibCoapAuthenticationMode.TRUST;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeNotNull;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.NoResponseOption;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.elements.auth.PreSharedKeyIdentity;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.interoperability.test.CaliforniumUtil;
import org.eclipse.californium.interoperability.test.ConnectorUtil;
import org.eclipse.californium.interoperability.test.ProcessUtil.ProcessResult;
import org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil;
import org.eclipse.californium.interoperability.test.ScandiumUtil;
import org.eclipse.californium.interoperability.test.ShutdownUtil;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

/**
 * Test for interoperability with libcoap client using openssl.
 * 
 * @see LibCoapProcessUtil
 */
public class LibCoapClientOpensslInteroperabilityTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final InetSocketAddress BIND = new InetSocketAddress(InetAddress.getLoopbackAddress(),
			ScandiumUtil.PORT);
	private static final String DESTINATION = "127.0.0.1:" + ScandiumUtil.PORT;
	private static final String DESTINATION_URL = "coaps://" + DESTINATION + "/";

	private static LibCoapProcessUtil processUtil;
	private static CaliforniumUtil californiumUtil;

	@BeforeClass
	public static void init() throws IOException, InterruptedException {
		processUtil = new LibCoapProcessUtil();
		ProcessResult result = processUtil.prepareLibCoapClientOpenssl(TIMEOUT_MILLIS);
		assumeNotNull(result);
		processUtil.assumeMinVersion("4.2.1");
		processUtil.assumeMinDtlsVersion("1.1.1");
		californiumUtil = new CaliforniumUtil(false);
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
	public void testLibCoapClientPskGCM() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256;
		assumeTrue("GCM not support by JCE", cipherSuite.isSupported());
		californiumUtil.start(BIND, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", PSK, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
		californiumUtil.assertPrincipalType(PreSharedKeyIdentity.class);
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
		DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder(new Configuration())
				.set(DtlsConfig.DTLS_USE_MULTI_HANDSHAKE_MESSAGE_RECORDS, true);
		californiumUtil.start(BIND, builder, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", PSK, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
		californiumUtil.assertPrincipalType(PreSharedKeyIdentity.class);
	}

	@Test
	public void testLibCoapClientPskNoSessionId() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder(new Configuration())
				.set(DtlsConfig.DTLS_SERVER_USE_SESSION_ID, false);
		californiumUtil.start(BIND, builder, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", PSK, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
		californiumUtil.assertPrincipalType(PreSharedKeyIdentity.class);
	}

	@Test
	public void testLibCoapClientPskNoResponse() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, null, cipherSuite);
		processUtil.setClientMessageType(CoAP.Type.NON);
		processUtil.setClientOption(new NoResponseOption(NoResponseOption.SUPPRESS_SUCCESS).toOption());
		processUtil.startupClient(DESTINATION_URL + "test", PSK, "Hello, CoAP!", cipherSuite);
		californiumUtil.assertReceivedData("Hello, CoAP!", REQUEST_TIMEOUT_MILLIS.get());
		assertFalse("unexpected \"Greetings!\" received", processUtil.waitConsole("Greetings!", REQUEST_TIMEOUT_MILLIS.get()));
		californiumUtil.assertPrincipalType(PreSharedKeyIdentity.class);
		processUtil.stop(TIMEOUT_MILLIS);
	}

	@Test
	public void testLibCoapClientPsk1k() throws Exception {
		processUtil.setVerboseLevel(null);
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "large", PSK, "Hello, CoAP!", cipherSuite);
		ProcessResult result = connect("Hello, CoAP!",
				"0f#############################################################");
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
				"3f#############################################################");
		assertThat(result, is(notNullValue()));
		assertThat(result.console, is(notNullValue()));
		assertThat(result.console.length(), is(greaterThan(4096)));
		californiumUtil.assertPrincipalType(PreSharedKeyIdentity.class);
	}

	@Test
	public void testLibCoapClientPsk4k4kSmallBlocks() throws Exception {
		processUtil.setVerboseLevel(null);
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, null, cipherSuite);
		String message = "Hello, CoAP! " + californiumUtil.createTextPayload(4096);
		processUtil.setClientBlocksize(128);
		int szx = BlockOption.size2Szx(128);
		processUtil.setClientOption(StandardOptionRegistry.BLOCK2.create(new BlockOption(szx, false, 0).getValue()));
		processUtil.startupClient(DESTINATION_URL + "large?size=4096", PSK, message, cipherSuite);
		ProcessResult result = connect(message,
				"3f#############################################################");
		assertThat(result, is(notNullValue()));
		assertThat(result.console, is(notNullValue()));
		assertThat(result.console.length(), is(greaterThan(4096)));
		californiumUtil.assertPrincipalType(PreSharedKeyIdentity.class);
	}

	@Test
	public void testLibCoapClientEcdsaGCM() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
		assumeTrue("GCM not support by JCE", cipherSuite.isSupported());
		californiumUtil.start(BIND, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", CHAIN, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
		californiumUtil.assertPrincipalType(X509CertPath.class);
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
		californiumUtil.loadCredentials(ConnectorUtil.SERVER_CA_RSA_NAME);
		californiumUtil.start(BIND, null, ScandiumUtil.TRUST_ROOT, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", CHAIN, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapClientRsa() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.isSupported()
				? CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
				: CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
		assumeTrue(cipherSuite.name() + " not support by JCE", cipherSuite.isSupported());

		californiumUtil.loadCredentials(ConnectorUtil.SERVER_RSA_NAME);
		californiumUtil.start(BIND, null, ScandiumUtil.TRUST_ROOT, cipherSuite);

		processUtil.setCertificate(CLIENT_RSA_CERTIFICATE);
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
		processUtil.setTrusts(SERVER_CA_RSA_CERTIFICATE);
		processUtil.startupClient(DESTINATION_URL + "test", TRUST, "Hello, CoAP!", cipherSuite);
		connect(null, "SSL3 alert write:fatal:unknown CA");
		californiumUtil.assertAlert(TIMEOUT_MILLIS, new AlertMessage(AlertLevel.FATAL, AlertDescription.UNKNOWN_CA));
	}

	@Test
	public void testLibCoapClientEcdsaCaFails() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, null, cipherSuite);
		processUtil.setCa(SERVER_CA_RSA_CERTIFICATE);
		processUtil.startupClient(DESTINATION_URL + "test", CA, "Hello, CoAP!", cipherSuite);
		connect(null, "SSL3 alert write:fatal:unknown CA");
		californiumUtil.assertAlert(TIMEOUT_MILLIS, new AlertMessage(AlertLevel.FATAL, AlertDescription.UNKNOWN_CA));
	}

	@Test
	public void testLibCoapClientEcdsaRsaTrust() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		californiumUtil.loadCredentials(ConnectorUtil.SERVER_CA_RSA_NAME);
		californiumUtil.start(BIND, null, ScandiumUtil.TRUST_ROOT, cipherSuite);

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
				assertTrue("missing " + check, processUtil.waitConsole(check, REQUEST_TIMEOUT_MILLIS.get()));
			}
		}
		if (sendMessage != null) {
			californiumUtil.assertReceivedData(sendMessage, REQUEST_TIMEOUT_MILLIS.get());
		}
		return processUtil.stop(TIMEOUT_MILLIS);
	}
}
