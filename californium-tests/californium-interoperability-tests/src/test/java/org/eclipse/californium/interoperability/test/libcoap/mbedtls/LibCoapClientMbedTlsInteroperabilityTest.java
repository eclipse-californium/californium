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

import static org.eclipse.californium.interoperability.test.CredentialslUtil.SERVER_CA_RSA_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.CLIENT_RSA_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.ProcessUtil.TIMEOUT_MILLIS;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.REQUEST_TIMEOUT_MILLIS;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.LibCoapAuthenticationMode.CA;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.LibCoapAuthenticationMode.CHAIN;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.LibCoapAuthenticationMode.PSK;
import static org.eclipse.californium.interoperability.test.libcoap.LibCoapProcessUtil.LibCoapAuthenticationMode.TRUST;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeNotNull;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

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
 * Test for interoperability with libcoap client using mbedtls.
 * 
 * @see LibCoapProcessUtil
 */
public class LibCoapClientMbedTlsInteroperabilityTest {

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
		ProcessResult result = processUtil.prepareLibCoapClientMbedTls(TIMEOUT_MILLIS);
		assumeNotNull(result);
		processUtil.assumeMinVersion("4.3.0");
		processUtil.assumeMinDtlsVersion("2.16.5");
		californiumUtil = new CaliforniumUtil(false);
	}

	@AfterClass
	public static void shutdown() throws InterruptedException {
		ShutdownUtil.shutdown(californiumUtil, processUtil);
	}

	private DtlsConnectorConfig.Builder builder;

	@Before
	public void start() {
		processUtil.setTag(name.getName());
		// mbedtls v2.27 still supports only the deprecated MAC calculation.
		// Ensure/adjust the extension id in mbedtls - include/mbedtls/ssl.h
		// for compatibility to 53
		// 
		// #define MBEDTLS_TLS_EXT_CID                        53
		// 
		// For libcoap enable the passive use of CID in src/coap_mbedtls.c,
		// coap_dtls_new_mbedtls_env, before mbedtls_ssl_set_bio with
		// 
		// mbedtls_ssl_set_cid(&m_env->ssl, MBEDTLS_SSL_CID_ENABLED, NULL, 0);

		builder = DtlsConnectorConfig.builder(new Configuration())
				.set(DtlsConfig.DTLS_SUPPORT_DEPRECATED_CID, true);
	}

	@After
	public void stop() throws InterruptedException {
		ShutdownUtil.shutdown(californiumUtil, processUtil);
	}

	@Test
	public void testLibCoapClientPskGCM() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256;
		assumeTrue("GCM not support by JCE", cipherSuite.isSupported());
		californiumUtil.start(BIND, builder, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", PSK, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
		californiumUtil.assertPrincipalType(PreSharedKeyIdentity.class);
	}

	@Test
	public void testLibCoapClientPsk() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, builder, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", PSK, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
		californiumUtil.assertPrincipalType(PreSharedKeyIdentity.class);
	}

	@Test
	public void testLibCoapClientPskMultiFragment() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		builder.set(DtlsConfig.DTLS_USE_MULTI_HANDSHAKE_MESSAGE_RECORDS, true);
		californiumUtil.start(BIND,  builder, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", PSK, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
		californiumUtil.assertPrincipalType(PreSharedKeyIdentity.class);
	}

	@Test
	public void testLibCoapClientPskNoSessionId() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CCM_8;
		builder.set(DtlsConfig.DTLS_SERVER_USE_SESSION_ID, false);
		californiumUtil.start(BIND, builder, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", PSK, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
		californiumUtil.assertPrincipalType(PreSharedKeyIdentity.class);
	}

	@Test
	public void testLibCoapClientEcdsaGCM() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
		assumeTrue("GCM not support by JCE", cipherSuite.isSupported());
		californiumUtil.start(BIND, builder, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", CHAIN, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapClientEcdsa() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, builder, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", CHAIN, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapClientEcdsaRsa() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		californiumUtil.loadCredentials(ConnectorUtil.SERVER_CA_RSA_NAME);
		californiumUtil.start(BIND, builder, ScandiumUtil.TRUST_ROOT, cipherSuite);

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
		californiumUtil.start(BIND, builder, null, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", TRUST, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
		californiumUtil.assertPrincipalType(X509CertPath.class);
	}

	@Test
	public void testLibCoapClientEcdsaTrustFails() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, builder, null, cipherSuite);

		processUtil.setTrusts(SERVER_CA_RSA_CERTIFICATE);
		processUtil.startupClient(DESTINATION_URL + "test", TRUST, "Hello, CoAP!", cipherSuite);
		connect(null, "X509 - Certificate verification failed");
		californiumUtil.assertAlert(TIMEOUT_MILLIS, new AlertMessage(AlertLevel.FATAL, AlertDescription.UNKNOWN_CA));
	}

	@Test
	public void testLibCoapClientEcdsaCaFails() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		californiumUtil.start(BIND, builder, null, cipherSuite);

		processUtil.setCa(SERVER_CA_RSA_CERTIFICATE);
		processUtil.startupClient(DESTINATION_URL + "test", CA, "Hello, CoAP!", cipherSuite);
		connect(null, "X509 - Certificate verification failed");
		californiumUtil.assertAlert(TIMEOUT_MILLIS, new AlertMessage(AlertLevel.FATAL, AlertDescription.UNKNOWN_CA));
	}

	@Test
	public void testLibCoapClientEcdsaRsaTrust() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
		californiumUtil.loadCredentials(ConnectorUtil.SERVER_CA_RSA_NAME);
		californiumUtil.start(BIND, builder, ScandiumUtil.TRUST_ROOT, cipherSuite);

		processUtil.startupClient(DESTINATION_URL + "test", TRUST, "Hello, CoAP!", cipherSuite);
		connect("Hello, CoAP!", "Greetings!");
		californiumUtil.assertPrincipalType(X509CertPath.class);
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
