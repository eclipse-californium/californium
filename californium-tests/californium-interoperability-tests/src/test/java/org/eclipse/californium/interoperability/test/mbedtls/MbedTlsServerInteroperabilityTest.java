/*******************************************************************************
 * Copyright (c) 2022 Bosch IO GmbH and others.
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
 *    Bosch.IO GmbH - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.interoperability.test.mbedtls;

import static org.eclipse.californium.interoperability.test.ConnectorUtil.HANDSHAKE_TIMEOUT_MILLIS;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.SERVER_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.SERVER_RSA_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.ProcessUtil.TIMEOUT_MILLIS;
import static org.eclipse.californium.interoperability.test.mbedtls.MbedTlsProcessUtil.AuthenticationMode.CHAIN;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.interoperability.test.ScandiumUtil;
import org.eclipse.californium.interoperability.test.ShutdownUtil;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConfig.DtlsRole;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.CertificateKeyAlgorithm;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/**
 * Test for interoperability with Mbed TLS server.
 * 
 * Test several different cipher suites.
 * 
 * @see MbedTlsUtil
 * @since 3.3
 */
@RunWith(Parameterized.class)
public class MbedTlsServerInteroperabilityTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final InetSocketAddress BIND = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
	private static final InetSocketAddress DESTINATION = new InetSocketAddress(InetAddress.getLoopbackAddress(),
			ScandiumUtil.PORT);
	private static final String ACCEPT = "127.0.0.1";

	private static MbedTlsProcessUtil processUtil;
	private static ScandiumUtil scandiumUtil;

	@BeforeClass
	public static void init() throws IOException, InterruptedException {
		processUtil = new MbedTlsProcessUtil();
		processUtil.assumeMinVersion("3.2.");
		scandiumUtil = new ScandiumUtil(true);
	}

	@AfterClass
	public static void shutdown() throws InterruptedException {
		ShutdownUtil.shutdown(scandiumUtil, processUtil);
	}

	@Parameter
	public CipherSuite cipherSuite;

	/**
	 * @return List of cipher suites.
	 */
	@Parameters(name = "{0}")
	public static Iterable<CipherSuite> cipherSuiteParams() {
		return MbedTlsUtil.getSupportedTestCipherSuites();
	}

	@After
	public void stop() throws InterruptedException {
		ShutdownUtil.shutdown(scandiumUtil, processUtil);
	}

	/**
	 * Establish a "connection" and send a message to the server and back to the
	 * client.
	 */
	@Test
	public void testMbedTlsServer() throws Exception {
		processUtil.setTag("mbedtls-server, " + cipherSuite.name());
		String certificate = cipherSuite.getCertificateKeyAlgorithm() == CertificateKeyAlgorithm.RSA ?
				SERVER_RSA_CERTIFICATE : SERVER_CERTIFICATE;
		String cipher = processUtil.startupServer(ACCEPT, ScandiumUtil.PORT, CHAIN, certificate, null, cipherSuite);

		DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder(new Configuration())
				.set(DtlsConfig.DTLS_ROLE, DtlsRole.CLIENT_ONLY);
		scandiumUtil.start(BIND, builder, null, cipherSuite);

		String message = "Hello MbedTLS!";
		scandiumUtil.send(message, DESTINATION, HANDSHAKE_TIMEOUT_MILLIS);

		assertTrue(processUtil.waitConsole("Ciphersuite is " + cipher, TIMEOUT_MILLIS));
		assertTrue(processUtil.waitConsole(message, TIMEOUT_MILLIS));

		// Mbed TLS server responds with HTTP 200, even in DTLS mode
		scandiumUtil.assertContainsReceivedData("HTTP/1.0 200 OK", TIMEOUT_MILLIS);

		processUtil.stop(200);
	}

	/**
	 * Establish a "connection" and send a message to the server and back to the
	 * client. Enables to use multiple handshake messages per record.
	 */
	@Test
	public void testMbedTlsServerMultiFragments() throws Exception {
		processUtil.setTag("mbedtls-server,  multiple handshake messages per record, " + cipherSuite.name());

		String certificate = cipherSuite.getCertificateKeyAlgorithm() == CertificateKeyAlgorithm.RSA ?
				SERVER_RSA_CERTIFICATE : SERVER_CERTIFICATE;
		String cipher = processUtil.startupServer(ACCEPT, ScandiumUtil.PORT, CHAIN, certificate, null, cipherSuite);

		DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder(new Configuration())
				.set(DtlsConfig.DTLS_ROLE, DtlsRole.CLIENT_ONLY)
				.set(DtlsConfig.DTLS_USE_MULTI_HANDSHAKE_MESSAGE_RECORDS, true);
		scandiumUtil.start(BIND, builder, null, cipherSuite);

		String message = "Hello MbedTLS!";
		scandiumUtil.send(message, DESTINATION, HANDSHAKE_TIMEOUT_MILLIS);

		assertTrue(processUtil.waitConsole("Ciphersuite is " + cipher, TIMEOUT_MILLIS));
		assertTrue(processUtil.waitConsole(message, TIMEOUT_MILLIS));

		// Mbed TLS server responds with HTTP 200, even in DTLS mode
		scandiumUtil.assertContainsReceivedData("HTTP/1.0 200 OK", TIMEOUT_MILLIS);

		processUtil.stop(200);
	}

	/**
	 * Establish a "connection" and send a message to the server and back to the
	 * client. Use DTLS 1.2 CID.
	 */
	@Test
	public void testMbedTlsServerCID() throws Exception {
		Bytes cid = new ConnectionId(new byte[] { 0, 1, 2, 3 });
		processUtil.setTag("mbedtls-server, " + cipherSuite.name());
		processUtil.addExtraArgs("cid=1", "cid_val=" + cid.getAsString());
		String certificate = cipherSuite.getCertificateKeyAlgorithm() == CertificateKeyAlgorithm.RSA ?
				SERVER_RSA_CERTIFICATE : SERVER_CERTIFICATE;
		String cipher = processUtil.startupServer(ACCEPT, ScandiumUtil.PORT, CHAIN, certificate, null, cipherSuite);

		DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder(new Configuration())
				.set(DtlsConfig.DTLS_ROLE, DtlsRole.CLIENT_ONLY);
		scandiumUtil.start(BIND, builder, null, cipherSuite);

		String message = "Hello MbedTLS!";
		scandiumUtil.send(message, DESTINATION, HANDSHAKE_TIMEOUT_MILLIS);

		assertTrue(processUtil.waitConsole("Ciphersuite is " + cipher, TIMEOUT_MILLIS));
		assertTrue(processUtil.waitConsole(message, TIMEOUT_MILLIS));

		// Mbed TLS server responds with HTTP 200, even in DTLS mode
		scandiumUtil.assertContainsReceivedData("HTTP/1.0 200 OK", TIMEOUT_MILLIS);

		EndpointContext context = scandiumUtil.getContext(TIMEOUT_MILLIS);
		Bytes bytes = context.get(DtlsEndpointContext.KEY_READ_CONNECTION_ID);
		assertNotNull("Missing read CID", bytes);
		assertFalse("Empyt read CID", bytes.isEmpty());
		bytes = context.get(DtlsEndpointContext.KEY_WRITE_CONNECTION_ID);
		assertThat("Write CID", bytes, is(cid));

		processUtil.stop(200);
	}
}
