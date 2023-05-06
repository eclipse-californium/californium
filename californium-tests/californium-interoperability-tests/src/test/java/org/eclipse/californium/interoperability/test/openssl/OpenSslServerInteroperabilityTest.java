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
import static org.eclipse.californium.interoperability.test.ProcessUtil.TIMEOUT_MILLIS;
import static org.eclipse.californium.interoperability.test.ProcessUtil.FOLLOW_UP_TIMEOUT_MILLIS;
import static org.eclipse.californium.interoperability.test.openssl.OpenSslProcessUtil.AuthenticationMode.CERTIFICATE;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.interoperability.test.ScandiumUtil;
import org.eclipse.californium.interoperability.test.ShutdownUtil;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConfig.DtlsRole;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
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
 * Test for interoperability with openssl server.
 * 
 * Test several different cipher suites.
 * 
 * Note: the windows version 1.1.1a to 1.1.1d of the openssl s_server seems to
 * be broken. It starts only to accept, when the first message is entered.
 * Therefore the test are skipped on windows.
 * 
 * @see OpenSslUtil
 */
@RunWith(Parameterized.class)
public class OpenSslServerInteroperabilityTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final InetSocketAddress BIND = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
	private static final InetSocketAddress DESTINATION = new InetSocketAddress(InetAddress.getLoopbackAddress(),
			ScandiumUtil.PORT);
	private static final String ACCEPT = "127.0.0.1:" + ScandiumUtil.PORT;

	private static OpenSslProcessUtil processUtil;
	private static ScandiumUtil scandiumUtil;

	@BeforeClass
	public static void init() throws IOException, InterruptedException {
		processUtil = new OpenSslProcessUtil();
		processUtil.assumeMinVersion("1.1.");
		processUtil.assumeServerVersion();
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
		return OpenSslUtil.getSupportedTestCipherSuites();
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
	public void testOpenSslServer() throws Exception {
		processUtil.setTag("openssl-server, " + cipherSuite.name());
		String certificate = cipherSuite.getCertificateKeyAlgorithm() == CertificateKeyAlgorithm.RSA ?
				SERVER_RSA_CERTIFICATE : SERVER_CERTIFICATE;
		String cipher = processUtil.startupServer(ACCEPT, CERTIFICATE, certificate, null, null, cipherSuite);

		DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder(new Configuration())
				.set(DtlsConfig.DTLS_ROLE, DtlsRole.CLIENT_ONLY);
		scandiumUtil.start(BIND, builder, null, cipherSuite);

		String message = "Hello OpenSSL!";
		scandiumUtil.send(message, DESTINATION, HANDSHAKE_TIMEOUT_MILLIS);

		assertTrue(processUtil.waitConsole("CIPHER is ", TIMEOUT_MILLIS));
		assertTrue(processUtil.waitConsole("CIPHER is " + cipher, FOLLOW_UP_TIMEOUT_MILLIS));
		assertTrue(processUtil.waitConsole(message, TIMEOUT_MILLIS));
		processUtil.send("ACK-" + message);

		scandiumUtil.assertReceivedData("ACK-" + message, TIMEOUT_MILLIS);

		processUtil.stop(TIMEOUT_MILLIS);
	}

	@Test
	public void testOpenSslServerMultiFragments() throws Exception {
		processUtil.setTag("openssl-server, multifragments per record, " + cipherSuite.name());

		String certificate = cipherSuite.getCertificateKeyAlgorithm() == CertificateKeyAlgorithm.RSA ?
				SERVER_RSA_CERTIFICATE : SERVER_CERTIFICATE;
		String cipher = processUtil.startupServer(ACCEPT, CERTIFICATE, certificate, null, null, cipherSuite);

		DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder(new Configuration())
				.set(DtlsConfig.DTLS_ROLE, DtlsRole.CLIENT_ONLY)
				.set(DtlsConfig.DTLS_USE_MULTI_HANDSHAKE_MESSAGE_RECORDS, true);
		scandiumUtil.start(BIND, builder, null, cipherSuite);

		String message = "Hello OpenSSL!";
		scandiumUtil.send(message, DESTINATION, HANDSHAKE_TIMEOUT_MILLIS);

		assertTrue(processUtil.waitConsole("CIPHER is ", TIMEOUT_MILLIS));
		assertTrue(processUtil.waitConsole("CIPHER is " + cipher, FOLLOW_UP_TIMEOUT_MILLIS));
		assertTrue(processUtil.waitConsole(message, TIMEOUT_MILLIS));
		processUtil.send("ACK-" + message);

		scandiumUtil.assertReceivedData("ACK-" + message, TIMEOUT_MILLIS);

		processUtil.stop(TIMEOUT_MILLIS);
	}
}
