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
package org.eclipse.californium.interoperability.test;

import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeNotNull;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;

import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.TestScope;
import org.eclipse.californium.interoperability.test.OpenSslUtil.AuthenticationMode;
import org.eclipse.californium.interoperability.test.ProcessUtil.ProcessResult;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
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

	private static final long TIMEOUT_MILLIS = 2000;

	private static OpenSslProcessUtil processUtil;
	private static ScandiumUtil scandiumUtil;

	@BeforeClass
	public static void init() throws IOException, InterruptedException {
		processUtil = new OpenSslProcessUtil();
		ProcessResult result = processUtil.getOpenSslVersion(TIMEOUT_MILLIS);
		assumeNotNull(result);
		assumeTrue(result.contains("OpenSSL 1\\.1\\."));
		String os = System.getProperty("os.name");
		if (os.startsWith("Windows")) {
			assumeFalse("Windows openssl server 1.1.1 seems to be broken!", result.contains("OpenSSL 1\\.1\\.1[abcd]"));
		}
		scandiumUtil = new ScandiumUtil(true);
	}

	@AfterClass
	public static void shutdown() throws InterruptedException {
		if (processUtil != null) {
			processUtil.shutdown();
		}
	}

	@Parameter
	public CipherSuite cipherSuite;

	/**
	 * @return List of cipher suites.
	 */
	@Parameters(name = "{0}")
	public static Iterable<CipherSuite> cipherSuiteParams() {
		if (TestScope.enableIntensiveTests()) {
			return OpenSslUtil.getSupportedCipherSuites();
		} else {
			if (CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.isSupported()) {
				return Arrays.asList(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
						CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
			} else {
				return Arrays.asList(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
						CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM);
			}
		}
	}

	@After
	public void stop() throws InterruptedException {
		if (scandiumUtil != null) {
			scandiumUtil.shutdown();
		}
		processUtil.shutdown();
	}

	/**
	 * Establish a "connection" and send a message to the server and back to the
	 * client.
	 */
	@Test
	public void testOpenSslServer() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, AuthenticationMode.CERTIFICATE, cipherSuite);

		scandiumUtil.start(BIND, null, cipherSuite);

		String message = "Hello OpenSSL!";
		scandiumUtil.send(message, DESTINATION, TIMEOUT_MILLIS);

		processUtil.waitConsole("CIPHER is " + cipher, TIMEOUT_MILLIS);
		processUtil.waitConsole(message, TIMEOUT_MILLIS);
		processUtil.send("ACK-" + message);

		scandiumUtil.assertReceivedData("ACK-" + message, TIMEOUT_MILLIS);

		processUtil.stop(TIMEOUT_MILLIS);
	}

	@Test
	public void testOpenSslServerMultiFragments() throws Exception {
		String cipher = processUtil.startupServer(ACCEPT, AuthenticationMode.CERTIFICATE, cipherSuite);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
		builder.setEnableMultiHandshakeMessageRecords(true);
		scandiumUtil.start(BIND, false, builder, null, cipherSuite);

		String message = "Hello OpenSSL!";
		scandiumUtil.send(message, DESTINATION, TIMEOUT_MILLIS);

		processUtil.waitConsole("CIPHER is " + cipher, TIMEOUT_MILLIS);
		processUtil.waitConsole(message, TIMEOUT_MILLIS);
		processUtil.send("ACK-" + message);

		scandiumUtil.assertReceivedData("ACK-" + message, TIMEOUT_MILLIS);

		processUtil.stop(TIMEOUT_MILLIS);
	}
}
