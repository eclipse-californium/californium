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

import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeNotNull;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.interoperability.test.OpenSslUtil.AuthenticationMode;
import org.eclipse.californium.interoperability.test.ProcessUtil.ProcessResult;
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
 * Test for interoperability with openssl client.
 * 
 * Test several different cipher suites.
 * 
 * @see OpenSslUtil
 */
@RunWith(Parameterized.class)
public class OpenSslClientInteroperabilityTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final InetSocketAddress BIND = new InetSocketAddress(InetAddress.getLoopbackAddress(),
			ScandiumUtil.PORT);
	private static final String DESTINATION = "127.0.0.1:" + ScandiumUtil.PORT;
	private static final long TIMEOUT_MILLIS = 2000;

	private static OpenSslProcessUtil processUtil;
	private static ScandiumUtil scandiumUtil;

	@BeforeClass
	public static void init() throws IOException, InterruptedException {
		processUtil = new OpenSslProcessUtil();
		ProcessResult result = processUtil.getOpenSslVersion(TIMEOUT_MILLIS);
		assumeNotNull(result);
		assumeTrue(result.contains("OpenSSL 1\\.1\\."));
		scandiumUtil = new ScandiumUtil(false);
	}

	@AfterClass
	public static void shutdown() throws InterruptedException {
		if (scandiumUtil != null) {
			scandiumUtil.shutdown();
			scandiumUtil = null;
		}
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
		return OpenSslUtil.CIPHERSUITES_MAP.keySet();
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
	public void testOpenSslClient() throws Exception {
		scandiumUtil.start(BIND, null, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, AuthenticationMode.CERTIFICATE, cipherSuite);
		assertTrue(processUtil.waitConsole("Cipher is " + cipher, TIMEOUT_MILLIS));

		String message = "Hello Scandium!";
		processUtil.send(message);

		scandiumUtil.assertReceivedData(message, TIMEOUT_MILLIS);
		scandiumUtil.response("ACK-" + message, TIMEOUT_MILLIS);

		assertTrue(processUtil.waitConsole("ACK-" + message, TIMEOUT_MILLIS));

		processUtil.stop(TIMEOUT_MILLIS);
	}
}
