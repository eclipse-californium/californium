/*******************************************************************************
 * Copyright (c) 2022 Contributors to the Eclipse Foundation.
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
 ******************************************************************************/
package org.eclipse.californium.interoperability.test.tinydtls;

import static org.eclipse.californium.interoperability.test.ConnectorUtil.HANDSHAKE_TIMEOUT_MILLIS;
import static org.eclipse.californium.interoperability.test.ProcessUtil.TIMEOUT_MILLIS;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.interoperability.test.ScandiumUtil;
import org.eclipse.californium.interoperability.test.ShutdownUtil;
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
 * Test for interoperability with tinydtls client.
 * 
 * Test several different cipher suites.
 * 
 * @see TinydtlsUtil
 * @since 3.8
 */
@RunWith(Parameterized.class)
public class TinydtlsClientInteroperabilityTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final InetSocketAddress BIND = new InetSocketAddress(InetAddress.getLoopbackAddress(),
			ScandiumUtil.PORT);
	private static final String DESTINATION = "127.0.0.1";

	private static TinydtlsProcessUtil processUtil;
	private static ScandiumUtil scandiumUtil;

	@BeforeClass
	public static void init() throws IOException, InterruptedException {
		processUtil = new TinydtlsProcessUtil();
		processUtil.assumeMinVersion("0.8.6");
		scandiumUtil = new ScandiumUtil(false);
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
		return TinydtlsUtil.getSupportedTestCipherSuites();
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
	public void testTinydtlsClient() throws Exception {
		processUtil.setTag("tinydtls-client, " + cipherSuite.name());
		scandiumUtil.start(BIND, null, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, ScandiumUtil.PORT,
				TinydtlsProcessUtil.AuthenticationMode.PSK, cipherSuite);
		assertTrue(processUtil.waitConsole("encrypt using " + cipher, HANDSHAKE_TIMEOUT_MILLIS));
		assertTrue(processUtil.waitConsole("Handshake complete", HANDSHAKE_TIMEOUT_MILLIS));

		String message = "Hello Scandium!\n";
		processUtil.send(message);

		scandiumUtil.assertReceivedData(message, TIMEOUT_MILLIS);
		scandiumUtil.response("ACK-" + message, TIMEOUT_MILLIS);

		assertTrue(processUtil.waitConsole("ACK-" + message, TIMEOUT_MILLIS));

		processUtil.send("client:exit\n");

		processUtil.stop(TIMEOUT_MILLIS);
	}

	@Test
	public void testTinydtlsClientCid() throws Exception {
		processUtil.setTag("tinydtls-client, cid, " + cipherSuite.name());
		processUtil.addExtraArgs("-z", "-e", "-r");
		scandiumUtil.start(BIND, null, cipherSuite);

		String cipher = processUtil.startupClient(DESTINATION, ScandiumUtil.PORT,
				TinydtlsProcessUtil.AuthenticationMode.PSK, cipherSuite);
		assertTrue(processUtil.waitConsole("encrypt using " + cipher, HANDSHAKE_TIMEOUT_MILLIS));
		assertTrue(processUtil.waitConsole("Handshake complete", HANDSHAKE_TIMEOUT_MILLIS));

		String message = "Hello Scandium!\n";
		processUtil.send(message);

		scandiumUtil.assertReceivedData(message, TIMEOUT_MILLIS);
		scandiumUtil.response("ACK-" + message, TIMEOUT_MILLIS);

		assertTrue(processUtil.waitConsole("ACK-" + message, TIMEOUT_MILLIS));

		processUtil.send("client:exit\n");

		EndpointContext context = scandiumUtil.getContext(TIMEOUT_MILLIS);
		Bytes bytes = context.get(DtlsEndpointContext.KEY_READ_CONNECTION_ID);
		assertNotNull("Missing CID", bytes);
		assertFalse("Empyt CID", bytes.isEmpty());
		Boolean extendedMasterSecret = context.get(DtlsEndpointContext.KEY_EXTENDED_MASTER_SECRET);
		assertEquals("Missing extended master secret", Boolean.TRUE, extendedMasterSecret);

		processUtil.stop(TIMEOUT_MILLIS);
	}

}
