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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.interoperability.test.ScandiumUtil;
import org.eclipse.californium.interoperability.test.ShutdownUtil;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConfig.DtlsRole;
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
 * Test for interoperability with tinydtls server.
 * 
 * Test several different cipher suites.
 * 
 * @see TinydtlsUtil
 * @since 3.8
 */
@RunWith(Parameterized.class)
public class TinydtlsServerInteroperabilityTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final InetSocketAddress BIND = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
	private static final InetSocketAddress DESTINATION = new InetSocketAddress(InetAddress.getLoopbackAddress(),
			ScandiumUtil.PORT);
	private static final String ACCEPT = "127.0.0.1";

	private static TinydtlsProcessUtil processUtil;
	private static ScandiumUtil scandiumUtil;

	@BeforeClass
	public static void init() throws IOException, InterruptedException {
		processUtil = new TinydtlsProcessUtil();
		processUtil.assumeMinVersion("0.8.6");
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
	public void testTinydtlsServer() throws Exception {
		processUtil.setTag("tinydtls-server, " + cipherSuite.name());
		String cipher = processUtil.startupServer(ACCEPT, ScandiumUtil.PORT, TinydtlsProcessUtil.AuthenticationMode.PSK,
				cipherSuite);

		DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder(new Configuration()).set(DtlsConfig.DTLS_ROLE,
				DtlsRole.CLIENT_ONLY);
		scandiumUtil.start(BIND, builder, null, cipherSuite);

		String message = "Hello Scandium!\n";
		scandiumUtil.send(message, DESTINATION, HANDSHAKE_TIMEOUT_MILLIS);

		assertTrue(processUtil.waitConsole("encrypt using " + cipher, TIMEOUT_MILLIS));
		assertTrue(processUtil.waitConsole(message, TIMEOUT_MILLIS));

		scandiumUtil.assertReceivedData(message, TIMEOUT_MILLIS);

		message = "server:exit\n";
		scandiumUtil.send(message, DESTINATION, HANDSHAKE_TIMEOUT_MILLIS);

		processUtil.stop(TIMEOUT_MILLIS);
	}

	@Test
	public void testTinydtlsServerForceExtension() throws Exception {
		processUtil.setTag("tinydtls-server, " + cipherSuite.name());
		processUtil.addExtraArgs("-e", "-r");
		String cipher = processUtil.startupServer(ACCEPT, ScandiumUtil.PORT, TinydtlsProcessUtil.AuthenticationMode.PSK,
				cipherSuite);

		DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder(new Configuration()).set(DtlsConfig.DTLS_ROLE,
				DtlsRole.CLIENT_ONLY);
		scandiumUtil.start(BIND, builder, null, cipherSuite);

		String message = "Hello Scandium!\n";
		scandiumUtil.send(message, DESTINATION, HANDSHAKE_TIMEOUT_MILLIS);

		assertTrue(processUtil.waitConsole("encrypt using " + cipher, TIMEOUT_MILLIS));
		assertTrue(processUtil.waitConsole(message, TIMEOUT_MILLIS));

		scandiumUtil.assertReceivedData(message, TIMEOUT_MILLIS);

		message = "server:exit\n";
		scandiumUtil.send(message, DESTINATION, HANDSHAKE_TIMEOUT_MILLIS);

		EndpointContext context = scandiumUtil.getContext(TIMEOUT_MILLIS);
		Boolean extendedMasterSecret = context.get(DtlsEndpointContext.KEY_EXTENDED_MASTER_SECRET);
		assertEquals("Missing extended master secret", Boolean.TRUE, extendedMasterSecret);

		processUtil.stop(TIMEOUT_MILLIS);
	}
}
