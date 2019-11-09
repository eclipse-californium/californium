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
 * Test for openssl interoperability.
 * 
 * Requires external openssl installation, otherwise the tests are skipped. On
 * linux install just the openssl package (version 1.1.1). On windows you may
 * install git for windows, <a href="https://git-scm.com/download/win">git</a>
 * and add the extra tools to your path ("Git/mingw64/bin", may also be done
 * using a installation option). Alternatively you may install openssl for
 * windows on it's own <a href=
 * "https://bintray.com/vszakats/generic/download_file?file_path=openssl-1.1.1c-win64-mingw.zip">OpenSsl
 * for Windows</a> and add that to your path.
 */
@RunWith(Parameterized.class)
public class OpenSslClientInteroperabilityTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final InetSocketAddress BIND = new InetSocketAddress(InetAddress.getLoopbackAddress(),
			ScandiumUtil.PORT);
	private static final long TIMEOUT_MILLIS = 2000;

	private static ProcessUtil processUtil;
	private static ScandiumUtil scandiumUtil;

	@BeforeClass
	public static void init() throws IOException, InterruptedException {
		processUtil = new ProcessUtil();
		processUtil.execute("openssl", "version");
		ProcessResult result = processUtil.waitResult(TIMEOUT_MILLIS);
		assumeNotNull(result);
		assumeTrue(result.contains("OpenSSL 1\\.1\\."));
		scandiumUtil = new ScandiumUtil(false);
	}

	@AfterClass
	public static void teardown() throws InterruptedException {
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
	@Parameters(name = "ciphersuite = {0}")
	public static Iterable<CipherSuite> cipherSuiteParams() {
		return OpenSslUtil.CIPHERSUITES_MAP.keySet();
	}

	@After
	public void shutdown() throws InterruptedException {
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
		scandiumUtil.start(BIND, cipherSuite);

		String cipher = startupClient(cipherSuite);
		assertTrue(processUtil.waitConsole("Cipher is " + cipher, TIMEOUT_MILLIS));

		String message = "Hello Scandium!";
		processUtil.send(message);

		scandiumUtil.assertReceivedData(message, TIMEOUT_MILLIS);
		scandiumUtil.response("ACK-" + message, TIMEOUT_MILLIS);

		assertTrue(processUtil.waitConsole("ACK-" + message, TIMEOUT_MILLIS));

		stopClient();
	}

	private String startupClient(CipherSuite cipher) throws IOException, InterruptedException {
		String openSslCipher = OpenSslUtil.CIPHERSUITES_MAP.get(cipher);
		if (cipher.isPskBased()) {
			startupPskClient(openSslCipher);
		} else {
			startupEcdsaClient(openSslCipher);
		}
		return openSslCipher;
	}

	private void startupPskClient(String ciphers) throws IOException, InterruptedException {
		processUtil.execute("openssl", "s_client", "-dtls1_2", "-4", "-connect", "127.0.0.1:" + ScandiumUtil.PORT,
				"-no-CAfile", "-cipher", ciphers, "-curves", "prime256v1", "-psk", "73656372657450534b");
	}

	private void startupEcdsaClient(String ciphers) throws IOException, InterruptedException {
		processUtil.execute("openssl", "s_client", "-dtls1_2", "-4", "-connect", "127.0.0.1:" + ScandiumUtil.PORT,
				"-no-CAfile", "-cipher", ciphers, "-curves", "prime256v1", "-cert", "client.pem");
	}

	private void stopClient() throws InterruptedException, IOException {
		processUtil.sendln("Q");
		processUtil.waitResult(TIMEOUT_MILLIS);
	}
}
