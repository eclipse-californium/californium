/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
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
 * 
 * Note: version 1.1.1a to 1.1.1c the openssl s_server seems to be broken. It
 * starts only to accept, when the first message is entered. Therefore the test
 * are skipped on windows.
 */
@RunWith(Parameterized.class)
public class OpenSslServerInteroperabilityTest {

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final InetSocketAddress BIND = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
	private static final InetSocketAddress DESTINATION = new InetSocketAddress(InetAddress.getLoopbackAddress(),
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
		String os = System.getProperty("os.name");
		if (os.startsWith("Windows")) {
			assumeFalse("Windows openssl server 1.1.1 seems to be broken!", result.contains("OpenSSL 1\\.1\\.1[abc]"));
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
	@Parameters(name = "ciphersuite = {0}")
	public static Iterable<CipherSuite> cipherSuiteParams() {
		return OpenSslUtil.CIPHERSUITES_MAP.keySet();
	}

	@After
	public void shutdownServer() throws InterruptedException {
		processUtil.shutdown();
	}

	/**
	 * Establish a "connection" and send a message to the server and back to the
	 * client.
	 */
	@Test
	public void testOpenSslServer() throws Exception {
		String cipher = startupServer(cipherSuite);

		scandiumUtil.start(BIND, cipherSuite);

		String message = "Hello OpenSSL!";
		scandiumUtil.send(message, DESTINATION, TIMEOUT_MILLIS);

		processUtil.waitConsole("CIPHER is " + cipher, TIMEOUT_MILLIS);
		processUtil.waitConsole(message, TIMEOUT_MILLIS);
		processUtil.send("ACK-" + message);

		scandiumUtil.assertReceivedData("ACK-" + message, TIMEOUT_MILLIS);

		stopServer();
	}

	private String startupServer(CipherSuite cipher) throws IOException, InterruptedException {
		String openSslCipher = OpenSslUtil.CIPHERSUITES_MAP.get(cipher);
		if (cipher.isPskBased()) {
			startupPskServer(openSslCipher);
		} else {
			startupEcdsaServer(openSslCipher);
		}
		return openSslCipher;
	}

	private void startupPskServer(String ciphers) throws IOException, InterruptedException {
		processUtil.execute("openssl", "s_server", "-4", "-dtls1_2", "-accept", "127.0.0.1:" + ScandiumUtil.PORT,
				"-listen", "-no-CAfile", "-cipher", ciphers, "-psk", "73656372657450534b");
	}

	private void startupEcdsaServer(String ciphers) throws IOException, InterruptedException {
		processUtil.execute("openssl", "s_server", "-4", "-dtls1_2", "-accept", "127.0.0.1:" + ScandiumUtil.PORT,
				"-listen", "-no-CAfile", "-cipher", ciphers, "-cert", "server.pem");
	}

	private void stopServer() throws InterruptedException, IOException {
		processUtil.sendln("Q");
		processUtil.waitResult(TIMEOUT_MILLIS);
	}

}
