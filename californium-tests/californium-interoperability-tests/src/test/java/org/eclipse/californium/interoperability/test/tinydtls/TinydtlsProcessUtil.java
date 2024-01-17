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

import static org.eclipse.californium.interoperability.test.CredentialslUtil.SERVER_CERTIFICATE;
import static org.junit.Assume.assumeNotNull;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;

import org.eclipse.californium.interoperability.test.ProcessUtil;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

/**
 * Test utility for tinydtls interoperability.
 * 
 * Executes (externally provided) tinydtls client and server.
 * 
 * Requires pre-installed dtls-client and dtls-server of tinydtls. Please use
 * the names "tinydtls-client" and "tinydtls-server" for the binaries found in
 * {@code <tinydtls>}/tests when copy or link them into your {@code PATH}.
 * 
 * In order to support DTLS 1.2 CID it's required to use the
 * "feature/connection_id" branch.
 * 
 * @since 3.8
 */
public class TinydtlsProcessUtil extends ProcessUtil {

	public enum AuthenticationMode {
		/**
		 * Use PSK.
		 */
		PSK,
		/**
		 * Use RPK.
		 */
		RPK
	}

	public static final String DEFAULT_VERBOSE_LEVEL = "9";

	private static final String CLIENT = "tinydtls-client";
	private static final String SERVER = "tinydtls-server";

	private String verboseLevel = DEFAULT_VERBOSE_LEVEL;

	/**
	 * Create instance.
	 */
	public TinydtlsProcessUtil() {
	}

	public void shutdown() throws InterruptedException {
		super.shutdown();
		verboseLevel = DEFAULT_VERBOSE_LEVEL;
	}

	public void setVerboseLevel(String level) {
		this.verboseLevel = level;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Get tinydtls version.
	 */
	@Override
	public ProcessResult getToolVersion(long timeMillis) {
		if (versionResult == null) {
			try {
				execute(CLIENT, "-h");
				versionResult = waitResult(timeMillis);
				assumeNotNull(versionResult);
				Matcher matcher = versionResult.match("dtls-\\S+ v(\\S+) --");
				assumeNotNull(matcher);
				version = matcher.group(1);
			} catch (InterruptedException ex) {
				return null;
			} catch (IOException ex) {
			}
		}
		return versionResult;
	}

	public String startupClient(String destination, int port, AuthenticationMode authMode, CipherSuite cipherSuite)
			throws IOException, InterruptedException {
		return startupClient(destination, port, authMode, null, cipherSuite);
	}

	public String startupClient(String destination, int port, AuthenticationMode authMode, String clientCert,
			CipherSuite cipherSuite) throws IOException, InterruptedException {
		List<String> args = new ArrayList<String>();
		String tinydtlsCiphers = TinydtlsUtil.getTinydtlsCipherSuites(cipherSuite);
		args.addAll(Arrays.asList(CLIENT, "-v", verboseLevel, "-c", tinydtlsCiphers));
		args.addAll(extraArgs);
		args.addAll(Arrays.asList(destination, Integer.toString(port)));
		print(args);
		execute(args);
		return tinydtlsCiphers;
	}

	public String startupServer(String accept, int port, AuthenticationMode authMode, CipherSuite cipherSuite)
			throws IOException, InterruptedException {
		return startupServer(accept, port, authMode, SERVER_CERTIFICATE, cipherSuite);
	}

	public String startupServer(String accept, int port, AuthenticationMode authMode, String serverCertificate,
			CipherSuite cipherSuite) throws IOException, InterruptedException {
		List<String> args = new ArrayList<String>();
		String tinydtlsCiphers = TinydtlsUtil.getTinydtlsCipherSuites(cipherSuite);
		args.addAll(Arrays.asList(SERVER, "-v", verboseLevel, "-c" + tinydtlsCiphers, "-A", accept, "-p",
				Integer.toString(port)));
		args.addAll(extraArgs);
		print(args);
		execute(args);
		// ensure, server is ready to ACCEPT messages
		// assumeTrue(waitConsole("Bind on udp:", TIMEOUT_MILLIS));
		return tinydtlsCiphers;
	}

	public ProcessResult stop(long timeoutMillis) throws InterruptedException, IOException {
		clearExtraArgs();
		return waitResult(timeoutMillis);
	}

}
