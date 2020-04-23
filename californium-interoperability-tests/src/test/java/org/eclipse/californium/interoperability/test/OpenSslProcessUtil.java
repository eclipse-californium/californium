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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.interoperability.test.OpenSslUtil.AuthenticationMode;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

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
 * Note: the windows version 1.1.1a to 1.1.1d of the openssl s_server seems to
 * be broken. It starts only to accept, when the first message is entered.
 * Therefore the test are skipped on windows.
 */
public class OpenSslProcessUtil extends ProcessUtil {

	public static final String DEFAULT_CURVES = "X25519:prime256v1";
	public static final String DEFAULT_SIGALGS = "ECDSA+SHA384:ECDSA+SHA256:RSA+SHA256";

	public static final String SERVER_CERTIFICATE = "server.pem";
	public static final String SERVER_RSA_CERTIFICATE = "serverRsa.pem";

	/**
	 * Create instance.
	 */
	public OpenSslProcessUtil() {
	}

	/**
	 * Get openssl version.
	 * 
	 * @param timeMillis timeout in milliseconds
	 * @return result of version command. {@code null}, if not available.
	 */
	public ProcessResult getOpenSslVersion(long timeMillis) {
		try {
			execute("openssl", "version");
			return waitResult(timeMillis);
		} catch (InterruptedException ex) {
			return null;
		} catch (IOException ex) {
			return null;
		}
	}

	public String startupClient(String destination, AuthenticationMode authMode, CipherSuite... ciphers)
			throws IOException, InterruptedException {
		return startupClient(destination, authMode, DEFAULT_CURVES, null, ciphers);
	}

	public String startupClient(String destination, OpenSslUtil.AuthenticationMode authMode, String curves,
			String sigAlgs, CipherSuite... ciphers) throws IOException, InterruptedException {
		List<CipherSuite> list = Arrays.asList(ciphers);
		List<String> args = new ArrayList<String>();
		String openSslCiphers = OpenSslUtil.getOpenSslCipherSuites(ciphers);
		args.addAll(Arrays.asList("openssl", "s_client", "-dtls1_2", "-4", "-connect", destination, "-cipher",
				openSslCiphers));
		if (CipherSuite.containsPskBasedCipherSuite(list)) {
			args.add("-psk");
			args.add(StringUtil.byteArray2Hex(OpenSslUtil.OPENSSL_PSK_SECRET));
		}
		if (CipherSuite.containsCipherSuiteRequiringCertExchange(list)) {
			args.add("-cert");
			args.add("client.pem");
			add(args, authMode, "caTrustStore.pem");
		}
		add(args, curves, sigAlgs);
		execute(args);
		return "(" + openSslCiphers.replace(":", "|") + ")";
	}

	public String startupServer(String accept, OpenSslUtil.AuthenticationMode authMode, CipherSuite... ciphers)
			throws IOException, InterruptedException {
		return startupServer(accept, authMode, SERVER_CERTIFICATE, null, null, ciphers);
	}

	public String startupServer(String accept, OpenSslUtil.AuthenticationMode authMode, String serverCertificate,
			String curves, String sigAlgs, CipherSuite... ciphers) throws IOException, InterruptedException {
		List<CipherSuite> list = Arrays.asList(ciphers);
		List<String> args = new ArrayList<String>();
		String openSslCiphers = OpenSslUtil.getOpenSslCipherSuites(ciphers);
		args.addAll(Arrays.asList("openssl", "s_server", "-4", "-dtls1_2", "-accept", accept, "-listen", "-verify", "5",
				"-cipher", openSslCiphers));
		if (CipherSuite.containsPskBasedCipherSuite(list)) {
			args.add("-psk");
			args.add(StringUtil.byteArray2Hex(OpenSslUtil.OPENSSL_PSK_SECRET));
		}
		if (CipherSuite.containsCipherSuiteRequiringCertExchange(list)) {
			args.add("-cert");
			args.add(serverCertificate);
			String chain = "caTrustStore.pem";
			if (SERVER_RSA_CERTIFICATE.equals(serverCertificate)) {
				chain = "caRsaTrustStore.pem";
			}
			add(args, authMode, chain);
		}
		add(args, curves, sigAlgs);
		execute(args);
		return "(" + openSslCiphers.replace(":", "|") + ")";
	}

	public void add(List<String> args, String curves, String sigAlgs) throws IOException, InterruptedException {
		if (curves != null) {
			args.add("-curves");
			args.add(curves);
		}
		if (sigAlgs != null) {
			args.add("-sigalgs");
			args.add(sigAlgs);
		}
	}

	public void add(List<String> args, OpenSslUtil.AuthenticationMode authMode, String chain)
			throws IOException, InterruptedException {
		switch (authMode) {
		case CERTIFICATE:
			args.add("-no-CAfile");
			break;
		case CHAIN:
			args.add("-no-CAfile");
			args.add("-cert_chain");
			args.add(chain);
			break;
		case TRUST:
			args.add("-CAfile");
			args.add("trustStore.pem");
			args.add("-build_chain");
			break;
		}
	}

	public void stop(long timeoutMillis) throws InterruptedException, IOException {
		sendln("Q");
		waitResult(timeoutMillis);
	}

}
