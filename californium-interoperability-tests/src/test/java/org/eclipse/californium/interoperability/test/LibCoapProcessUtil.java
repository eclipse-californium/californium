/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Achim Kraus (Bosch.IO GmbH) - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.interoperability.test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.eclipse.californium.interoperability.test.OpenSslUtil.AuthenticationMode;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

/**
 * Utility for libcoap interoperability tests.
 * 
 * Provides invocations for coap-server and -clients.
 * 
 * The required libcoap examples are not included. The test requires version
 * 4.2.1 (maybe newer) and is intended to work with openssl as DTLS
 * implementation.
 * 
 * Check <a href="https://libcoap.net/">libcoap.net</a> for further information.
 * <a href="https://libcoap.net/install.html">install</a> describes how to build
 * it locally, the sources are available at
 * <a href="https://github.com/obgm/libcoap">github -libcoap</a>.
 * 
 * After {@code sudo make install}, execution of {@code sudo ldconfig} maybe
 * required on Ubuntu 18.04.
 */
public class LibCoapProcessUtil extends ProcessUtil {

	public static final String LIBCOAP_CLIENT = "coap-client";
	public static final String LIBCOAP_SERVER = "coap-server";

	private String verboseLevel;

	/**
	 * Create instance.
	 */
	public LibCoapProcessUtil() {
	}

	/**
	 * Get libcoap version.
	 * 
	 * @param timeMillis timeout in milliseconds
	 * @return result of coap-client command. {@code null}, if not available.
	 */
	public ProcessResult getLibCoapVersion(long timeMillis) {
		try {
			execute("coap-client");
			return waitResult(timeMillis);
		} catch (InterruptedException ex) {
			return null;
		} catch (IOException ex) {
			return null;
		}
	}

	public void setVerboseLevel(String level) {
		this.verboseLevel = level;
	}

	public void startupClient(String destination, AuthenticationMode authMode, String message, CipherSuite... ciphers)
			throws IOException, InterruptedException {
		List<CipherSuite> list = Arrays.asList(ciphers);
		List<String> args = new ArrayList<String>();
		args.add(LIBCOAP_CLIENT);
		if (verboseLevel != null) {
			args.add("-v");
			args.add(verboseLevel);
		}
		if (message != null) {
			message = message.replace(" ", "%20");
			args.addAll(Arrays.asList("-m", "POST", "-e", message));
		} else {
			args.addAll(Arrays.asList("-m", "GET"));
		}
		if (CipherSuite.containsPskBasedCipherSuite(list)) {
			args.add("-u");
			args.add(OpenSslUtil.OPENSSL_PSK_IDENTITY);
			args.add("-k");
			args.add(new String(OpenSslUtil.OPENSSL_PSK_SECRET));
		}
		if (CipherSuite.containsCipherSuiteRequiringCertExchange(list)) {
			args.add("-c");
			args.add(OpenSslProcessUtil.CLIENT_CERTIFICATE);
			add(args, authMode, OpenSslProcessUtil.TRUSTSTORE);
		}
		args.add(destination);
		print(args);
		execute(args);
	}

	public void startupServer(String accept, AuthenticationMode authMode, CipherSuite... ciphers)
			throws IOException, InterruptedException {
		startupServer(accept, authMode, OpenSslProcessUtil.SERVER_CERTIFICATE, ciphers);
	}

	public void startupServer(String accept, AuthenticationMode authMode, String serverCertificate,
			CipherSuite... ciphers) throws IOException, InterruptedException {
		List<CipherSuite> list = Arrays.asList(ciphers);
		List<String> args = new ArrayList<String>();
		args.addAll(Arrays.asList(LIBCOAP_SERVER, "-p", "5683"));
		if (verboseLevel != null) {
			args.add("-v");
			args.add(verboseLevel);
		}
		if (CipherSuite.containsPskBasedCipherSuite(list)) {
			args.add("-k");
			args.add(new String(OpenSslUtil.OPENSSL_PSK_SECRET));
		}
		if (CipherSuite.containsCipherSuiteRequiringCertExchange(list)) {
			args.add("-c");
			args.add(serverCertificate);
			String chain = OpenSslProcessUtil.CA_CERTIFICATES;
			if (OpenSslProcessUtil.SERVER_RSA_CERTIFICATE.equals(serverCertificate)) {
				chain = OpenSslProcessUtil.CA_RSA_CERTIFICATES;
			}
			add(args, authMode, chain);
		}
		print(args);
		execute(args);
	}

	public void add(List<String> args, OpenSslUtil.AuthenticationMode authMode, String chain)
			throws IOException, InterruptedException {
		switch (authMode) {
		case PSK:
			break;
		case CERTIFICATE:
		case CHAIN:
			args.add("-R");
			args.add(chain);
			break;
		case TRUST:
			args.add("-R");
			args.add(chain);
			args.add("-C");
			args.add(chain);
			break;
		}
	}

	public ProcessResult stop(long timeoutMillis) throws InterruptedException, IOException {
		return waitResult(timeoutMillis);
	}

}
