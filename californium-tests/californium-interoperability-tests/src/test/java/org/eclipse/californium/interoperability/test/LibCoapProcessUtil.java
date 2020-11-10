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
 * If tinydtls should be also tested, prepare a second configuration, build and installation
 * <pre>
 * ./configure --enable-dtls --with-tinydtls --disable-doxygen --disable-manpages --program-suffix=-tinydtls
 * </pre>
 * 
 * After {@code sudo make install}, execution of {@code sudo ldconfig} maybe
 * required on Ubuntu 18.04.
 */
public class LibCoapProcessUtil extends ProcessUtil {

	public static final String LIBCOAP_CLIENT_TINYDTLS = "coap-client-tinydtls";
	public static final String LIBCOAP_CLIENT = "coap-client";
	public static final String LIBCOAP_SERVER = "coap-server";

	private String verboseLevel;

	/**
	 * Create instance.
	 */
	public LibCoapProcessUtil() {
	}

	/**
	 * Get libcoap client with tinydtls version.
	 * 
	 * @param timeMillis timeout in milliseconds
	 * @return result of coap-client-tinydtls command. {@code null}, if not available.
	 */
	public ProcessResult getLibCoapClientTinyDtlsVersion(long timeMillis) {
		try {
			execute(LIBCOAP_CLIENT_TINYDTLS);
			return waitResult(timeMillis);
		} catch (InterruptedException ex) {
			return null;
		} catch (IOException ex) {
			return null;
		}
	}

	/**
	 * Get libcoap client version.
	 * 
	 * @param timeMillis timeout in milliseconds
	 * @return result of coap-client command. {@code null}, if not available.
	 */
	public ProcessResult getLibCoapClientVersion(long timeMillis) {
		try {
			execute(LIBCOAP_CLIENT);
			return waitResult(timeMillis);
		} catch (InterruptedException ex) {
			return null;
		} catch (IOException ex) {
			return null;
		}
	}

	/**
	 * Get libcoap servert version.
	 * 
	 * @param timeMillis timeout in milliseconds
	 * @return result of coap-server command. {@code null}, if not available.
	 */
	public ProcessResult getLibCoapServerVersion(long timeMillis) {
		try {
			// use not supported option -h to trigger the help message!
			execute(LIBCOAP_SERVER, "-h");
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

	public void startupClientTinyDtls(String destination, AuthenticationMode authMode, String message, CipherSuite... ciphers)
			throws IOException, InterruptedException {
		List<CipherSuite> list = Arrays.asList(ciphers);
		List<String> args = new ArrayList<String>();
		args.add(LIBCOAP_CLIENT_TINYDTLS);
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
			throw new IllegalArgumentException("TinyDTLS doesn't support x509!");
		}
		args.add(destination);
		print(args);
		execute(args);
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
			add(args, authMode, OpenSslProcessUtil.ROOT_CERTIFICATE, OpenSslProcessUtil.TRUSTSTORE);
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
			add(args, authMode, OpenSslProcessUtil.ROOT_CERTIFICATE, OpenSslProcessUtil.TRUSTSTORE);
		}
		print(args);
		execute(args);
	}

	public void add(List<String> args, OpenSslUtil.AuthenticationMode authMode, String commonCa, String trusts)
			throws IOException, InterruptedException {
		switch (authMode) {
		case PSK:
			break;
		case CERTIFICATE:
		case CHAIN:
			args.add("-R");
			args.add(trusts);
			break;
		case TRUST:
			args.add("-R");
			args.add(trusts);
			args.add("-C");
			args.add(commonCa);
			break;
		}
	}

	public ProcessResult stop(long timeoutMillis) throws InterruptedException, IOException {
		return waitResult(timeoutMillis);
	}

}
