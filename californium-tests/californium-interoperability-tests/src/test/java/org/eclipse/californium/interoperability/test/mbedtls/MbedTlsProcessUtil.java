/*******************************************************************************
 * Copyright (c) 2022 Bosch IO GmbH and others.
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
 *    Bosch.IO GmbH - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.interoperability.test.mbedtls;

import static org.eclipse.californium.interoperability.test.CredentialslUtil.CA_CERTIFICATES;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.CA_RSA_CERTIFICATES;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.CLIENT_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.SERVER_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.SERVER_CA_RSA_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.TRUSTSTORE;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.OPENSSL_PSK_IDENTITY;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.OPENSSL_PSK_SECRET;
import static org.junit.Assume.assumeThat;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;

import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.interoperability.test.ProcessUtil;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

/**
 * Test utility for Mbed TLS interoperability.
 * 
 * Executes (externally provided) Mbed TLS client and server.
 * 
 * Requires pre-installed ssl_client2 and ssl_server2 of Mbed TLS 3.1.0, build
 * with {@code MBEDTLS_SSL_DTLS_CONNECTION_ID} enabled (see
 * <a href="https://github.com/ARMmbed/mbedtls" target="_blank">github Mbed
 * TLS</a>). Please use the names "mbedtls3_ssl_client2" and
 * "mbedtls3_ssl_server2" for the binaries found in
 * {@code <Mbed TLS>}/programs/ssl when copy or link them into your
 * {@code PATH}.
 * 
 * The ssl_client2 sends a HTTP GET request even over DTLS. And the ssl_server2
 * sends back a "HTTP/1.0 200 OK", regardless of the incoming received message.
 * Both don't have the possibility to write their build version, please check
 * that with other means.
 * 
 * @since 3.3
 */
public class MbedTlsProcessUtil extends ProcessUtil {

	public enum AuthenticationMode {
		/**
		 * Use PSK.
		 */
		PSK,
		/**
		 * Send peer's certificate-chain, trust all.
		 */
		CHAIN,
		/**
		 * Send peer's certificate-chain, trust provided CAs.
		 */
		TRUST
	}

	public static final String DEFAULT_VERBOSE_LEVEL = "1";

	public static final String DEFAULT_CURVES = "x25519,secp256r1";

	/**
	 * Option for {@code curves} (or {@code groups}) used by the mbedtls
	 * programs up to version 3.4.1.
	 * 
	 * @since 3.11
	 */
	private static final String DEPRECATED_CURVES_OPTION = "curves";

	/**
	 * Option for {@code curves} (or {@code groups}) used by the mbedtls
	 * programs since version 3.5.0.
	 * 
	 * @since 3.11
	 */
	private static final String NEW_CURVES_OPTION = "groups";

	private String verboseLevel = DEFAULT_VERBOSE_LEVEL;

	/**
	 * Option for {@code curves} (or {@code groups}).
	 * 
	 * Depends on version of mbedtls.
	 * 
	 * @since 3.11
	 */
	private String curvesOption = "curves";

	/**
	 * Create instance.
	 */
	public MbedTlsProcessUtil() {
	}

	public void shutdown() throws InterruptedException {
		super.shutdown();
		verboseLevel = DEFAULT_VERBOSE_LEVEL;
	}

	public void setVerboseLevel(String level) {
		this.verboseLevel = level;
	}

	/**
	 * Get Mbed TLS version.
	 * 
	 * Currently not working. Only used to detect a "mbedtls3_ssl_client2"
	 * binary in the path.
	 * 
	 * @param timeMillis timeout in milliseconds
	 * @return result of version command. {@code null}, if not available.
	 */
	public ProcessResult getToolVersion(long timeMillis) {
		if (versionResult == null) {
			try {
				execute("mbedtls_ssl_client2", "build_version=1");
				versionResult = waitResult(timeMillis);
				assumeThat("reading version failed!", versionResult, notNullValue());
				Matcher matcher = versionResult.match("[mM]bed TLS (\\S+) ");
				assumeThat("extracting version failed!", versionResult, notNullValue());
				version = matcher.group(1);
				curvesOption = (compareVersion("3.5.0") >= 0) ? NEW_CURVES_OPTION : DEPRECATED_CURVES_OPTION;
			} catch (InterruptedException ex) {
				return null;
			} catch (IOException ex) {
			}
		}
		return versionResult;
	}

	public String startupClient(String destination, int port, MbedTlsProcessUtil.AuthenticationMode authMode,
			CipherSuite cipherSuite) throws IOException, InterruptedException {
		return startupClient(destination, port, authMode, DEFAULT_CURVES, cipherSuite);
	}

	public String startupClient(String destination, int port, MbedTlsProcessUtil.AuthenticationMode authMode,
			String curves, CipherSuite cipherSuite) throws IOException, InterruptedException {
		return startupClient(destination, port, authMode, curves, CLIENT_CERTIFICATE, cipherSuite);
	}

	public String startupClient(String destination, int port, MbedTlsProcessUtil.AuthenticationMode authMode,
			String curves, String clientCert, CipherSuite cipherSuite) throws IOException, InterruptedException {
		List<String> args = new ArrayList<String>();
		String mbedTlsCiphers = MbedTlsUtil.getMbedTlsCipherSuites(cipherSuite);
		args.addAll(Arrays.asList("mbedtls_ssl_client2", "dtls=1", "debug_level=" + verboseLevel,
				"server_addr=" + destination, "server_port=" + port, "force_ciphersuite=" + mbedTlsCiphers));
		if (cipherSuite.isPskBased()) {
			args.add("psk_identity=" + OPENSSL_PSK_IDENTITY);
			args.add("psk=" + StringUtil.byteArray2Hex(OPENSSL_PSK_SECRET));
		}
		if (cipherSuite.requiresServerCertificateMessage()) {
			args.add("crt_file=" + clientCert);
			args.add("key_file=" + clientCert);
			add(args, authMode, CA_CERTIFICATES);
		}
		add(args, curves);
		args.addAll(extraArgs);
		print(args);
		execute(args);
		return mbedTlsCiphers;
	}

	public String startupServer(String accept, int port, MbedTlsProcessUtil.AuthenticationMode authMode,
			CipherSuite cipherSuite) throws IOException, InterruptedException {
		return startupServer(accept, port, authMode, SERVER_CERTIFICATE, null, cipherSuite);
	}

	public String startupServer(String accept, int port, MbedTlsProcessUtil.AuthenticationMode authMode,
			String serverCertificate, String curves, CipherSuite cipherSuite) throws IOException, InterruptedException {
		List<String> args = new ArrayList<String>();
		String mbedTlsCiphers = MbedTlsUtil.getMbedTlsCipherSuites(cipherSuite);
		args.addAll(Arrays.asList("mbedtls_ssl_server2", "dtls=1", "debug_level=" + verboseLevel,
				"server_addr=" + accept, "server_port=" + port, "force_ciphersuite=" + mbedTlsCiphers));
		args.add("exchanges=2");
		if (cipherSuite.isPskBased()) {
			args.add("psk_identity=" + OPENSSL_PSK_IDENTITY);
			args.add("psk=" + StringUtil.byteArray2Hex(OPENSSL_PSK_SECRET));
		}
		if (cipherSuite.requiresServerCertificateMessage()) {
			args.add("crt_file=" + serverCertificate);
			args.add("key_file=" + serverCertificate);
			String chain = CA_CERTIFICATES;
			if (SERVER_CA_RSA_CERTIFICATE.equals(serverCertificate)) {
				chain = CA_RSA_CERTIFICATES;
			}
			add(args, authMode, chain);
		}
		add(args, curves);
		args.addAll(extraArgs);
		print(args);
		execute(args);
		// ensure, server is ready to ACCEPT messages
		assumeTrue(waitConsole("Bind on udp:", TIMEOUT_MILLIS));
		return mbedTlsCiphers;
	}

	public void add(List<String> args, String curves) throws IOException, InterruptedException {
		if (curves != null) {
			args.add(curvesOption + "=" + curves);
		}
	}

	public void add(List<String> args, MbedTlsProcessUtil.AuthenticationMode authMode, String chain)
			throws IOException, InterruptedException {
		switch (authMode) {
		case PSK:
			break;
		case CHAIN:
			args.add("auth_mode=optional");
			break;
		case TRUST:
			args.add("auth_mode=required");
			args.add("ca_file=" + TRUSTSTORE);
			break;
		}
	}

	public ProcessResult stop(long timeoutMillis) throws InterruptedException, IOException {
		return waitResult(timeoutMillis);
	}

}
