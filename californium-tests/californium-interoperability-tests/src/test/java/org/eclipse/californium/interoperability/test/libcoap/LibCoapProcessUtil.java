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
package org.eclipse.californium.interoperability.test.libcoap;

import static org.eclipse.californium.interoperability.test.OpenSslUtil.CLIENT_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.OpenSslUtil.OPENSSL_PSK_IDENTITY;
import static org.eclipse.californium.interoperability.test.OpenSslUtil.OPENSSL_PSK_SECRET;
import static org.eclipse.californium.interoperability.test.OpenSslUtil.ROOT_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.OpenSslUtil.SERVER_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.OpenSslUtil.TRUSTSTORE;
import static org.junit.Assume.assumeNotNull;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;

import org.eclipse.californium.interoperability.test.ProcessUtil;
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
 * If tinydtls, mbedtls or gnutls should be also tested, prepare additional
 * configuration, build and installation
 * 
 * <pre>
 * ./configure --disable-shared --enable-dtls --with-openssl --disable-doxygen --disable-manpages
 * ./configure --disable-shared --enable-dtls --with-tinydtls --disable-doxygen --disable-manpages --program-suffix=-tinydtls
 * ./configure --disable-shared --enable-dtls --with-gnutls --disable-doxygen --disable-manpages --program-suffix=-gnutls
 * With libcoap 4.3.0:
 * ./configure --disable-shared --enable-dtls --with-mbedtls --disable-doxygen --disable-manpages --program-suffix=-mbedtls
 * </pre>
 * 
 * After {@code sudo make install}, execution of {@code sudo ldconfig} may be
 * required on Ubuntu 18.04. If {@code --disable-shared} is added, the binaries are statically linked.
 */
public class LibCoapProcessUtil extends ProcessUtil {

	public enum LibCoapAuthenticationMode {
		/**
		 * Use PSK.
		 */
		PSK,
		/**
		 * Use Raw Public Key.
		 */
		RPK,
		/**
		 * Send peer's certificate, trust all.
		 */
		CERTIFICATE,
		/**
		 * Send peer's certificate-chain, trust all.
		 */
		CHAIN,
		/**
		 * Send peer's certificate-chain, and trusted CA.
		 */
		CA,
		/**
		 * Send peer's certificate-chain, trust trusts.
		 */
		TRUST
	}

	public static final String LIBCOAP_CLIENT_TINYDTLS = "coap-client-tinydtls";
	public static final String LIBCOAP_CLIENT_GNUTLS = "coap-client-gnutls";
	public static final String LIBCOAP_CLIENT_MBEDTLS = "coap-client-mbedtls";
	public static final String LIBCOAP_CLIENT = "coap-client";
	public static final String LIBCOAP_SERVER_TINYDTLS = "coap-server-tinydtls";
	public static final String LIBCOAP_SERVER_GNUTLS = "coap-server-gnutls";
	public static final String LIBCOAP_SERVER_MBEDTLS = "coap-server-mbedtls";
	public static final String LIBCOAP_SERVER = "coap-server";

	public static final String DEFAULT_VERBOSE_LEVEL = "7";

	public static final String RAW_PUBLIC_KEY_PAIR = "ec_private.pem";

	private String client = LIBCOAP_CLIENT;
	private String server = LIBCOAP_SERVER;

	private String version;
	private String dtlsVersion;

	private String verboseLevel = DEFAULT_VERBOSE_LEVEL;
	private String certificate;
	private String privateKey;
	private String ca;
	private String trusts;

	/**
	 * Create instance.
	 */
	public LibCoapProcessUtil() {
	}

	public void shutdown() throws InterruptedException {
		super.shutdown();
		verboseLevel = DEFAULT_VERBOSE_LEVEL;
		certificate = null;
		privateKey = null;
		ca = null;
		trusts = null;
	}

	/**
	 * Get libcoap client with tinydtls version.
	 * 
	 * @param timeMillis timeout in milliseconds
	 * @return result of coap-client-tinydtls command. {@code null}, if not
	 *         available.
	 */
	public ProcessResult prepareLibCoapClientTinyDtls(long timeMillis) {
		client = LIBCOAP_CLIENT_TINYDTLS;
		return prepareLibCoapApplication(client, "TinyDTLS", timeMillis);
	}

	/**
	 * Get libcoap client with gnutls version.
	 * 
	 * @param timeMillis timeout in milliseconds
	 * @return result of coap-client-gnutls command. {@code null}, if not
	 *         available.
	 */
	public ProcessResult prepareLibCoapClientGnuTls(long timeMillis) {
		client = LIBCOAP_CLIENT_GNUTLS;
		return prepareLibCoapApplication(client, "GnuTLS", timeMillis);
	}

	/**
	 * Get libcoap client with mbedtls version.
	 * 
	 * @param timeMillis timeout in milliseconds
	 * @return result of coap-client-mbedtls command. {@code null}, if not
	 *         available.
	 */
	public ProcessResult prepareLibCoapClientMbedTls(long timeMillis) {
		client = LIBCOAP_CLIENT_MBEDTLS;
		return prepareLibCoapApplication(client, "Mbed TLS", timeMillis);
	}

	/**
	 * Get libcoap client version.
	 * 
	 * @param timeMillis timeout in milliseconds
	 * @return result of coap-client command. {@code null}, if not available.
	 */
	public ProcessResult prepareLibCoapClient(long timeMillis) {
		client = LIBCOAP_CLIENT;
		return prepareLibCoapApplication(client, "OpenSSL", timeMillis);
	}

	/**
	 * Get libcoap server with tinydtls version.
	 * 
	 * @param timeMillis timeout in milliseconds
	 * @return result of coap-server-tinydtls command. {@code null}, if not
	 *         available.
	 */
	public ProcessResult prepareLibCoapServerTinyDtls(long timeMillis) {
		server = LIBCOAP_SERVER_TINYDTLS;
		return prepareLibCoapApplication(server, "TinyDTLS", timeMillis);
	}

	/**
	 * Get libcoap server with gnutls version.
	 * 
	 * @param timeMillis timeout in milliseconds
	 * @return result of coap-server-gnutls command. {@code null}, if not
	 *         available.
	 */
	public ProcessResult prepareLibCoapServerGnuTls(long timeMillis) {
		server = LIBCOAP_SERVER_GNUTLS;
		return prepareLibCoapApplication(server, "GnuTLS", timeMillis);
	}

	/**
	 * Get libcoap server with mbedtls version.
	 * 
	 * @param timeMillis timeout in milliseconds
	 * @return result of coap-server-mbedtls command. {@code null}, if not
	 *         available.
	 */
	public ProcessResult prepareLibCoapServerMbedTls(long timeMillis) {
		server = LIBCOAP_SERVER_MBEDTLS;
		return prepareLibCoapApplication(server, "Mbed TLS", timeMillis);
	}

	/**
	 * Get libcoap server version.
	 * 
	 * @param timeMillis timeout in milliseconds
	 * @return result of coap-server command. {@code null}, if not available.
	 */
	public ProcessResult preapreLibCoapServer(long timeMillis) {
		server = LIBCOAP_SERVER;
		return prepareLibCoapApplication(server, "OpenSSL", timeMillis);
	}

	/**
	 * Prepare for libcoap application
	 * 
	 * @param application application.
	 * @param dtlsLibrary dtls-library
	 * @param timeMillis timeout in milliseconds
	 * @return result of libcoap application. {@code null}, if not available.
	 */
	public ProcessResult prepareLibCoapApplication(String application, String dtlsLibrary, long timeMillis) {
		try {
			// use not supported option -h to trigger the help message!
			execute(application, "-h");
			ProcessResult result = waitResult(timeMillis);
			assumeNotNull(result);
			Matcher matcher = result.match(application + " v(\\S+) ");
			assumeNotNull(matcher);
			version = matcher.group(1);

			matcher = result.match(dtlsLibrary + " - runtime (\\S+),");
			assumeNotNull(matcher);
			dtlsVersion = matcher.group(1);

			return result;
		} catch (InterruptedException ex) {
			return null;
		} catch (IOException ex) {
			return null;
		} catch (RuntimeException ex) {
			return null;
		}
	}

	public void assumeMinVersion(String version) {
		assumeNotNull(version);
		assumeTrue(this.version + " > " + version, compareVersion(this.version, version) >= 0);
	}

	public void assumeMinDtlsVersion(String version) {
		assumeNotNull(version);
		assumeTrue(this.dtlsVersion + " > " + version, compareVersion(this.dtlsVersion, version) >= 0);
	}

	public String getVersion() {
		return version;
	}

	public String getDtlsVersion() {
		return dtlsVersion;
	}

	public int compareVersion(String version2) {
		return compareVersion(version, version2);
	}

	public int compareDtlsVersion(String version2) {
		return compareVersion(dtlsVersion, version2);
	}

	public static int compareVersion(String version1, String version2) {
		String[] versionPath1 = version1.split("\\.");
		String[] versionPath2 = version2.split("\\.");
		int length = versionPath1.length;
		if (versionPath2.length < length) {
			length = versionPath2.length;
		}
		for (int index = 0; index < length; ++index) {
			int cmp = versionPath1[index].compareTo(versionPath2[index]);
			if (cmp != 0) {
				return cmp;
			}
		}
		return versionPath1.length - versionPath2.length;
	}

	public void setVerboseLevel(String level) {
		this.verboseLevel = level;
	}

	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}

	public void setPrivateKey(String privateKey) {
		this.privateKey = privateKey;
	}

	public void setCa(String ca) {
		this.ca = ca;
	}

	public void setTrusts(String trusts) {
		this.trusts = trusts;
	}

	public void startupClient(String destination, LibCoapAuthenticationMode authMode, String message,
			CipherSuite... ciphers) throws IOException, InterruptedException {
		List<CipherSuite> list = Arrays.asList(ciphers);
		List<String> args = new ArrayList<String>();
		args.add(client);
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
			args.add(OPENSSL_PSK_IDENTITY);
			args.add("-k");
			args.add(new String(OPENSSL_PSK_SECRET));
		}
		if (CipherSuite.containsCipherSuiteRequiringCertExchange(list)) {
			if (authMode == LibCoapAuthenticationMode.RPK) {
				args.add("-M");
				args.add(RAW_PUBLIC_KEY_PAIR);
			} else {
				args.add("-c");
				args.add(certificate != null ? certificate : CLIENT_CERTIFICATE);
				if (privateKey != null) {
					args.add("-j");
					args.add(privateKey);
				}
				add(args, authMode);
			}
		}
		args.add(destination);
		print(args);
		execute(args);
	}

	public void startupServer(String accept, LibCoapAuthenticationMode authMode, CipherSuite... ciphers)
			throws IOException, InterruptedException {
		List<CipherSuite> list = Arrays.asList(ciphers);
		List<String> args = new ArrayList<String>();
		// provide coap port, coaps will be +1
		args.addAll(Arrays.asList(server, "-p", "5683"));
		if (verboseLevel != null) {
			args.add("-v");
			args.add(verboseLevel);
		}
		if (CipherSuite.containsPskBasedCipherSuite(list)) {
			args.add("-k");
			args.add(new String(OPENSSL_PSK_SECRET));
		}
		if (CipherSuite.containsCipherSuiteRequiringCertExchange(list)) {
			if (authMode == LibCoapAuthenticationMode.RPK) {
				args.add("-M");
				args.add(RAW_PUBLIC_KEY_PAIR);
			} else {
				args.add("-c");
				args.add(certificate != null ? certificate : SERVER_CERTIFICATE);
				if (privateKey != null) {
					args.add("-j");
					args.add(privateKey);
				}
				add(args, authMode);
			}
		}
		print(args);
		execute(args);
	}

	public void add(List<String> args, LibCoapAuthenticationMode authMode) throws IOException, InterruptedException {
		switch (authMode) {
		case PSK:
			break;
		case CERTIFICATE:
			break;
		case RPK:
			break;
		case CHAIN:
			if (version.startsWith("4.3.0")) {
				args.add("-n");
			}
			args.add("-R");
			args.add(trusts != null ? trusts : TRUSTSTORE);
			break;
		case CA:
			args.add("-C");
			args.add(ca != null ? ca : ROOT_CERTIFICATE);
			break;
		case TRUST:
			args.add("-R");
			args.add(trusts != null ? trusts : TRUSTSTORE);
			break;
		}
	}

	public ProcessResult stop(long timeoutMillis) throws InterruptedException, IOException {
		return waitResult(timeoutMillis);
	}

}
