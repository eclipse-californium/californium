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

import static org.eclipse.californium.interoperability.test.CredentialslUtil.CLIENT_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.OPENSSL_PSK_IDENTITY;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.OPENSSL_PSK_SECRET;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.ROOT_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.SERVER_CERTIFICATE;
import static org.eclipse.californium.interoperability.test.CredentialslUtil.TRUSTSTORE;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeNotNull;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.interoperability.test.ProcessUtil;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

/**
 * Utility for libcoap interoperability tests.
 * 
 * Provides invocations for coap-server and -clients.
 * 
 * The required libcoap examples are not included. The test requires version
 * 4.2.1 (better 4.3.0rc3 or newer) and is intended to work with openssl as DTLS
 * implementation.
 * 
 * Check <a href="https://libcoap.net/" target="_blank">libcoap.net</a> for
 * further information.
 * <a href="https://libcoap.net/install.html" target="_blank">install</a>
 * describes how to build it locally, the sources are available at
 * <a href="https://github.com/obgm/libcoap" target="_blank">github
 * -libcoap</a>.
 * 
 * If tinydtls, mbedtls or gnutls should be also tested, prepare additional
 * configurations, builds and installations.
 * 
 * (The configure examples requires a new libcoap from Apr 28 2021 or newer.
 * That introduces the {@code --enable-add-default-names} feature. If used with
 * version before that requires to use {@code --program-suffix} with the (d)tls
 * library, e.g. {@code --program-suffix=-tinydtls}.)
 * 
 * <pre>
 * ./configure --disable-shared --enable-dtls --with-openssl --disable-doxygen --disable-manpages
 * ./configure --disable-shared --enable-dtls --with-gnutls --disable-doxygen --disable-manpages
 * 
 * With tinydtls:
 * ./configure --disable-shared --enable-dtls --with-tinydtls --disable-doxygen --disable-manpages
 * or
 * ./configure --disable-shared --enable-dtls --with-tinydtls --with-submodule-tinydtls --disable-doxygen --disable-manpages
 * 
 * With libcoap 4.3.0:
 * ./configure --disable-shared --enable-dtls --with-mbedtls --disable-doxygen --disable-manpages
 * </pre>
 * 
 * After {@code sudo make install}, execution of {@code sudo ldconfig} may be
 * required on Ubuntu 18.04. If {@code --disable-shared} is added, the binaries
 * are statically linked.
 * 
 * Note: eclipse/tinydtls has been continuously improved over 2021. Consider to
 * use the development branch
 * <a href="https://github.com/eclipse/tinydtls/tree/develop">github
 * eclipse/tinydtls - develop"</a> for the interoperability tests.
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

	public static final String VALGRIND = "valgrind";

	public static final String LIBCOAP_CLIENT_TINYDTLS = "coap-client-tinydtls";
	public static final String LIBCOAP_CLIENT_GNUTLS = "coap-client-gnutls";
	public static final String LIBCOAP_CLIENT_MBEDTLS = "coap-client-mbedtls";
	public static final String LIBCOAP_CLIENT_OPENSSL = "coap-client-openssl";
	public static final String LIBCOAP_SERVER_TINYDTLS = "coap-server-tinydtls";
	public static final String LIBCOAP_SERVER_GNUTLS = "coap-server-gnutls";
	public static final String LIBCOAP_SERVER_MBEDTLS = "coap-server-mbedtls";
	public static final String LIBCOAP_SERVER_OPENSSL = "coap-server-openssl";

	public static final String DEFAULT_VERBOSE_LEVEL = "7";

	public static final String RAW_PUBLIC_KEY_PAIR = "ec_private.pem";

	public static final long VALGRIND_TIMEOUT_MILLIS = TIMEOUT_MILLIS * 3;

	public static final AtomicLong REQUEST_TIMEOUT_MILLIS = new AtomicLong(TIMEOUT_MILLIS);

	private String valgrind = VALGRIND;

	private String client = LIBCOAP_CLIENT_OPENSSL;
	private String server = LIBCOAP_SERVER_OPENSSL;

	private String dtlsVersion;
	private String valgrindVersion;
	private boolean valgrindActive;

	private String verboseLevel = DEFAULT_VERBOSE_LEVEL;
	private boolean dtlsVerboseLevel;
	private String certificate;
	private String privateKey;
	private String ca;
	private String trusts;

	private Integer clientBlocksize;
	private Option clientOption;
	private CoAP.Type type;

	private boolean serverMode;

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
		clientOption = null;
		clientBlocksize = null;
		type = null;
		serverMode = false;
		valgrindActive = false;
		REQUEST_TIMEOUT_MILLIS.set(TIMEOUT_MILLIS);
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
	 * Get libcoap client with openssl version.
	 * 
	 * @param timeMillis timeout in milliseconds
	 * @return result of coap-client command. {@code null}, if not available.
	 */
	public ProcessResult prepareLibCoapClientOpenssl(long timeMillis) {
		client = LIBCOAP_CLIENT_OPENSSL;
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
	 * Get libcoap server with openssl version.
	 * 
	 * @param timeMillis timeout in milliseconds
	 * @return result of coap-server command. {@code null}, if not available.
	 */
	public ProcessResult prepareLibCoapServerOpenssl(long timeMillis) {
		server = LIBCOAP_SERVER_OPENSSL;
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

		if (!Boolean.FALSE.equals(StringUtil.getConfigurationBoolean("USE_VALGRIND"))) {
			prepareValgrind(timeMillis);
		}

		try {
			// use not supported option -h to trigger the help message!
			execute(application, "-h");
			ProcessResult result = waitResult(timeMillis);
			assumeNotNull(result);
			versionResult = result;
			Matcher matcher = result.match(application + " v(\\S+) ");
			assumeNotNull(matcher);
			version = matcher.group(1);

			matcher = result.match(dtlsLibrary + " - runtime (\\S+),");
			assumeNotNull(matcher);
			dtlsVersion = matcher.group(1);

			dtlsVerboseLevel = result.contains("\\[-V num\\]");

			return result;
		} catch (InterruptedException ex) {
			return null;
		} catch (IOException ex) {
			return null;
		} catch (RuntimeException ex) {
			return null;
		}
	}

	/**
	 * Prepare to use valgrind for memory checks
	 * 
	 * @param timeMillis timeout in milliseconds
	 * @return result of valgrind application. {@code null}, if not available.
	 * @since 3.0
	 */
	public ProcessResult prepareValgrind(long timeMillis) {
		try {
			execute(valgrind, "--version");
			ProcessResult result = waitResult(timeMillis);
			if (result == null) {
				return null;
			}
			Matcher matcher = result.match(valgrind + "-(\\S+)");
			if (matcher == null) {
				return null;
			}
			valgrindVersion = matcher.group(1);
			return result;
		} catch (InterruptedException ex) {
			return null;
		} catch (IOException ex) {
			return null;
		} catch (RuntimeException ex) {
			return null;
		}
	}

	public void assumeMinDtlsVersion(String version) {
		assumeNotNull(this.dtlsVersion);
		assumeTrue(this.dtlsVersion + " > " + version, compareVersion(this.dtlsVersion, version) >= 0);
	}

	public String getDtlsVersion() {
		return dtlsVersion;
	}

	public int compareDtlsVersion(String version2) {
		return compareVersion(dtlsVersion, version2);
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

	public void setClientOption(Option option) {
		this.clientOption = option;
	}

	public void setClientMessageType(CoAP.Type type) {
		this.type = type;
	}

	public void setClientBlocksize(int blocksize) {
		this.clientBlocksize = blocksize;
	}

	public void startupClient(String destination, LibCoapAuthenticationMode authMode, String message,
			CipherSuite... ciphers) throws IOException, InterruptedException {
		serverMode = false;
		List<CipherSuite> list = Arrays.asList(ciphers);
		List<String> args = new ArrayList<String>();
		addValgrind(args);
		args.add(client);
		if (verboseLevel != null) {
			args.add("-v"); // coap
			args.add(verboseLevel);
			if (dtlsVerboseLevel) {
				args.add("-V"); // dtls
				args.add(verboseLevel);
			}
		}
		if (message != null) {
			message = message.replace(" ", "%20");
			message = message.replace("\n", "%0a");
			message = message.replace("\r", "%0d");
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
		if (clientOption != null) {
			args.add("-O");
			byte[] value = clientOption.getValue();
			args.add(clientOption.getNumber() + ",0x" + StringUtil.byteArray2Hex(value));
		}
		if (clientBlocksize != null) {
			args.add("-b");
			args.add(clientBlocksize.toString());
		}
		if (type == Type.NON) {
			args.add("-N");
		}
		args.add(destination);
		args.addAll(extraArgs);
		print(args);
		execute(args);
	}

	public void startupServer(String accept, LibCoapAuthenticationMode authMode, CipherSuite... ciphers)
			throws IOException, InterruptedException {
		serverMode = true;
		List<CipherSuite> list = Arrays.asList(ciphers);
		List<String> args = new ArrayList<String>();
		// provide coap port, coaps will be +1
		args.addAll(Arrays.asList(server, "-p", "5683"));
		if (verboseLevel != null) {
			args.add("-v"); // coap
			args.add(verboseLevel);
			if (dtlsVerboseLevel) {
				args.add("-V"); // dtls
				args.add(verboseLevel);
			}
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
		args.addAll(extraArgs);
		print(args);
		execute(args);
		// wait for DEBG created DTLS endpoint [::]:5684
		assumeTrue(waitConsole("created DTLS endpoint (\\[[^]]*\\]|[^:]*):5684", TIMEOUT_MILLIS));
	}

	public void add(List<String> args, LibCoapAuthenticationMode authMode) {
		switch (authMode) {
		case PSK:
			break;
		case CERTIFICATE:
			break;
		case RPK:
			break;
		case CHAIN:
			if (compareVersion("4.3.0") >= 0) {
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

	public void addValgrind(List<String> args) {
		if (valgrindVersion != null) {
			valgrindActive = true;
			args.add(valgrind);
			args.add("--track-origins=yes");
			args.add("--leak-check=yes");
			args.add("--show-reachable=yes");
			REQUEST_TIMEOUT_MILLIS.set(VALGRIND_TIMEOUT_MILLIS);
		}
	}

	public ProcessResult stop(long timeoutMillis) throws InterruptedException, IOException {
		boolean forced = false;
		if (serverMode) {
			forced = super.stop();
		}
		ProcessResult result = waitResult(timeoutMillis);
		if (!serverMode && result == null) {
			forced = super.stop();
			result = waitResult(timeoutMillis);
		}
		if (valgrindActive && !forced && result != null) {
			assertTrue(result.contains("ERROR SUMMARY: 0 errors "));
		}
		return result;
	}

}
