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
package org.eclipse.californium.interoperability.test.openssl;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.eclipse.californium.elements.util.TestScope;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

/**
 * Utility for openssl. Map of {@link CipherSuite} to openssl cipher suite name.
 */
public class OpenSslUtil {

	/**
	 * Map of Californium's cipher suites to openssl names.
	 */
	public static final Map<CipherSuite, String> CIPHERSUITES_MAP = new HashMap<CipherSuite, String>();

	static {
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, "ECDHE-PSK-AES128-CBC-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256, "PSK-AES128-GCM-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA378, "PSK-AES256-GCM-SHA384");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8, "PSK-AES128-CCM8:@SECLEVEL=0");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_256_CCM_8, "PSK-AES256-CCM8:@SECLEVEL=0");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_128_CCM, "PSK-AES128-CCM");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_256_CCM, "PSK-AES256-CCM");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256, "PSK-AES128-CBC-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "ECDHE-ECDSA-AES128-GCM-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "ECDHE-ECDSA-AES256-GCM-SHA384");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, "ECDHE-ECDSA-AES128-CCM8:@SECLEVEL=0");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8, "ECDHE-ECDSA-AES256-CCM8:@SECLEVEL=0");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM, "ECDHE-ECDSA-AES128-CCM");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM, "ECDHE-ECDSA-AES256-CCM");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, "ECDHE-ECDSA-AES256-SHA");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, "ECDHE-ECDSA-AES128-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, "ECDHE-ECDSA-AES256-SHA384");

		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "ECDHE-RSA-AES128-GCM-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "ECDHE-RSA-AES256-GCM-SHA384");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "ECDHE-RSA-AES128-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "ECDHE-RSA-AES256-SHA");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, "ECDHE-RSA-AES256-SHA384");

		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_ARIA_128_GCM_SHA256, "PSK-ARIA128-GCM-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_ARIA_256_GCM_SHA384, "PSK-ARIA256-GCM-SHA384");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256, "ECDHE-ECDSA-ARIA128-GCM-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384, "ECDHE-ECDSA-ARIA256-GCM-SHA384");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256, "ECDHE-ARIA128-GCM-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384, "ECDHE-ARIA256-GCM-SHA384");

	}

	/**
	 * Get cipher suites supported by the jce.
	 * 
	 * The supported cipher suites depends on the jce version. GCM is supported
	 * with Java 8.
	 * 
	 * @return jce supported cipher suites
	 * @since 2.4
	 */
	public static Iterable<CipherSuite> getSupportedCipherSuites() {
		Set<CipherSuite> supported = new TreeSet<>();
		for (CipherSuite cipherSuite : CIPHERSUITES_MAP.keySet()) {
			if (cipherSuite.isSupported()) {
				supported.add(cipherSuite);
			}
		}
		return supported;
	}

	/**
	 * Get test cipher suites supported by the jce.
	 * 
	 * The supported cipher suites depends on the jce version. GCM is supported
	 * with Java 8.
	 * 
	 * @return jce supported test cipher suites
	 * @since 3.0
	 */
	public static Iterable<CipherSuite> getSupportedTestCipherSuites() {
		if (TestScope.enableIntensiveTests()) {
			return OpenSslUtil.getSupportedCipherSuites();
		} else {
			if (CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.isSupported()) {
				return Arrays.asList(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
						CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
			} else {
				return Arrays.asList(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
						CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
						CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
			}
		}
	}

	/**
	 * Get list of openssl cipher suite names.
	 * 
	 * @param ciphers Californium cipher suites.
	 * @return list of openssl cipher suite names separated by {@code ":"}.
	 * @throws IllegalArgumentException if cipher suite is provided, which is
	 *             not included in {@link #CIPHERSUITES_MAP}.
	 */
	public static String getOpenSslCipherSuites(CipherSuite... ciphers) {
		StringBuilder result = new StringBuilder();
		for (CipherSuite cipher : ciphers) {
			String openSslCipher = CIPHERSUITES_MAP.get(cipher);
			if (openSslCipher == null) {
				throw new IllegalArgumentException("'" + cipher + "' is not supported by openssl!");
			}
			result.append(openSslCipher);
			result.append(":");
		}
		if (result.length() > 0) {
			return result.substring(0, result.length() - 1);
		} else {
			return "";
		}
	}

	/**
	 * Get openssl signature and algorithm name.
	 * 
	 * @param jcaName JCA name. e.g. "SHA256withECDSA"
	 * @return openssl name. e.g. "ECDSA+SHA256"
	 * @throws IllegalArgumentException if jcaName does not contain a "with"
	 * @since 2.3
	 */
	public static String getOpenSslSignatureAndHashAlgorithm(String jcaName) {
		int index = jcaName.indexOf("with");
		if (index < 0) {
			index = jcaName.indexOf("WITH");
		}
		if (0 < index) {
			String hash = jcaName.substring(0, index);
			String signature = jcaName.substring(index + 4, jcaName.length());
			return signature + "+" + hash;
		} else {
			throw new IllegalArgumentException("'" + jcaName + "' does not contain 'with'");
		}
	}

	/**
	 * Get ":" separated list of openssl signature and algorithm names.
	 * 
	 * @param jcaNames JCA names. e.g. "SHA256withECDSA", "SHA256withRSA"
	 * @return openssl names. e.g. "ECDSA+SHA256:RSA+SHA256"
	 * @throws IllegalArgumentException if one of the jcaNames does not contain
	 *             a "with"
	 * @since 2.3
	 */
	public static String getOpenSslSignatureAndHashAlgorithms(String... jcaNames) {
		StringBuilder result = new StringBuilder();
		for (String jcaName : jcaNames) {
			result.append(getOpenSslSignatureAndHashAlgorithm(jcaName));
			result.append(":");
		}
		if (result.length() > 0) {
			return result.substring(0, result.length() - 1);
		} else {
			return "";
		}
	}
}
