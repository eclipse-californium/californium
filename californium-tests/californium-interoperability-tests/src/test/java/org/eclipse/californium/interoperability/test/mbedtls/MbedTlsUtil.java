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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.eclipse.californium.elements.util.TestScope;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

/**
 * Utility for Mbed TLS. Map of {@link CipherSuite} to Mbed TLS cipher suite
 * name.
 * 
 * @since 3.3
 */
public class MbedTlsUtil {

	/**
	 * Map of Californium's cipher suites to Mbed TLS names.
	 */
	public static final Map<CipherSuite, String> CIPHERSUITES_MAP = new HashMap<CipherSuite, String>();

	static {
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
				"TLS-ECDHE-PSK-WITH-AES-128-CBC-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256, "TLS-PSK-WITH-AES-128-GCM-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA378, "TLS-PSK-WITH-AES-256-GCM-SHA384");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8, "TLS-PSK-WITH-AES-128-CCM-8");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_256_CCM_8, "TLS-PSK-WITH-AES-256-CCM-8");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_128_CCM, "TLS-PSK-WITH-AES-128-CCM");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_256_CCM, "TLS-PSK-WITH-AES-256-CCM");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256, "TLS-PSK-WITH-AES-128-CBC-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				"TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				"TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, "TLS-ECDHE-ECDSA-WITH-AES-128-CCM-8");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8, "TLS-ECDHE-ECDSA-WITH-AES-256-CCM-8");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM, "TLS-ECDHE-ECDSA-WITH-AES-128-CCM");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM, "TLS-ECDHE-ECDSA-WITH-AES-256-CCM");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, "TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
				"TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
				"TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384");

		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				"TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				"TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
				"TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
				"TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384");

		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_ARIA_128_GCM_SHA256,
				"TLS-PSK-WITH-ARIA-128-GCM-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_ARIA_256_GCM_SHA384,
				"TLS-PSK-WITH-ARIA-256-GCM-SHA384");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_ARIA_128_CBC_SHA256,
				"TLS-PSK-WITH-ARIA-128-CBC-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_ARIA_256_CBC_SHA384,
				"TLS-PSK-WITH-ARIA-256-CBC-SHA384");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256,
				"TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384,
				"TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
				"TLS-ECDHE-ECDSA-WITH-ARIA-128-GCM-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
				"TLS-ECDHE-ECDSA-WITH-ARIA-256-GCM-SHA384");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
				"TLS-ECDHE-RSA-WITH-ARIA-128-GCM-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
				"TLS-ECDHE-RSA-WITH-ARIA-256-GCM-SHA384");
	}

	/**
	 * Get cipher suites supported by the JCE.
	 * 
	 * The supported cipher suites depends on the JCE version. GCM is supported
	 * with Java 8.
	 * 
	 * @return JCE supported cipher suites
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
	 * Get test cipher suites supported by the JCE.
	 * 
	 * The supported cipher suites depends on the JCE version. GCM is supported
	 * with Java 8.
	 * 
	 * @return JCE supported test cipher suites
	 */
	public static Iterable<CipherSuite> getSupportedTestCipherSuites() {
		if (TestScope.enableIntensiveTests()) {
			return MbedTlsUtil.getSupportedCipherSuites();
		} else {
			if (CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.isSupported()) {
				return Arrays.asList(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
						CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
			} else {
				return Arrays.asList(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
						CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
						CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
			}
		}
	}

	/**
	 * Get Mbed TLS cipher suite name.
	 * 
	 * @param cipherSuite Californium cipher suite.
	 * @return Mbed TLS cipher suite name.
	 * @throws IllegalArgumentException if cipher suite is provided, which is
	 *             not included in {@link #CIPHERSUITES_MAP}.
	 */
	public static String getMbedTlsCipherSuites(CipherSuite cipherSuite) {
		String mbedTlsCipher = CIPHERSUITES_MAP.get(cipherSuite);
		if (mbedTlsCipher == null) {
			throw new IllegalArgumentException("'" + cipherSuite + "' is not supported by Mbed TLS!");
		}
		return mbedTlsCipher;
	}
}
