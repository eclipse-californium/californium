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

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

/**
 * Utility for tinydtls.
 * 
 * Map of {@link CipherSuite} to tinydtls cipher suite name.
 * 
 * @since 3.8
 */
public class TinydtlsUtil {

	/**
	 * Map of Californium's cipher suites to tinydtls names.
	 */
	public static final Map<CipherSuite, String> CIPHERSUITES_MAP = new HashMap<CipherSuite, String>();

	static {
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8, "TLS_PSK_WITH_AES_128_CCM_8");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_128_CCM, "TLS_PSK_WITH_AES_128_CCM");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM, "TLS_ECDHE_ECDSA_WITH_AES_128_CCM");
	}

	/**
	 * Get cipher suites supported by the JCE.
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
	 * @return JCE supported test cipher suites
	 */
	public static Iterable<CipherSuite> getSupportedTestCipherSuites() {
		return TinydtlsUtil.getSupportedCipherSuites();
	}

	/**
	 * Get tinydtls cipher suite name.
	 * 
	 * @param cipherSuite Californium cipher suite.
	 * @return tinydtls cipher suite name.
	 * @throws IllegalArgumentException if cipher suite is provided, which is
	 *             not included in {@link #CIPHERSUITES_MAP}.
	 */
	public static String getTinydtlsCipherSuites(CipherSuite cipherSuite) {
		String tinydtlsCipher = CIPHERSUITES_MAP.get(cipherSuite);
		if (tinydtlsCipher == null) {
			throw new IllegalArgumentException("'" + cipherSuite + "' is not supported by tinydtls!");
		}
		return tinydtlsCipher;
	}
}
