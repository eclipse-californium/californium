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

import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;

/**
 * Utility for openssl. Map of {@link CipherSuite} to openssl cipher suite name.
 */
public class OpenSslUtil {

	public static final Map<CipherSuite, String> CIPHERSUITES_MAP = new HashMap<CipherSuite, String>();

	static {
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, "ECDHE-PSK-AES128-CBC-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256, "PSK-AES128-GCM-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA378, "PSK-AES256-GCM-SHA384");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8, "PSK-AES128-CCM8");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_256_CCM_8, "PSK-AES256-CCM8");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_128_CCM, "PSK-AES128-CCM");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_256_CCM, "PSK-AES256-CCM");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256, "PSK-AES128-CBC-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "ECDHE-ECDSA-AES128-GCM-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "ECDHE-ECDSA-AES256-GCM-SHA384");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, "ECDHE-ECDSA-AES128-CCM8");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8, "ECDHE-ECDSA-AES256-CCM8");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM, "ECDHE-ECDSA-AES128-CCM");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM, "ECDHE-ECDSA-AES256-CCM");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, "ECDHE-ECDSA-AES256-SHA");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, "ECDHE-ECDSA-AES128-SHA256");
		CIPHERSUITES_MAP.put(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, "ECDHE-ECDSA-AES256-SHA384");
	}
}
