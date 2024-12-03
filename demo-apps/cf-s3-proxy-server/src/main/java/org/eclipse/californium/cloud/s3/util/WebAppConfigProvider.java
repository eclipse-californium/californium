/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.cloud.s3.util;

import java.util.Map;

/**
 * Web application configuration provider.
 * <p>
 * Resolves domain-section-name pairs to set of web application configuration
 * values.
 * 
 * @since 3.12
 */
public interface WebAppConfigProvider {

	String CONFIGURATION_PREFIX = ".config";
	String DIAGNOSE_NAME = "diagnose";
	String CONFIGWRITE_NAME = "ConfigWrite";

	/**
	 * Get web application configuration values of subsection.
	 * 
	 * @param domain domain name
	 * @param section section
	 * @return set of web application configuration values
	 */
	Map<String, Map<String, String>> getSubSections(String domain, String section);

	/**
	 * Get web application configuration value.
	 * 
	 * @param domain domain name
	 * @param section section
	 * @param name name of web application configuration parameter.
	 * @return web application configuration value
	 */
	String get(String domain, String section, String name);

	/**
	 * Remove web application configuration value.
	 * 
	 * @param domain domain name
	 * @param section section
	 * @param name name of web application configuration parameter.
	 * @return removed web application configuration value, {@code null}, if
	 *         field wasn't available.
	 * @since 4.0
	 */
	String remove(String domain, String section, String name);

	/**
	 * Check, if value is available and not {@code "false"} nor {@code 0}.
	 * 
	 * @param domain domain name
	 * @param section section
	 * @param name name of web application configuration parameter.
	 * @return {@code true}, if value is available and not {@code "false"} nor
	 *         {@code 0}, {@code false}, otherwise.
	 */
	default boolean isEnabled(String domain, String section, String name) {
		String value = get(domain, section, name);
		return value != null && !value.equalsIgnoreCase("false") && !value.equals("0");
	}
}
