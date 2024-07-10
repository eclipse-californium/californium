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

import java.net.URI;

/**
 * Http forward destination provider.
 * 
 * Resolves domain name to http destination.
 * 
 * @since 3.13
 */
public interface HttpForwardDestinationProvider {

	/**
	 * Device identity mode.
	 */
	enum DeviceIdentityMode {
		/**
		 * No device identity is forwarded.
		 */
		NONE,
		/**
		 * The device identity is forwarded as headline in the payload.
		 */
		HEADLINE,
		/**
		 * The device identity is forwarded as query-parameter "id".
		 */
		QUERY_PARAMETER
	};

	/**
	 * Http forward destination.
	 * 
	 * @param domain domain name
	 * @return http forward destination, or {@code null}, if domain doesn't use
	 *         http forwarding.
	 */
	URI getDestination(String domain);

	/**
	 * Get authentication credentials for the http forwarding.
	 * 
	 * @param domain domain name
	 * @return authentication credentials, or {@code null}, if no authentication
	 *         is used.
	 */
	String getAuthentication(String domain);

	/**
	 * Get device identity mode.
	 * 
	 * @param domain domain name
	 * @return device identity mode, or {@code null}, if no device identity is
	 *         forwarded.
	 */
	DeviceIdentityMode getDeviceIdentityMode(String domain);
}
