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
package org.eclipse.californium.cloud.s3.forward;

import org.eclipse.californium.cloud.s3.util.DomainPrincipalInfo;

/**
 * Http forward provider.
 * <p>
 * Resolves domain and device name to http destination, authentication, mode and
 * filter.
 * 
 * @since 4.0
 */
public interface HttpForwardConfigurationProvider {

	/**
	 * Gets http forward configuration.
	 * 
	 * @param principalInfo principal info (with domain and device name)
	 * @return http forward configuration, or {@code null}, if http forwarding
	 *         is not used.
	 */
	HttpForwardConfiguration getConfiguration(DomainPrincipalInfo principalInfo);

}
