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

import java.util.Set;

import org.eclipse.californium.cloud.util.DeviceIdentifier;

/**
 * Device groups provider.
 * <p>
 * Resolves domain-group name pairs to set of devices.
 * 
 * @since 3.12
 */
public interface DeviceGroupProvider {

	/**
	 * Get group of device names.
	 * 
	 * @param domain domain name
	 * @param group group name
	 * @return set of device identifiers.
	 * @since 3.13 use DeviceIdentifier instead of String
	 */
	Set<DeviceIdentifier> getGroup(String domain, String group);
}
