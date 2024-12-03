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
package org.eclipse.californium.cloud.util;

/**
 * Device identifier.
 * 
 * @since 3.13
 */
public interface DeviceIdentifier {

	/**
	 * Get device name.
	 * <p>
	 * The name is a fixed identifier for the device.
	 * 
	 * @return device name
	 */
	String getName();

	/**
	 * Get device label.
	 * <p>
	 * The label is displayed identifier, which may be adapted from time to
	 * time.
	 * 
	 * @return label. {@code null}, if name should be used as displayed
	 *         identifier
	 */
	String getLabel();

}
