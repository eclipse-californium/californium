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

import org.eclipse.californium.cloud.util.DeviceManager.DeviceInfo;

/**
 * Device provisioning consumer.
 * 
 * @since 3.13
 */
public interface DeviceProvisioningConsumer {

	/**
	 * Add data to device store.
	 * 
	 * @param info device info of provisioning.
	 * @param time timestamp of request.
	 * @param data data to add.
	 * @param response response consumer.
	 */
	void add(DeviceInfo info, long time, String data, ResultConsumer response);
}
