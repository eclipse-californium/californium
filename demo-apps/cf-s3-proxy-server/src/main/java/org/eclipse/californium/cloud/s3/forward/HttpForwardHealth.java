/********************************************************************************
 * Copyright (c) 2025 Contributors to the Eclipse Foundation
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

/**
 * Http forward health.
 * 
 * @since 4.0
 */
public interface HttpForwardHealth {

	/**
	 * Report http forwards or failures.
	 * 
	 * @param domain domain name
	 * @param success {@code true} for successful forward, {@code false} on
	 *            failure
	 */
	void forwarded(String domain, boolean success);

}
