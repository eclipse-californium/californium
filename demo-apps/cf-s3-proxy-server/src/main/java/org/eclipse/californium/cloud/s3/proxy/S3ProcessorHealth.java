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
package org.eclipse.californium.cloud.s3.proxy;

/**
 * S3 processor health.
 * 
 * @since 3.13
 */
public interface S3ProcessorHealth {

	/**
	 * Report processed days or failures.
	 * 
	 * @param domain domain name
	 * @param days number of processed days, or {@code -1} on failure
	 */
	void processedDay(String domain, int days);

	/**
	 * Report device currently pending processing.
	 * 
	 * @param domain domain name
	 * @param devices number of pending devices
	 */
	void processingDevices(String domain, int devices);

}
