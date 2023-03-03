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

/**
 * Domain user.
 * 
 * Domain name and user pair.
 * 
 * @since 3.12
 */
public class WebAppDomainUser {

	/**
	 * User.
	 */
	public final WebAppUser user;
	/**
	 * Domain name.
	 */
	public final String domain;

	/**
	 * Create domain user.
	 * 
	 * @param domain domain name
	 * @param user user
	 */
	public WebAppDomainUser(String domain, WebAppUser user) {
		this.domain = domain;
		this.user = user;
	}
}
