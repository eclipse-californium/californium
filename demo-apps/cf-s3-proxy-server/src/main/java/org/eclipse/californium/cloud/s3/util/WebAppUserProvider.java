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
 * Domain web application user provider.
 * <p>
 * Resolves domain- and/or user names to {@link WebAppDomainUser}.
 * 
 * @since 3.12
 */
public interface WebAppUserProvider {

	/**
	 * Gets domain user.
	 * 
	 * @param domainName domain name. Maybe {@code null}, if user name is unique.
	 * @param userName user name
	 * 
	 * @return domain user or {@code null}, if unknown.
	 * @see DomainNamePair
	 */
	WebAppDomainUser getDomainUser(String domainName, String userName);
}
