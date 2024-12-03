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
 * Domain name.
 * <p>
 * Pair of domain name and name.
 * 
 * @since 3.12
 */
public class DomainNamePair {

	/**
	 * Name in domain.
	 */
	public final String name;
	/**
	 * Domain name.
	 */
	public final String domain;

	/**
	 * Creates domain name pair.
	 * 
	 * @param domain domain name
	 * @param name name
	 */
	public DomainNamePair(String domain, String name) {
		this.domain = domain;
		this.name = name;
	}

	/**
	 * Creates domain name pair.
	 * <p>
	 * Splits provided name at {@code @}. First part is considered as name,
	 * second, if available is considered as domain name.
	 * 
	 * @param name full name
	 * @return domain name pair.
	 * @throws NullPointerException if name is {@code null}
	 */
	public static DomainNamePair fromName(String name) {
		if (name == null) {
			throw new NullPointerException("name must not be null!");
		}
		String[] pair = name.split("@", 2);
		if (pair.length == 2) {
			return new DomainNamePair(pair[1], pair[0]);
		} else {
			return new DomainNamePair(null, pair[0]);
		}
	}
}
