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
package org.eclipse.californium.elements.auth;

import java.util.Objects;

/**
 * Application level principal.
 * 
 * @since 4.0
 */
public class ApplicationPrincipal extends AbstractExtensiblePrincipal<ApplicationPrincipal> {

	/**
	 * Anonymous principal.
	 */
	public static final ApplicationPrincipal ANONYMOUS = new ApplicationPrincipal("anonymous");

	/**
	 * Principal's name.
	 */
	private final String name;

	/**
	 * Creates an application principal.
	 * 
	 * @param name name
	 */
	public ApplicationPrincipal(String name) {
		this.name = name;
	}

	/**
	 * Creates an application principal.
	 * 
	 * @param name name
	 * @param additionalInformation additional information
	 */
	private ApplicationPrincipal(String name, AdditionalInfo additionalInformation) {
		super(additionalInformation);
		this.name = name;
	}

	@Override
	public ApplicationPrincipal amend(AdditionalInfo additionalInfo) {
		return new ApplicationPrincipal(name, additionalInfo);
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String toString() {
		return "Application Prinicpal [" + name + "]";
	}

	@Override
	public int hashCode() {
		return name.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		} else if (obj == null) {
			return false;
		} else if (getClass() != obj.getClass()) {
			return false;
		}
		ApplicationPrincipal other = (ApplicationPrincipal) obj;
		return Objects.equals(name, other.name);
	}

}
