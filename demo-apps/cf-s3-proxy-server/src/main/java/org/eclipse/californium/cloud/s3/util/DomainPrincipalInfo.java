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

import java.security.Principal;

import org.eclipse.californium.cloud.util.PrincipalInfo;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.auth.AdditionalInfo;
import org.eclipse.californium.elements.auth.ExtensiblePrincipal;

/**
 * Domain principal info.
 * 
 * @since 4.0
 */
public class DomainPrincipalInfo extends PrincipalInfo {

	/**
	 * Key for domain name in additional info.
	 */
	public static final String INFO_DOMAIN = "domain";

	/**
	 * Principal domain.
	 */
	public final String domain;

	/**
	 * Creates domain principal info.
	 * 
	 * @param domain domain name of principal
	 * @param group group of principal
	 * @param name name of principal
	 * @param type type of principal
	 */
	public DomainPrincipalInfo(String domain, String group, String name, Type type) {
		super(group, name, type);
		if (domain == null) {
			domain = DomainDeviceManager.DEFAULT_DOMAIN;
		}
		this.domain = domain;
	}

	@Override
	public String toString() {
		return name + "@" + domain + " (" + group + "," + type.getShortName() + ")";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + domain.hashCode();
		result = prime * result + group.hashCode();
		result = prime * result + name.hashCode();
		result = prime * result + type.hashCode();
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		DomainPrincipalInfo other = (DomainPrincipalInfo) obj;
		if (!domain.equals(other.domain)) {
			return false;
		} else if (!group.equals(other.group)) {
			return false;
		} else if (!name.equals(other.name)) {
			return false;
		} else if (type != other.type) {
			return false;
		}
		return true;
	}

	/**
	 * Gets principal info.
	 * <p>
	 * Only {@link ExtensiblePrincipal} with {@link AdditionalInfo}
	 * {@link #INFO_PROVIDER} are supported.
	 * 
	 * @param principal the principal
	 * @return principal info, or {@code null}, if not available.
	 * @see EndpointContext#getPeerIdentity()
	 * @since 4.0 (supports {@link DomainApplicationAnonymous#ANONYMOUS_INFO}, if {@code null} is provided as
	 *        principal.)
	 */
	public static DomainPrincipalInfo getPrincipalInfo(Principal principal) {
		if (principal == null) {
			return DomainApplicationAnonymous.ANONYMOUS_INFO;
		} else if (principal instanceof ExtensiblePrincipal) {
			@SuppressWarnings("unchecked")
			ExtensiblePrincipal<? extends Principal> extensiblePrincipal = (ExtensiblePrincipal<? extends Principal>) principal;
			DomainPrincipalInfoProvider provider = extensiblePrincipal.getExtendedInfo().get(INFO_PROVIDER,
					DomainPrincipalInfoProvider.class);
			if (provider != null) {
				return provider.getPrincipalInfo(extensiblePrincipal);
			}
		}
		return null;
	}

	/**
	 * Gets domain.
	 * <p>
	 * Only {@link ExtensiblePrincipal} with {@link AdditionalInfo}
	 * {@link #INFO_DOMAIN} are supported.
	 * 
	 * @param principal the principal
	 * @return domain name, or {@code null}, if not available.
	 * @see EndpointContext#getPeerIdentity()
	 */
	public static String getDomain(Principal principal) {
		if (principal instanceof ExtensiblePrincipal) {
			@SuppressWarnings("unchecked")
			ExtensiblePrincipal<? extends Principal> extensiblePrincipal = (ExtensiblePrincipal<? extends Principal>) principal;
			return extensiblePrincipal.getExtendedInfo().get(INFO_DOMAIN, String.class);
		}
		return null;
	}

}
