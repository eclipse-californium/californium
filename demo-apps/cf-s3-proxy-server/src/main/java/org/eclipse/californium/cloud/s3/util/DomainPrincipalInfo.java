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
	 * Create domain principal info
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

	/**
	 * Get principal info.
	 * 
	 * Only {@link ExtensiblePrincipal} with {@link AdditionalInfo}
	 * {@link #INFO_PROVIDER} are supported.
	 * 
	 * @param principal the principal
	 * @return principal info, or {@code null}, if not available.
	 * @see EndpointContext#getPeerIdentity()
	 */
	public static DomainPrincipalInfo getPrincipalInfo(Principal principal) {
		if (principal instanceof ExtensiblePrincipal) {
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
	 * Get domain.
	 * 
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
