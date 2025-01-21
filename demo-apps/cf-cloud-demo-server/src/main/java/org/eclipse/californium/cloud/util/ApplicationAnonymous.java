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
package org.eclipse.californium.cloud.util;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.cloud.util.PrincipalInfo.Type;
import org.eclipse.californium.elements.auth.AdditionalInfo;
import org.eclipse.californium.elements.auth.ApplicationPrincipal;

/**
 * Application level anonymous.
 * 
 * @since 4.0
 */
public class ApplicationAnonymous {

	public static final PrincipalInfo ANONYMOUS_INFO = new PrincipalInfo(ApplicationPrincipal.ANONYMOUS.getName(),
			ApplicationPrincipal.ANONYMOUS.getName(), Type.ANONYMOUS_DEVICE);

	public static final PrincipalInfo APPL_AUTH_INFO = new PrincipalInfo(ApplicationPrincipal.ANONYMOUS.getName(),
			ApplicationPrincipal.ANONYMOUS.getName(), Type.APPL_AUTH_DEVICE);

	/**
	 * Application anonymous principal.
	 */
	public static final ApplicationPrincipal APPL_AUTH_PRINCIPAL;

	static {
		Map<String, Object> info = new HashMap<>();
		info.put(PrincipalInfo.INFO_NAME, ApplicationPrincipal.ANONYMOUS.getName());
		info.put(PrincipalInfo.INFO_PROVIDER, new PrincipalInfoProvider() {
			
			@Override
			public PrincipalInfo getPrincipalInfo(Principal principal) {
				if (ApplicationPrincipal.ANONYMOUS.equals(principal)) {
					return APPL_AUTH_INFO;
				}
				return null;
			}
		});
		APPL_AUTH_PRINCIPAL = ApplicationPrincipal.ANONYMOUS.amend(AdditionalInfo.from(info));
	}
}
