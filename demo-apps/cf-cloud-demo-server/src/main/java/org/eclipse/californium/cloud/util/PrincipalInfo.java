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

import java.security.Principal;

import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.auth.AdditionalInfo;
import org.eclipse.californium.elements.auth.ExtensiblePrincipal;

/**
 * Principal info.
 * 
 * Application relevant information of principal.
 * 
 * @since 4.0
 */
public class PrincipalInfo {

	/**
	 * Key for principal info provider in additional info.
	 */
	public static final String INFO_PROVIDER = "provider";
	/**
	 * Key for principal name in additional info.
	 */
	public static final String INFO_NAME = "name";

	/**
	 * Type of principal info.
	 */
	public enum Type {

		/**
		 * Device principal info.
		 */
		DEVICE("dev"),
		/**
		 * Provisioning principal info.
		 */
		PROVISIONING("prov"),
		/**
		 * Certificate authority principal info.
		 */
		CA("ca"),
		/**
		 * Web user principal info
		 */
		WEB("web");

		/**
		 * Short name. Using in device storage files.
		 */
		private final String shortName;

		/**
		 * Create instance with short name.
		 * 
		 * @param shortName short name for device storage files
		 */
		private Type(String shortName) {
			this.shortName = shortName;
		}

		/**
		 * Get short name.
		 * 
		 * @return short name
		 */
		public String getShortName() {
			return shortName;
		}

		/**
		 * Get type based on short name.
		 * 
		 * @param shortName short name of type
		 * @return type with short name
		 */
		public static Type valueOfShortName(String shortName) {
			for (Type type : Type.values()) {
				if (shortName.equalsIgnoreCase(type.getShortName())) {
					return type;
				}
			}
			return null;
		}
	}

	/**
	 * Principal name.
	 */
	public final String name;
	/**
	 * Principal group.
	 */
	public final String group;
	/**
	 * Principal type.
	 */
	public final Type type;

	/**
	 * Create principal info.
	 * 
	 * @param group group of principal
	 * @param name name of principal
	 * @param type type of principal
	 */
	public PrincipalInfo(String group, String name, Type type) {
		this.name = name;
		this.group = group;
		this.type = type;
	}

	@Override
	public String toString() {
		return name + " (" + group + "," + type.getShortName() + ")";
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
	public static PrincipalInfo getPrincipalInfo(Principal principal) {
		if (principal instanceof ExtensiblePrincipal) {
			@SuppressWarnings("unchecked")
			ExtensiblePrincipal<? extends Principal> extensiblePrincipal = (ExtensiblePrincipal<? extends Principal>) principal;
			PrincipalInfoProvider provider = extensiblePrincipal.getExtendedInfo().get(INFO_PROVIDER,
					PrincipalInfoProvider.class);
			if (provider != null) {
				return provider.getPrincipalInfo(extensiblePrincipal);
			}
		}
		return null;
	}

}
