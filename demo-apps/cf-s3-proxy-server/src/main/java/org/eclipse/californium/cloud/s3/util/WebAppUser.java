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

import java.util.List;

/**
 * Web application's user credentials.
 * 
 * @since 3.12
 */
public class WebAppUser {

	/**
	 * User name for web application login service.
	 */
	public final String name;
	/**
	 * Password for web application login service.
	 */
	public final String password;
	/**
	 * S3 access key identity.
	 */
	public final String accessKeyId;
	/**
	 * S3 access key secret.
	 */
	public final String accessKeySecret;
	/**
	 * Web application configuration.
	 */
	public final String webAppConfig;
	/**
	 * List of groups.
	 */
	public final List<String> groups;

	/**
	 * Creates web application's user credentials.
	 * 
	 * @param name login service user name
	 * @param password login service password
	 * @param accessKeyId S3 access key identity
	 * @param accessKeySecret S3 access key secret
	 * @param config "Single Page Application" configuration
	 * @param groups list of groups
	 */
	public WebAppUser(String name, String password, String accessKeyId, String accessKeySecret, String config,
			List<String> groups) {
		this.name = name;
		this.password = password;
		this.accessKeyId = accessKeyId;
		this.accessKeySecret = accessKeySecret;
		this.webAppConfig = config;
		this.groups = groups;
	}

	@Override
	public int hashCode() {
		return name.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		WebAppUser other = (WebAppUser) obj;
		if (!name.equals(other.name))
			return false;
		return true;
	}

	/**
	 * Creates web application's user builder.
	 * 
	 * @return web application's user builder
	 */
	public static WebAppUser.Builder builder() {
		return new Builder();
	}

	/**
	 * web application's user builder.
	 */
	public static class Builder {

		/**
		 * User name for web application login service.
		 */
		public String name;
		/**
		 * Password for web application login service.
		 */
		public String password;
		/**
		 * S3 access key identity.
		 */
		public String accessKeyId;
		/**
		 * S3 access key secret.
		 */
		public String accessKeySecret;
		/**
		 * Web application configuration.
		 */
		public String webAppConfig;
		/**
		 * List of groups.
		 */
		public List<String> groups;

		/**
		 * Creates builder.
		 */
		private Builder() {

		}

		/**
		 * Creates web application user.
		 * 
		 * @return web application user
		 */
		public WebAppUser build() {
			return new WebAppUser(name, password, accessKeyId, accessKeySecret, webAppConfig, groups);
		}
	}
}
