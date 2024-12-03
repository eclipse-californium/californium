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

import java.util.Set;

/**
 * S3 proxy client provider.
 * 
 * @since 3.12
 */
public interface S3ProxyClientProvider {

	/**
	 * Gets domains.
	 * 
	 * @return set of domain names.
	 * @since 3.13
	 */
	Set<String> getDomains();

	/**
	 * Gets S3 proxy client for domain.
	 * 
	 * @param domain domain name
	 * @return S3 proxy client, or {@code null}, if not available.
	 */
	S3ProxyClient getProxyClient(String domain);

	/**
	 * Gets S3 proxy client for web resources.
	 * 
	 * @return S3 proxy client for web resources
	 */
	S3ProxyClient getWebClient();

}
