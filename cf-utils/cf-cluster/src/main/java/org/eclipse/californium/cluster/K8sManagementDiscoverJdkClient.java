/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.cluster;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.net.ssl.SSLContext;

/**
 * K8s discover implementation using the jdk http-client.
 * 
 * @since 2.5
 */
public class K8sManagementDiscoverJdkClient extends K8sManagementDiscoverClient {

	/**
	 * Create k8s discover client.
	 * 
	 * @param externalPort external/exposed port for cluster internal management
	 *            interfaces.
	 * @throws GeneralSecurityException if initializing ssl context fails
	 * @throws IOException if loading trust store fails
	 */
	public K8sManagementDiscoverJdkClient(int externalPort) throws GeneralSecurityException, IOException {
		super(externalPort);
	}

	@Override
	public HttpResult executeHttpRequest(String url, String token, SSLContext sslContext)
			throws IOException, GeneralSecurityException {

		return new JdkHttpClient().get(url, token, true, sslContext);
	}
}
