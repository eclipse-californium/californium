/*******************************************************************************
 * Copyright (c) 2022 Bosch.IO GmbH and others.
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
 * K8s management client.
 *
 * Uses k8s management API to list cluster-pods:
 * 
 * <ul>
 * <li>{@code "${KUBECTL_HOST}/api/v1/namespaces/default/pods"}</li>
 * <li>{@code "${KUBECTL_HOST}/api/v1/namespaces/${KUBECTL_NAMESPACE}/pods}"</li>
 * <li>{@code "${KUBECTL_HOST}/api/v1/namespaces/${KUBECTL_NAMESPACE}/pods?labelSelector=app%3D${pod.label}"}</li>
 * </ul>
 * 
 * @since 3.4
 */
public class K8sManagementJdkClient extends K8sManagementClient {

	/**
	 * Create k8s management client.
	 * 
	 * @throws GeneralSecurityException if initializing ssl context fails
	 * @throws IOException if loading trust store fails
	 */
	public K8sManagementJdkClient() throws GeneralSecurityException, IOException {
		super();
	}

	@Override
	public HttpResult executeHttpRequest(String url, String token, SSLContext sslContext)
			throws IOException, GeneralSecurityException {

		return new JdkHttpClient().get(url, token, true, sslContext);
	}
}
