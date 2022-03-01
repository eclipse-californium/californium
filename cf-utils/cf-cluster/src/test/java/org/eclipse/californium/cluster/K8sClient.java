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
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.List;

/**
 * Simple test client for http k8s API pod discovering.
 * 
 * Setup environment "KUBECTL_TOKEN" with your microk8s access token.
 */
public class K8sClient {

	static {
		String property = System.getProperty("logback.configurationFile");
		if (property == null) {
			System.setProperty("logback.configurationFile", "logback-cluster-config.xml");
		}
	}

	public static void main(String[] args) {
		System.setProperty("KUBECTL_NODE_ID", "10");
		System.setProperty("KUBECTL_HOST", "https://10.152.183.1");
		System.setProperty("KUBECTL_NAMESPACE", "cali");
		System.setProperty("KUBECTL_SELECTOR_LABEL", "controller-revision-hash");
		try {
			K8sManagementJdkClient k8sClient = new K8sManagementJdkClient();
			K8sDiscoverClient client = new K8sDiscoverClient(k8sClient, 5885);
			List<InetSocketAddress> discoverScope = client.getClusterNodesDiscoverScope();
			if (discoverScope.isEmpty()) {
				System.out.println("no pods found!");
			} else {
				for (InetSocketAddress pod : discoverScope) {
					System.out.println("pod: " + pod);
				}
			}
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
