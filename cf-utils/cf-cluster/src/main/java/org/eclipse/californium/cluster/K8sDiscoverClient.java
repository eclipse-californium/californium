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
 *                    derived from K8sManagementDiscoverJdkClient
 ******************************************************************************/
package org.eclipse.californium.cluster;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import javax.crypto.SecretKey;

import org.eclipse.californium.cluster.DtlsClusterManager.ClusterNodesDiscover;
import org.eclipse.californium.cluster.K8sManagementClient.Pod;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsClusterConnectorConfig.Builder;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * K8s discover implementation.
 *
 * Uses k8s management API to list cluster-pods:
 * 
 * <ul>
 * <li>{@code "${KUBECTL_HOST}/api/v1/namespaces/default/pods"}</li>
 * <li>{@code "${KUBECTL_HOST}/api/v1/namespaces/${KUBECTL_NAMESPACE}/pods}"</li>
 * <li>{@code "${KUBECTL_HOST}/api/v1/namespaces/${KUBECTL_NAMESPACE}/pods?labelSelector=app%3D${pod.label}"}</li>
 * </ul>
 * 
 * Excludes own pod (hostname) from {@link #getClusterNodesDiscoverScope()}.
 * 
 * Supported environment variables:
 * <dl>
 * <dt>KUBECTL_SELECTOR</dt>
 * <dd>selector expression. Optional, value e.g. "app%3Dcf-extserver"</dd>
 * <dt>KUBECTL_SELECTOR_LABEL</dt>
 * <dd>selector expression. Optional, default "controller-revision-hash"</dd>
 * <dt>DTLS_CID_MGMT_IDENTITY</dt>
 * <dd>PSK identity for cluster management interface encryption</dd>
 * <dt>DTLS_CID_MGMT_SECRET_BASE64</dt>
 * <dd>PSK secret in base64 for cluster management interface encryption</dd>
 * </dl>
 * 
 * @since 3.4
 */
public class K8sDiscoverClient implements ClusterNodesDiscover {

	private static final Logger LOGGER = LoggerFactory.getLogger(K8sDiscoverClient.class);

	private static final String KUBECTL_SELECTOR = "KUBECTL_SELECTOR";
	private static final String KUBECTL_SELECTOR_LABEL = "KUBECTL_SELECTOR_LABEL";
	private static final String KUBECTL_NODE_ID = "KUBECTL_NODE_ID";
	private static final String DTLS_CID_MGMT_IDENTITY = "DTLS_CID_MGMT_IDENTITY";
	private static final String DTLS_CID_MGMT_SECRET_BASE64 = "DTLS_CID_MGMT_SECRET_BASE64";
	private static final String INITIAL_CLUSTERNODES_LABEL = "initialDtlsClusterNodes";
	private static final String DEFAULT_SELECTOR_LABEL = "controller-revision-hash";

	private final K8sManagementClient client;
	/**
	 * External (exposed) ports for cluster internal management interfaces.
	 */
	private final int externalPort;
	/**
	 * Node-id of this {@link DTLSConnector}.
	 */
	private final int nodeId;
	/**
	 * k8s selector for cid-cluster pods.
	 */
	private final String selector;

	/**
	 * List of ip-addresses for k8s cid-cluster pods.
	 */
	private final List<String> discoverScope = new ArrayList<>();

	private final int clusterNodes;

	/**
	 * Create k8s discover client.
	 * 
	 * @param client k8s management client used to discover cluster nodes
	 * @param externalPort external/exposed port for cluster internal management
	 *            interfaces.
	 * @throws GeneralSecurityException if initializing ssl context fails
	 * @throws IOException if loading trust store fails
	 */
	public K8sDiscoverClient(K8sManagementClient client, int externalPort)
			throws GeneralSecurityException, IOException {
		this.client = client;
		this.externalPort = externalPort;
		Integer node = null;
		String id = StringUtil.getConfiguration(KUBECTL_NODE_ID);
		if (id != null && !id.isEmpty()) {
			try {
				node = Integer.valueOf(id);
			} catch (NumberFormatException ex) {
				LOGGER.warn("KUBECTL_NODE_ID: {}", id, ex);
			}
		}
		String hostName = client.getHostName();
		if (node == null) {
			int pos = hostName.lastIndexOf("-");
			if (pos >= 0) {
				id = hostName.substring(pos + 1);
				try {
					node = Integer.valueOf(id);
				} catch (NumberFormatException ex) {
					LOGGER.warn("HOSTNAME: {}", hostName, ex);
				}
			}
		}
		if (node != null) {
			nodeId = node;
		} else {
			throw new IllegalArgumentException("node-id not available!");
		}

		String selector = StringUtil.getConfiguration(KUBECTL_SELECTOR);
		if (selector == null || selector.isEmpty()) {
			String label = StringUtil.getConfiguration(KUBECTL_SELECTOR_LABEL);
			if (label == null || label.isEmpty()) {
				label = DEFAULT_SELECTOR_LABEL;
			}
			selector = client.getLabelSelector(label);
		}
		this.selector = selector;
		int clusterNodes = 0;
		String nodesLabel = client.getLabel(INITIAL_CLUSTERNODES_LABEL);
		if (nodesLabel != null) {
			try {
				clusterNodes = Integer.parseInt(nodesLabel);
			} catch (NumberFormatException ex) {
			}
		}
		this.clusterNodes = clusterNodes;
		LOGGER.info("Node-ID: {}, external-port: {}, cluster-nodes: {}, selector: {}", nodeId, externalPort,
				clusterNodes, selector);
	}

	/**
	 * Get node-id.
	 * 
	 * @return node-id
	 * @throws IllegalStateException if node-id is not available (no cluster
	 *             support)
	 */
	public int getNodeID() {
		if (nodeId < 0) {
			throw new IllegalStateException("node-id not available!");
		}
		return nodeId;
	}

	@Override
	public List<InetSocketAddress> getClusterNodesDiscoverScope() {
		List<InetSocketAddress> scope = new ArrayList<>();
		try {
			String hostName = client.getHostName();
			String append = null;
			if (selector != null) {
				append = "?labelSelector=" + selector;
			}
			Set<Pod> pods = client.getPods(append);
			for (Pod pod : pods) {
				LOGGER.info("{}", pod);
			}
			LOGGER.info("host: {}", client.hostName);
			synchronized (discoverScope) {
				discoverScope.clear();
				for (Pod pod : pods) {
					if (pod.address != null && !hostName.equals(pod.name)) {
						discoverScope.add(pod.address);
					}
				}
				for (String address : discoverScope) {
					scope.add(new InetSocketAddress(address, externalPort));
				}
			}
		} catch (HttpResultException e) {
			LOGGER.error("http: ", e);
		} catch (IOException e) {
			LOGGER.error("error: ", e);
		} catch (GeneralSecurityException e) {
			LOGGER.error("error: ", e);
		}
		return scope;
	}

	@Override
	public int getInitialClusterNodes() {
		return clusterNodes;
	}

	/**
	 * Amend k8s environment to {@link Builder}.
	 * 
	 * Set {@code DTLS_CID_MGMT_IDENTITY} and
	 * {@code DTLS_CID_MGMT_SECRET_BASE64}, if available.
	 * 
	 * @param builder builder to amend environment
	 * @return passed in builder for command chaining.
	 */
	public static Builder setConfiguration(Builder builder) {
		String identity = StringUtil.getConfiguration(DTLS_CID_MGMT_IDENTITY);
		String secret = StringUtil.getConfiguration(DTLS_CID_MGMT_SECRET_BASE64);
		if (identity != null && secret != null) {
			byte[] secretBytes = StringUtil.base64ToByteArray(secret);
			SecretKey key = SecretUtil.create(secretBytes, "PSK");
			Arrays.fill(secretBytes, (byte) 0);
			builder.setSecure(identity, key);
			SecretUtil.destroy(key);
			int len = secret.length();
			int end = len > 20 ? 10 : len / 2;
			LOGGER.info("PSK identity {}, secret {}... ({} bytes)", identity, secret.substring(0, end),
					secretBytes.length);
		}
		return builder;
	}

}
