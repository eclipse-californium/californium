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
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.eclipse.californium.cluster.DtlsClusterManager.ClusterNodesDiscover;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsClusterConnectorConfig.Builder;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * K8s discover implementation.
 *
 * Uses k8s management API to list cluster-pods:
 * 
 * <ul>
 * <li>{@code "${KUBECTL_HOST}/api/v1/namespaces/default/pods"}</li>
 * <li>{@code "${KUBECTL_HOST}/api/v1/namespaces/${KUBECTL_NAMESPACE}/pods}"</li>
 * <li>{@code "${KUBECTL_HOST}/api/v1/namespaces/${KUBECTL_NAMESPACE}/pods?labelSelector=${KUBECTL_SELECTOR}"}</li>
 * </ul>
 * 
 * Excludes own pod (hostname) from {@link #getClusterNodesDiscoverScope()}.
 * 
 * Supported environment variables:
 * <dl>
 * <dt>KUBECTL_NODE_ID</dt>
 * <dd>node-id (number). Optional, if missing, extracted from the tail of the
 * hostname.</dd>
 * <dt>KUBECTL_HOST</dt>
 * <dd>k8s API host. e.g. "https://10.152.183.1"</dd>
 * <dt>KUBECTL_TOKEN</dt>
 * <dd>bearer token for k8s API.</dd>
 * <dt>KUBECTL_NAMESPACE</dt>
 * <dd>namespace to select cluster pods. Optional, default is "default".</dd>
 * <dt>KUBECTL_SELECTOR</dt>
 * <dd>selector expression. Optional, value e.g. "app%3Dcf-extserver"</dd>
 * <dt>KUBECTL_TRUSTSTORE</dt>
 * <dd>truststore definition. See
 * {@link SslContextUtil#loadTrustedCertificates(String)}. Optional, default
 * "trust all".</dd>
 * <dt>DTLS_CID_MGMT_IDENTITY</dt>
 * <dd>PSK identity for cluster management interface encryption</dd>
 * <dt>DTLS_CID_MGMT_SECRET_BASE64</dt>
 * <dd>PSK secret in base64 for cluster management interface encryption</dd>
 * </dl>
 * 
 * @since 2.5
 */
public abstract class K8sManagementDiscoverClient implements ClusterNodesDiscover {

	/**
	 * Logger.
	 */
	protected static final Logger LOGGER = LoggerFactory.getLogger(K8sManagementDiscoverClient.class);

	/**
	 * Connect timeout for k8s API in milliseconds.
	 */
	protected static final int CONNECT_TIMEOUT_MILLIS = 2000;
	/**
	 * Request timeout for k8s API in milliseconds.
	 */
	protected static final int REQUEST_TIMEOUT_MILLIS = 2000;
	/**
	 * External (exposed) ports for cluster internal management interfaces.
	 */
	private final int externalPort;
	/**
	 * Node-id of this {@link DTLSConnector}.
	 */
	private final int nodeId;
	/**
	 * Hostname.
	 */
	private final String hostName;
	/**
	 * k8s API host URL. e.g. "https://10.152.183.1".
	 */
	private final String hostUrl;
	/**
	 * Bearer token for k8s API.
	 */
	private final String token;
	/**
	 * k8s namespace of cid-cluster pods.
	 */
	private final String namespace;
	/**
	 * k8s selector for cid-cluster pods.
	 */
	private final String selector;
	/**
	 * http client ssl context.
	 */
	private final SSLContext sslContext;

	/**
	 * List of ip-addresses for k8s cid-cluster pods.
	 */
	private final List<String> discoverScope = new ArrayList<>();

	/**
	 * Create k8s discover client.
	 * 
	 * @param externalPort external/exposed port for cluster internal management
	 *            interfaces.
	 * @throws GeneralSecurityException if initializing ssl context fails
	 * @throws IOException if loading trust store fails
	 */
	public K8sManagementDiscoverClient(int externalPort) throws GeneralSecurityException, IOException {
		this.hostName = InetAddress.getLocalHost().getHostName();
		this.externalPort = externalPort;
		Integer node = null;
		String id = StringUtil.getConfiguration("KUBECTL_NODE_ID");
		if (id != null && !id.isEmpty()) {
			try {
				node = Integer.valueOf(id);
			} catch (NumberFormatException ex) {
				LOGGER.warn("KUBECTL_NODE_ID: {}", id, ex);
			}
		}
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
		this.hostUrl = StringUtil.getConfiguration("KUBECTL_HOST");
		this.token = StringUtil.getConfiguration("KUBECTL_TOKEN");
		this.namespace = StringUtil.getConfiguration("KUBECTL_NAMESPACE");
		this.selector = StringUtil.getConfiguration("KUBECTL_SELECTOR");
		String trustStore = StringUtil.getConfiguration("KUBECTL_TRUSTSTORE");
		Certificate[] trusts = null;
		if (trustStore != null && !trustStore.isEmpty()) {
			trusts = SslContextUtil.loadTrustedCertificates(trustStore);
		}
		LOGGER.info("Node-ID: {} - {}", nodeId, externalPort);
		LOGGER.info("{} / {} / {}", hostUrl, namespace, selector);
		int len = token.length();
		int end = len > 20 ? 10 : len / 2;
		LOGGER.info("bearer token {}... ({} bytes)", token.substring(0, end), len);
		KeyManager[] keyManager = SslContextUtil.createAnonymousKeyManager();
		TrustManager[] trustManager;
		if (trusts == null || trusts.length == 0) {
			trustManager = SslContextUtil.createTrustAllManager();
		} else {
			trustManager = SslContextUtil.createTrustManager("trusts", trusts);
		}
		sslContext = SSLContext.getInstance("TLSv1.3");
		sslContext.init(keyManager, trustManager, null);
	}

	/**
	 * Get node-id.
	 * 
	 * @return node-id
	 */
	public int getNodeID() {
		return nodeId;
	}

	/**
	 * Execute http GET request.
	 * 
	 * @param url url of get request
	 * @param token bearer token for authentication
	 * @param sslContext ssl context to verify API server.
	 * @return input stream with response, or {@code null}, if response code is
	 *         not OK.
	 * @throws IOException if an i/o error occurred.
	 * @throws GeneralSecurityException if an security error occurred.
	 */
	public abstract InputStream getPods(String url, String token, SSLContext sslContext)
			throws IOException, GeneralSecurityException;

	/**
	 * Get pods from k8s API.
	 * 
	 * Store result in {@link #discoverScope}.
	 * 
	 * @throws IOException if an i/o error occurs during the http GET
	 * @throws GeneralSecurityException if an security error occurs during the
	 *             http GET
	 */
	public void discoverPods() throws IOException, GeneralSecurityException {
		StringBuilder url = new StringBuilder(hostUrl);
		url.append("/api/v1/namespaces/");
		if (namespace != null) {
			url.append(namespace);
		} else {
			url.append("default");
		}
		url.append("/pods");
		if (selector != null) {
			url.append("?labelSelector=").append(selector);
		}

		InputStream inputStream = getPods(url.toString(), token, sslContext);
		if (inputStream != null) {
			try {
				// Get the response
				Reader reader = new InputStreamReader(inputStream);
				JsonElement element = JsonParser.parseReader(reader);

				Set<Pod> pods = new HashSet<>();

				if (LOGGER.isDebugEnabled()) {
					GsonBuilder builder = new GsonBuilder();
					builder.setPrettyPrinting();
					Gson gson = builder.create();
					LOGGER.debug("{}", gson.toJson(element));
				}
				JsonElement childElement = getChild(element, "items");
				if (childElement != null && childElement.isJsonArray()) {
					JsonArray jsonArray = childElement.getAsJsonArray();
					for (JsonElement item : jsonArray) {
						String name = null;
						String phase = null;
						String group = null;
						String address = null;
						Set<String> addresses = new HashSet<>();
						childElement = getChild(item, "metadata/name");
						if (childElement != null) {
							name = childElement.getAsString();
						}
						childElement = getChild(item, "metadata/labels/controller-revision-hash");
						if (childElement == null) {
							childElement = getChild(item, "metadata/labels/pod-template-hash");
							if (childElement == null) {
								childElement = getChild(item, "metadata/labels/deployment");
							}
						}
						if (childElement != null) {
							group = childElement.getAsString();
						}
						childElement = getChild(item, "status/phase");
						if (childElement != null) {
							phase = childElement.getAsString();
						}
						childElement = getChild(item, "status/podIP");
						if (childElement != null) {
							address = childElement.getAsString();
							addresses.add(address);
						}
						childElement = getChild(item, "status/podIPs");
						if (childElement != null && childElement.isJsonArray()) {
							JsonArray ipArray = childElement.getAsJsonArray();
							for (JsonElement ip : ipArray) {
								if (ip.isJsonObject()) {
									childElement = getChild(ip, "ip");
									if (childElement != null) {
										String multiAddress = childElement.getAsString();
										if (address == null) {
											address = multiAddress;
										}
										addresses.add(multiAddress);
									}
								}
							}
						}
						pods.add(new Pod(name, group, phase, address, addresses));
					}
				}

				for (Pod pod : pods) {
					if (pod.addresses.size() > 1) {
						LOGGER.info("{} ({}) => {}: {}", pod.name, pod.group, pod.phase, pod.addresses);
					} else {
						LOGGER.info("{} ({}) => {}: {}", pod.name, pod.group, pod.phase, pod.address);
					}
				}
				LOGGER.info("host: {}", hostName);
				synchronized (discoverScope) {
					discoverScope.clear();
					for (Pod pod : pods) {
						if (pod.address != null && !hostName.equals(pod.name)) {
							discoverScope.add(pod.address);
						}
					}
				}
			} finally {
				inputStream.close();
			}
		}
	}

	/**
	 * Get child element.
	 * 
	 * @param element base element
	 * @param path path to child
	 * @return child element, or {@code null}, if not available.
	 */
	private JsonElement getChild(JsonElement element, String path) {
		String[] pathItems = path.split("/");
		return getChild(element, pathItems, 0);
	}

	/**
	 * Get child element from sub-path.
	 * 
	 * @param element base element
	 * @param path path array
	 * @param pathIndex current index in path array.
	 * @return child element, or {@code null}, if not available.
	 */
	private JsonElement getChild(JsonElement element, String[] path, int pathIndex) {
		JsonElement current = null;
		String name = path[pathIndex];
		if (element.isJsonArray()) {
			JsonArray jsonArray = element.getAsJsonArray();
			int index = Integer.parseInt(name);
			current = jsonArray.get(index);
		} else if (element.isJsonObject()) {
			JsonObject jsonObject = element.getAsJsonObject();
			current = jsonObject.get(name);
		}
		if (current != null && pathIndex + 1 < path.length) {
			return getChild(current, path, pathIndex + 1);
		}
		return current;
	}

	/**
	 * k8s API information of pods.
	 */
	private static class Pod {

		/**
		 * Name of pod.
		 */
		private final String name;
		/**
		 * Group tag of pod. Either value of
		 * "metadata/labels/controller-revision-hash",
		 * "metadata/labels/pod-template-hash", or "metadata/labels/deployment".
		 */
		private final String group;
		/**
		 * Status phase of pod.
		 */
		private final String phase;
		/**
		 * ip-address of pod.
		 */
		private final String address;
		/**
		 * List of ip-addresses of pod.
		 */
		private final Set<String> addresses;

		/**
		 * Create pod information instance.
		 * 
		 * @param name pod name
		 * @param group pod group
		 * @param phase status phase
		 * @param address pod address
		 * @param addresses pod addresses
		 */
		private Pod(String name, String group, String phase, String address, Set<String> addresses) {
			this.name = name;
			this.group = group;
			this.phase = phase;
			this.address = address;
			this.addresses = addresses;
		}
	}

	@Override
	public List<InetSocketAddress> getClusterNodesDiscoverScope() {
		List<InetSocketAddress> scope = new ArrayList<>();
		try {
			discoverPods();
			synchronized (discoverScope) {
				for (String address : discoverScope) {
					scope.add(new InetSocketAddress(address, externalPort));
				}
			}
		} catch (IOException e) {
			LOGGER.error("error: ", e);
		} catch (GeneralSecurityException e) {
			LOGGER.error("error: ", e);
		}
		return scope;
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
		String identity = StringUtil.getConfiguration("DTLS_CID_MGMT_IDENTITY");
		String secret = StringUtil.getConfiguration("DTLS_CID_MGMT_SECRET_BASE64");
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
