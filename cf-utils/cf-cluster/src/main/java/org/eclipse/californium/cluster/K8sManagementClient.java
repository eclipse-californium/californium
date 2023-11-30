/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.net.ssl.SSLContext;

import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * K8s management API implementation.
 *
 * Uses k8s management API to list or read cluster-pods:
 * 
 * <ul>
 * <li>{@code "${KUBECTL_HOST}/api/v1/namespaces/default/pods"}</li>
 * <li>{@code "${KUBECTL_HOST}/api/v1/namespaces/${KUBECTL_NAMESPACE}/pods}"</li>
 * <li>{@code "${KUBECTL_HOST}/api/v1/namespaces/${KUBECTL_NAMESPACE}/pods?labelSelector=${KUBECTL_SELECTOR}"}</li>
 * <li>{@code "${KUBECTL_HOST}/api/v1/namespaces/${KUBECTL_NAMESPACE}/pods/name}"</li>
 * </ul>
 * 
 * Supported environment variables:
 * <dl>
 * <dt>KUBECTL_NODE_ID</dt>
 * <dd>node-id (number). Optional, if missing, extracted from the tail of the
 * hostname.</dd>
 * <dt>KUBECTL_HOST</dt>
 * <dd>k8s API host. e.g. "https://10.152.183.1". Optional, if missing or empty,
 * "kubernetes.default.svc" is used.</dd>
 * <dt>KUBECTL_TOKEN</dt>
 * <dd>bearer token for k8s API. Optional, if empty, the content of
 * "/var/run/secrets/kubernetes.io/serviceaccount/token" is used.</dd>
 * <dt>KUBECTL_NAMESPACE</dt>
 * <dd>namespace to select cluster pods. Optional, if missing or empty, the
 * content of "/var/run/secrets/kubernetes.io/serviceaccount/namespace" is
 * used".</dd>
 * </dl>
 * 
 * @see <a href=
 *      "https://kubernetes.io/docs/tasks/run-application/access-api-from-pod/"
 *      target="_blank">kubernetes.io - Accessing the Kubernetes API from a
 *      Pod</a>
 * 
 * @since 3.0 (extracted from {@link K8sDiscoverClient}.
 */
public abstract class K8sManagementClient {

	/**
	 * Default hostname for pods accessing the kubectl API.
	 */
	private static final String KUBECTL_DEFAULT_HOST = "kubernetes.default.svc";
	/**
	 * Default service-account for pods accessing the kubectl API.
	 */
	private static final File KUBECTL_DEFAULT_SERVICE_ACCOUNT = new File(
			"/var/run/secrets/kubernetes.io/serviceaccount");
	/**
	 * Default token for pods accessing the kubectl API.
	 */
	private static final File KUBECTL_DEFAULT_TOKEN_FILE = new File(KUBECTL_DEFAULT_SERVICE_ACCOUNT, "token");
	/**
	 * Default namespace for pods accessing the kubectl API.
	 */
	private static final File KUBECTL_DEFAULT_NAMESPACE = new File(KUBECTL_DEFAULT_SERVICE_ACCOUNT, "namespace");
	/**
	 * Default CA cert for pods accessing the kubectl API.
	 */
	private static final File KUBECTL_DEFAULT_CA_CERT_FILE = new File(KUBECTL_DEFAULT_SERVICE_ACCOUNT, "ca.crt");

	private static final String K8S_API_VERSION = "v1";
	private static final String KUBECTL_HOST = "KUBECTL_HOST";
	private static final String KUBECTL_TOKEN = "KUBECTL_TOKEN";
	private static final String KUBECTL_NAMESPACE = "KUBECTL_NAMESPACE";

	/**
	 * The logger.
	 * 
	 * @deprecated scope will change to private.
	 */
	@Deprecated
	protected static final Logger LOGGER = LoggerFactory.getLogger(K8sManagementClient.class);
	/**
	 * Hostname.
	 */
	protected final String hostName;
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
	 * http client ssl context.
	 */
	private final SSLContext sslContext;
	/**
	 * Own pod.
	 * 
	 * @since 3.4
	 */
	private final Pod pod;

	/**
	 * Create k8s management client.
	 * 
	 * @throws GeneralSecurityException if initializing ssl context fails
	 * @throws IOException if loading trust store fails
	 */
	public K8sManagementClient() throws GeneralSecurityException, IOException {
		this.hostName = InetAddress.getLocalHost().getHostName();
		String kubectlHost = StringUtil.getConfiguration(KUBECTL_HOST);
		if (kubectlHost == null || kubectlHost.isEmpty()) {
			kubectlHost = KUBECTL_DEFAULT_HOST;
		}
		String namespace = StringUtil.getConfiguration(KUBECTL_NAMESPACE);
		if (namespace == null || namespace.isEmpty()) {
			namespace = StringUtil.readFile(KUBECTL_DEFAULT_NAMESPACE, namespace);
		}
		this.namespace = namespace;
		this.hostUrl = "https://" + kubectlHost;
		String token = StringUtil.getConfiguration(KUBECTL_TOKEN);
		if (token != null && token.isEmpty()) {
			// replace "empty" token by default.
			// but keep null, if no token is provided
			token = StringUtil.readFile(KUBECTL_DEFAULT_TOKEN_FILE, token);
		}
		this.token = token;
		LOGGER.info("Host: {}, namespace: {}", hostUrl, namespace);
		if (token != null && !token.isEmpty()) {
			int len = token.length();
			int end = len > 20 ? 10 : len / 2;
			LOGGER.info("bearer token {}... ({} bytes)", token.substring(0, end), len);
		} else {
			LOGGER.info("no bearer token!");
		}
		sslContext = CredentialsUtil.getK8sHttpsClientContext(KUBECTL_DEFAULT_CA_CERT_FILE);
		pod = getOwnPod();
	}

	/**
	 * Get hostname.
	 * 
	 * @return hostname
	 */
	public String getHostName() {
		return hostName;
	}

	/**
	 * Get value of k8s label of own pod.
	 * 
	 * @param label name of label, e.g. "app"
	 * @return value of k8s label. {@code null}, if not available.
	 * @since 3.4
	 */
	public String getLabel(String label) {
		return Pod.getLabel(pod, label);
	}

	/**
	 * Get selector with k8s label and current label value of own pod.
	 * 
	 * @param label name of label, e.g. "app"
	 * @return selector with k8s label and current label value.
	 *         {@code label%3Dvalue}. {@code null}, if not available
	 * @since 3.4
	 */
	public String getLabelSelector(String label) {
		String value = Pod.getLabel(pod, label);
		if (value != null) {
			return label + "%3D" + value;
		}
		return null;
	}

	/**
	 * Get k8s management URL.
	 * 
	 * @return {@code "${KUBECTL_HOST}/api/v1/namespaces/${KUBECTL_NAMESPACE}}
	 */
	public String getK8sManagementUrl() {
		StringBuilder url = new StringBuilder(hostUrl);
		url.append("/api/v1/namespaces/");
		if (namespace != null) {
			url.append(namespace);
		} else {
			url.append("default");
		}
		return url.toString();
	}

	/**
	 * Get pods from k8s API.
	 * 
	 * @param append text to append to the {@link #getK8sManagementUrl()}, or
	 *            {@code null}. Used to specify a specific pod or a selector for
	 *            a group.
	 * @return set of pods. May be empty, if no matching pod is found.
	 * @throws IOException if an i/o error occurs during the http GET
	 * @throws GeneralSecurityException if an security error occurs during the
	 *             http GET
	 * @throws HttpResultException if the http result is not as expected
	 */
	public Set<Pod> getPods(String append) throws IOException, GeneralSecurityException, HttpResultException {
		String url = getK8sManagementUrl() + "/pods";
		if (append != null && !append.isEmpty()) {
			url += append;
		}
		Set<Pod> pods = new HashSet<>();
		HttpResult result = executeHttpRequest(url, token, sslContext);
		try {
			InputStream content = result.getContent();
			if (content != null) {
				// Get the response
				Reader reader = new InputStreamReader(content);
				if (result.getResponseCode() != HttpURLConnection.HTTP_OK) {
					if (LOGGER.isInfoEnabled()) {
						JsonElement element = JsonParser.parseReader(reader);
						GsonBuilder builder = new GsonBuilder();
						builder.setPrettyPrinting();
						Gson gson = builder.create();
						LOGGER.info("{}", gson.toJson(element));
					}
					throw new HttpResultException(url, result);
				}
				JsonElement element = JsonParser.parseReader(reader);
				if (LOGGER.isDebugEnabled()) {
					GsonBuilder builder = new GsonBuilder();
					builder.setPrettyPrinting();
					Gson gson = builder.create();
					LOGGER.trace("{}", gson.toJson(element));
				}
				String apiVersion = getApiVersion(element);
				if (apiVersion == null) {
					LOGGER.warn("API version unknown!");
				} else if (!K8S_API_VERSION.equals(apiVersion)) {
					LOGGER.warn("API version {} not support! Requires {}.", apiVersion, K8S_API_VERSION);
				}

				JsonElement childElement = getChild(element, "kind");
				if (childElement != null) {
					String kind = childElement.getAsString();
					if (kind.equalsIgnoreCase("Pod")) {
						Pod pod = getPod(element);
						if (pod != null) {
							pods.add(pod);
						}
					} else if (kind.equalsIgnoreCase("PodList")) {
						childElement = getChild(element, "items");
						if (childElement != null && childElement.isJsonArray()) {
							JsonArray jsonArray = childElement.getAsJsonArray();
							for (JsonElement item : jsonArray) {
								Pod pod = getPod(item);
								if (pod != null) {
									pods.add(pod);
								}
							}
						}
					}
				}

				for (Pod pod : pods) {
					LOGGER.debug("{}", pod);
				}
				LOGGER.debug("host: {}", hostName);
			} else {
				throw new HttpResultException(url, result);
			}
		} finally {
			result.close();
		}

		return pods;
	}

	/**
	 * Execute http GET request.
	 * 
	 * Note: this is called during initialization of the class instance.
	 * 
	 * @param url url of get request
	 * @param token bearer token for authentication
	 * @param sslContext ssl context to verify API server.
	 * @return http result.
	 * @throws IOException if an i/o error occurred.
	 * @throws GeneralSecurityException if an security error occurred.
	 */
	public abstract HttpResult executeHttpRequest(String url, String token, SSLContext sslContext)
			throws IOException, GeneralSecurityException;

	/**
	 * Get information about own pod from k8s API.
	 * 
	 * @return own pod, {@code null}, if not available.
	 * @since 3.4
	 */
	private Pod getOwnPod() {
		try {
			Set<Pod> pods = getPods("/" + hostName);
			if (!pods.isEmpty()) {
				Pod pod = pods.iterator().next();
				LOGGER.info("own pod: {}", pod);
				return pod;
			}
			LOGGER.info("missing own pod! {}", hostName);
		} catch (HttpResultException e) {
			LOGGER.error("http: ", e);
		} catch (IOException e) {
			LOGGER.error("io error: ", e);
		} catch (GeneralSecurityException e) {
			LOGGER.error("security error: ", e);
		}
		return null;
	}

	/**
	 * Get api version from json.
	 * 
	 * @param item json item
	 * @return api version, or {@code null}, if not available.
	 */
	private String getApiVersion(JsonElement item) {
		JsonElement childElement = getChild(item, "apiVersion");
		if (childElement != null) {
			return childElement.getAsString();
		}
		return null;
	}

	/**
	 * Get Pod from json.
	 * 
	 * @param item json item
	 * @return Pod
	 */
	private Pod getPod(JsonElement item) {
		String name = null;
		Map<String, String> labels = null;
		String phase = null;
		boolean ready = false;
		String group = null;
		String address = null;
		Set<String> addresses = new HashSet<>();
		JsonElement childElement = getChild(item, "metadata/name");
		if (childElement != null) {
			name = childElement.getAsString();
		}
		childElement = getChild(item, "metadata/labels");
		if (childElement != null && childElement.isJsonObject()) {
			JsonObject labelsElement = childElement.getAsJsonObject();
			Set<Entry<String, JsonElement>> set = labelsElement.entrySet();
			labels = new HashMap<>(set.size());
			for (Entry<String, JsonElement> label : set) {
				labels.put(label.getKey(), label.getValue().getAsString());
			}
			group = labels.get("controller-revision-hash");
			if (group == null) {
				group = labels.get("pod-template-hash");
			}
			if (group == null) {
				group = labels.get("deployment");
			}
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
		childElement = getChild(item, "status/conditions");
		if (childElement != null && childElement.isJsonArray()) {
			JsonArray conditions = childElement.getAsJsonArray();
			for (JsonElement condition : conditions) {
				if (condition.isJsonObject()) {
					JsonElement typeElement = getChild(condition, "type");
					JsonElement statusElement = getChild(condition, "status");
					if (typeElement != null && statusElement != null) {
						if (typeElement.getAsString().equalsIgnoreCase("Ready")) {
							ready = statusElement.getAsString().equalsIgnoreCase("True");
						}
					}
				}
			}
		}
		return new Pod(name, labels, group, phase, ready, address, addresses);
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
	public static class Pod {

		/**
		 * Name of pod.
		 */
		public final String name;
		/**
		 * Labels of pods.
		 */
		public final Map<String, String> labels;
		/**
		 * Group tag of pod. Either value of
		 * "metadata/labels/controller-revision-hash",
		 * "metadata/labels/pod-template-hash", or "metadata/labels/deployment".
		 */
		public final String group;
		/**
		 * Status phase of pod.
		 */
		public final String phase;
		/**
		 * Ready status of pod.
		 */
		public final boolean ready;
		/**
		 * ip-address of pod.
		 */
		public final String address;
		/**
		 * List of ip-addresses of pod.
		 */
		public final Set<String> addresses;

		/**
		 * Create pod information instance.
		 * 
		 * @param name pod name
		 * @param labels pod labels
		 * @param group pod group
		 * @param phase status phase
		 * @param ready pod ready
		 * @param address pod address
		 * @param addresses pod addresses
		 */
		private Pod(String name, Map<String, String> labels, String group, String phase, boolean ready, String address,
				Set<String> addresses) {
			this.name = name;
			this.labels = labels;
			this.group = group;
			this.phase = phase;
			this.ready = ready;
			this.address = address;
			this.addresses = addresses;
		}

		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder("pod: ");
			builder.append(name).append(", group: ").append(group).append(", phase: ").append(phase);
			builder.append(ready ? " - ready" : " - not ready");
			if (addresses.size() > 1) {
				builder.append(StringUtil.lineSeparator());
				builder.append("   ip: ");
				for (String maddress : addresses) {
					builder.append(maddress).append(",");
				}
				builder.setLength(builder.length() - 1);
			} else {
				builder.append(", ip: ").append(address);
			}
			return builder.toString();
		}

		/**
		 * Get value of k8s label of this pod.
		 * 
		 * @param label name of label, e.g. "app"
		 * @return value of k8s label. {@code null}, if not available.
		 * @since 3.4
		 */
		public String getLabel(String label) {
			if (labels != null) {
				String value = labels.get(label);
				if (value != null && !value.isEmpty()) {
					return value;
				}
			}
			return null;
		}

		/**
		 * Get value of k8s label.
		 * 
		 * @param pod pod to get the label's value
		 * @param label name of label, e.g. "app"
		 * @return value of k8s label. {@code null}, if not available.
		 * @since 3.4
		 */
		public static String getLabel(Pod pod, String label) {
			if (pod != null) {
				return pod.getLabel(label);
			}
			return null;
		}
	}
}
