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
 *                    derived from RestoreHttpClient
 ******************************************************************************/
package org.eclipse.californium.cluster;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;

import org.eclipse.californium.cluster.K8sManagementClient.Pod;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The k8s restore http-client.
 * 
 * In order to prevent from accidentally reverse restore by a restart of the
 * double during the update, the doubles must marked with the labels
 * {@code restore=true} ahead the update. The restore is only executed, if the
 * double has that label and the new pod not. Though the new pods are not
 * labeled with that, a restarting double (failover) will not execute a reverse
 * restore.
 * 
 * @since 3.4 (was RestoreHttpClient)
 */
public class K8sRestoreJdkHttpClient extends RestoreJdkHttpClient {

	private static final Logger LOGGER = LoggerFactory.getLogger(K8sRestoreJdkHttpClient.class);

	/**
	 * Hostname pattern.
	 * 
	 * Matches {@code <name>-(a|b)-<n>}.
	 */
	private static final Pattern HOSTNAME_PATTERN = Pattern.compile("^(.*-)([ab])(-\\d+)$");

	private static final String KUBECTL_RESTORE_SELECTOR_LABEL = "KUBECTL_RESTORE_SELECTOR_LABEL";
	private static final String DEFAULT_RESTORE_SELECTOR_LABEL = "app";

	private final Random rand = new Random();

	/**
	 * Get information of corresponding pod in other statefulset.
	 * 
	 * Check, if hostname matches {@code "<name>-(a|b)-<id>} and exchange
	 * {@code a}/{@code b}. Request information of other pod from k8s API.
	 * 
	 * @param k8sClient k8s client for k8s API.
	 * @return information of corresponding pod in other statefulset, or
	 *         {@code null}, if not available.
	 * @since 3.4
	 */
	public Pod getClusterPodToRestore(K8sManagementClient k8sClient) {
		String hostName = k8sClient.getHostName();
		Matcher matcher = HOSTNAME_PATTERN.matcher(hostName);
		if (matcher.matches()) {
			String head = matcher.group(1);
			String update = matcher.group(2);
			String node = matcher.group(3);
			if (update.equals("a")) {
				update = "b";
			} else if (update.equals("b")) {
				update = "a";
			}
			String restore = head + update + node;
			LOGGER.info("k8s: check to restore {} from {}", hostName, restore);
			return getPodToRestore(k8sClient, "/" + restore);
		} else {
			LOGGER.info("k8s: {} doesn't match name-pattern!", hostName);
		}
		return null;
	}

	/**
	 * Get information of corresponding pod in other deployment.
	 * 
	 * Select pods using {@link #KUBECTL_RESTORE_SELECTOR_LABEL}, with
	 * {@link #DEFAULT_RESTORE_SELECTOR_LABEL} as default.
	 * 
	 * @param k8sClient k8s client for k8s API.
	 * @return information of corresponding pod in other deployment, or
	 *         {@code null}, if not available.
	 * @since 3.4
	 */
	public Pod getSinglePodToRestore(K8sManagementClient k8sClient) {
		String hostName = k8sClient.getHostName();
		String label = StringUtil.getConfiguration(KUBECTL_RESTORE_SELECTOR_LABEL);
		if (label == null || label.isEmpty()) {
			label = DEFAULT_RESTORE_SELECTOR_LABEL;
		}
		String selector = k8sClient.getLabelSelector(label);
		if (selector != null) {
			LOGGER.info("k8s: check to restore {} from other pod", hostName);
			selector = "?labelSelector=" + selector;
			return getPodToRestore(k8sClient, selector);
		} else {
			LOGGER.warn("k8s: failed to restore {} from other pod, missing selector!", hostName);
			return null;
		}
	}

	/**
	 * Get pod to restore.
	 * 
	 * In order to prevent from accidentally reverse restore by a restart of the
	 * double during the update, the doubles must marked with the labels
	 * {@code restore=true} ahead the update. The restore is only executed, if
	 * the double has that label. Though the new pods are not labeled with that,
	 * a restarting double (failover) will not execute a reverse restore.
	 * 
	 * @param k8sClient k8s client for k8s API.
	 * @param append specifier for other pod
	 * @return other pod, or {@code null}, if this pod is already marked with
	 *         the label {@code restore=true}, or the double is not marked with
	 *         that.
	 * @since 3.4
	 */
	private Pod getPodToRestore(K8sManagementClient k8sClient, String append) {
		String hostName = k8sClient.getHostName();
		if ("true".equalsIgnoreCase(k8sClient.getLabel("restore"))) {
			// restart during pending restore
			LOGGER.info("k8s: pod {} has been restarted while downloading!", hostName);
			return null;
		}
		boolean retry = true;
		int retries;
		for (retries = 0; retry && retries < 3; ++retries) {
			try {
				Set<Pod> found = new HashSet<>();
				Set<Pod> pods = k8sClient.getPods(append);
				for (Pod pod : pods) {
					if (pod.address != null && !hostName.equals(pod.name)) {
						if ("true".equalsIgnoreCase(pod.getLabel("restore"))) {
							found.add(pod);
						} else {
							LOGGER.info("k8s: pod {} is not ready for restore!", pod.name);
						}
					}
				}
				if (found.size() == 1) {
					return found.iterator().next();
				}
			} catch (HttpResultException e) {
				if (e.getResponseCode() == 503) {
					LOGGER.info("k8s: {} failed: {}", hostName, e.getMessage());
				} else if (e.getResponseCode() == 404) {
					LOGGER.info("k8s: {} failed: {}", hostName, e.getMessage());
					return null;
				} else {
					LOGGER.error("k8s-http: {} failed:", hostName, e);
				}
			} catch (IOException e) {
				LOGGER.warn("k8s: {} failed to read:", hostName, e);
			} catch (GeneralSecurityException e) {
				// not ready!
				LOGGER.warn("k8s: {} failed:", hostName, e);
			}
			try {
				Thread.sleep(200 + rand.nextInt(200));
			} catch (InterruptedException e) {
			}
		}
		LOGGER.warn("k8s: loading pod info {} failed after {} retries!", hostName, retries);
		return null;
	}

	/**
	 * Restore servers from their k8s green/blue double.
	 * 
	 * For cid cluster, a statefulset is used and the pod name of the double is
	 * build using the hostname exchanging {@code a}/{@code b}, if the hostname
	 * matches the {@link #HOSTNAME_PATTERN}.
	 * 
	 * <b>Note:</b> though the hostname verification of the x509 certificate is
	 * not used, be careful and just use private trust-anchors in the related
	 * trust-store.
	 * 
	 * @param k8sClient k8s client to call the k8s management API (get pod).
	 * @param port port number of https service to restore the servers.
	 * @param sslContext ssl context for k8s management API
	 * @param servers servers to be restored.
	 * @return number of loaded connections.
	 * @since 3.4
	 */
	public int restoreCluster(K8sManagementClient k8sClient, int port, SSLContext sslContext, CoapServer... servers) {
		String hostName = k8sClient.getHostName();
		if (hostName == null) {
			LOGGER.warn("hostname missing!");
		}
		Pod pod = getClusterPodToRestore(k8sClient);
		return restore(hostName, pod == null ? null : pod.address, port, sslContext, servers);
	}

	/**
	 * Restore servers from their k8s green/blue double.
	 * 
	 * For non cluster, the pod of the double is selected via the
	 * {@link #KUBECTL_RESTORE_SELECTOR_LABEL}.
	 * 
	 * <b>Note:</b> though the hostname verification of the x509 certificate is
	 * not used, be careful and just use private trust-anchors in the related
	 * trust-store.
	 * 
	 * @param k8sClient k8s client to call the k8s management API (get pod).
	 * @param port port number of https service to restore the servers.
	 * @param sslContext ssl context for k8s management API
	 * @param servers servers to be restored.
	 * @return number of loaded connections.
	 * @since 3.4
	 */
	public int restoreSingle(K8sManagementClient k8sClient, int port, SSLContext sslContext, CoapServer... servers) {
		String hostName = k8sClient.getHostName();
		if (hostName == null) {
			LOGGER.warn("hostname missing!");
		}
		Pod pod = getSinglePodToRestore(k8sClient);
		return restore(hostName, pod == null ? null : pod.address, port, sslContext, servers);
	}
}
