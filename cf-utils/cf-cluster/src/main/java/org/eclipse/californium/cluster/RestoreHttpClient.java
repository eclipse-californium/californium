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

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;

import org.eclipse.californium.cluster.K8sManagementClient.Pod;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.server.ServersSerializationUtil;
import org.eclipse.californium.elements.util.ClockUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The restore http-client.
 * 
 * @since 3.0
 */
public class RestoreHttpClient implements Readiness {

	private static final Logger LOGGER = LoggerFactory.getLogger(RestoreHttpClient.class);

	/**
	 * Hostname pattern.
	 * 
	 * Matches {@code <name>-(a|b)-<n>}.
	 */
	private static final Pattern HOSTNAME_PATTERN = Pattern.compile("^(.*-)([ab])(-\\d+)$");

	private final Random rand = new Random();
	private String hostName;
	private volatile boolean ready;

	@Override
	public boolean isReady() {
		return ready;
	}

	/**
	 * Get information of corresponding pod in other statefulset.
	 * 
	 * Check, if hostname matches {@code "<name>-(a|b)-<id>} and exchange
	 * {@code a}/{@code b}. Request information of other pod from k8s API.
	 * 
	 * @param k8sClient k8s client for k8s API.
	 * @return information of corresponding pod in other statefulset, or
	 *         {@code null}, if not available.
	 */
	public Pod getPodToRestore(K8sManagementClient k8sClient) {
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
			boolean retry = true;
			int retries;
			for (retries = 0; retry && retries < 3; ++retries) {
				try {
					Set<Pod> pods = k8sClient.getPods("/" + restore);
					for (Pod pod : pods) {
						if (pod.address != null) {
							if ("true".equalsIgnoreCase(pod.labels.get("restore"))) {
								return pod;
							} else {
								LOGGER.info("k8s: pod {} is not ready for restore!", pod.name);
							}
						}
					}
				} catch (HttpResultException e) {
					if (e.getResponseCode() == 503) {
						LOGGER.info("k8s: {} failed: {}", restore, e.getMessage());
					} else if (e.getResponseCode() == 404) {
						LOGGER.info("k8s: {} failed: {}", restore, e.getMessage());
						return null;
					} else {
						LOGGER.error("k8s-http: {} failed:", restore, e);
					}
				} catch (IOException e) {
					LOGGER.warn("k8s: {} failed to read:", restore, e);
				} catch (GeneralSecurityException e) {
					// not ready!
					LOGGER.warn("k8s: {} failed:", restore, e);
				}
				try {
					Thread.sleep(200 + rand.nextInt(200));
				} catch (InterruptedException e) {
				}
			}
			LOGGER.warn("k8s: loading pod info {} failed after {} retries!", restore, retries);
		} else {
			LOGGER.info("k8s: {} doesn't match name-pattern!", hostName);
		}
		return null;
	}

	/**
	 * Download the state to restore from the pod of the other statefulset.
	 * 
	 * <b>Note:</b> though the hostname verification of the x509 certificate is
	 * not used, be careful and just use private trust-anchors in the related
	 * trust-store.
	 * 
	 * @param restore pod to download the state
	 * @param port port number of the download service on that pod
	 * @param sslContext ssl context to download the state
	 * @return input stream, or {@code null}, if not available.
	 */
	public InputStream downloadRestore(Pod restore, int port, SSLContext sslContext) {
		String scheme = sslContext != null ? "https" : "http";
		LOGGER.info("download: restore {} from {}/{} using {}", hostName, restore.name, restore.address, scheme);
		for (int retries = 0; retries < 3; ++retries) {
			try {
				JdkHttpClient client = new JdkHttpClient();
				HttpResult result = client.get(scheme + "://" + restore.address + ":" + port + "/restore", null, false,
						sslContext);
				LOGGER.info("download: {} from {}/{}: {} - {}", scheme, restore.name, restore.address,
						result.getResponseCode(), result.getResponseMessage());
				if (sslContext != null) {
					Principal peerPrincipal = result.getPeerPrincipal();
					LOGGER.info("download: https-peer {}", peerPrincipal);
				}
				if (result.getResponseCode() != 503) {
					return result.getContent();
				}
			} catch (IOException e) {
				LOGGER.warn("download: {} from {}/{} failed:", scheme, restore.name, restore.address, e);
			} catch (GeneralSecurityException e) {
				// not ready!
				LOGGER.warn("download: {} from {}/{} failed:", scheme, restore.name, restore.address, e);
				return null;
			}
		}
		return null;
	}

	/**
	 * Restore servers from their k8s green/blue double.
	 * 
	 * The pod name of the double is build using the hostname exchanging
	 * {@code a}/{@code b}, if the hostname matches the
	 * {@link #HOSTNAME_PATTERN}. In order to prevent from accidentally reverse
	 * restore by a restart of the double during the update, the doubles must
	 * marked with the labels {@code restore=true} ahead the update. The restore
	 * is only executed, if the double has that label. Though the new pods are
	 * not labeled with that, a restarting double (failover) will not execute a
	 * reverse restore.
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
	 */
	public int restore(K8sManagementClient k8sClient, int port, SSLContext sslContext, CoapServer... servers) {
		int count = 0;
		hostName = k8sClient.getHostName();
		if (hostName == null) {
			LOGGER.warn("hostname missing!");
		}
		Pod restore = getPodToRestore(k8sClient);
		if (restore != null) {
			long time = ClockUtil.nanoRealtime();
			InputStream in = downloadRestore(restore, port, sslContext);
			if (in != null) {
				try {
					count = ServersSerializationUtil.loadServers(in, servers);
					time = ClockUtil.nanoRealtime() - time;
					LOGGER.info("restored {} connections from {}/{} in {} ms", count, restore.name, restore.address,
							TimeUnit.NANOSECONDS.toMillis(time));
				} catch (IllegalArgumentException e) {
					LOGGER.warn("restore from {}/{} failed:", restore.name, restore.address, e);
				}
			}
		} else {
			LOGGER.info("{} no pod to restore!", hostName);
		}
		ready = true;
		return count;
	}
}
