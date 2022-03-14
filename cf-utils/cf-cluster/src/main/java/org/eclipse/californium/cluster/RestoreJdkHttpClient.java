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
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.PersistentComponentUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The restore http-client.
 * 
 * If used with {@link JdkMonitorService}, add this client as component with
 * {@link JdkMonitorService#addComponent(Readiness)} before
 * {@link JdkMonitorService#start()}.
 * 
 * @since 3.4 (parts of RestoreHttpClient)
 */
public class RestoreJdkHttpClient implements Readiness {

	private static final Logger LOGGER = LoggerFactory.getLogger(RestoreJdkHttpClient.class);

	/**
	 * Request timeout for download API in milliseconds.
	 */
	private static final int REQUEST_TIMEOUT_MILLIS = 15000;

	private volatile boolean ready;

	@Override
	public boolean isReady() {
		return ready;
	}

	/**
	 * Download the state to restore from other host.
	 * 
	 * <b>Note:</b> though the hostname verification of the x509 certificate is
	 * not used, be careful and just use private trust-anchors in the related
	 * trust-store.
	 * 
	 * @param hostName own hostname
	 * @param restoreHostName hostname to download the state
	 * @param port port number of the download service on that pod
	 * @param sslContext ssl context to download the state
	 * @return input stream, or {@code null}, if not available.
	 * @since 3.4 (added parameter hostName and restoreHostName)
	 */
	public InputStream downloadRestore(String hostName, String restoreHostName, int port, SSLContext sslContext) {
		String scheme = sslContext != null ? "https" : "http";
		LOGGER.info("download: restore {} from {}:{} using {}", hostName, restoreHostName, port, scheme);
		for (int retries = 0; retries < 3; ++retries) {
			try {
				JdkHttpClient client = new JdkHttpClient();
				HttpResult result = client.get(scheme + "://" + restoreHostName + ":" + port + "/restore",
						REQUEST_TIMEOUT_MILLIS, null, false, sslContext);
				LOGGER.info("download: {} from {}: {} - {}", scheme, restoreHostName, result.getResponseCode(),
						result.getResponseMessage());
				if (sslContext != null) {
					Principal peerPrincipal = result.getPeerPrincipal();
					LOGGER.info("download: https-peer {}", peerPrincipal);
				}
				if (result.getResponseCode() != 503) {
					return result.getContent();
				}
			} catch (IOException e) {
				LOGGER.warn("download: {} from {} failed:", scheme, restoreHostName, e);
			} catch (GeneralSecurityException e) {
				// not ready!
				LOGGER.warn("download: {} from {} failed:", scheme, restoreHostName, e);
				return null;
			}
		}
		return null;
	}

	/**
	 * Restore servers from their green/blue double.
	 * 
	 * <b>Note:</b> though the hostname verification of the x509 certificate is
	 * not used for the download, be careful and just use private trust-anchors
	 * in the related trust-store.
	 * 
	 * @param hostName own hostname
	 * @param restoreHostName hostname to download the state
	 * @param port port number of https service to restore the servers.
	 * @param sslContext ssl context for k8s management API
	 * @param servers servers to be restored.
	 * @return number of loaded connections.
	 * @since 3.4
	 */
	public int restore(String hostName, String restoreHostName, int port, SSLContext sslContext,
			CoapServer... servers) {
		int count = 0;
		if (restoreHostName != null) {
			long time = ClockUtil.nanoRealtime();
			InputStream in = downloadRestore(hostName, restoreHostName, port, sslContext);
			if (in != null) {
				PersistentComponentUtil util = new PersistentComponentUtil();
				for (CoapServer server : servers) {
					util.addProvider(server);
				}
				try {
					count = util.loadComponents(in);
					time = ClockUtil.nanoRealtime() - time;
					LOGGER.info("restored {} connections from {} in {} ms", count, restoreHostName,
							TimeUnit.NANOSECONDS.toMillis(time));
				} catch (IllegalArgumentException e) {
					LOGGER.warn("restore from {} failed:", restoreHostName, e);
				}
			}
		} else {
			LOGGER.info("{} no pod to restore!", hostName);
		}
		ready = true;
		return count;
	}

}
