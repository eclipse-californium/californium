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
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.Principal;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The jdk http-client.
 * 
 * @since 3.0
 */
public class JdkHttpClient {

	private static final Logger LOGGER = LoggerFactory.getLogger(JdkHttpClient.class);

	/**
	 * Connect timeout for k8s API in milliseconds.
	 */
	public static final int CONNECT_TIMEOUT_MILLIS = 5000;
	/**
	 * Request timeout for k8s API in milliseconds.
	 */
	public static final int REQUEST_TIMEOUT_MILLIS = 10000;

	/**
	 * Execute http GET request.
	 * 
	 * @param url url for GET
	 * @param token optional bearer token
	 * @param sslContext ssl context for https
	 * @return http result.
	 * @throws IOException if an i/o error occurred
	 * @throws GeneralSecurityException if an encryption error occurred
	 */
	public HttpResult get(String url, String token, SSLContext sslContext)
			throws IOException, GeneralSecurityException {

		try {
			URL get = new URL(url);
			HttpURLConnection con = (HttpURLConnection) get.openConnection();
			if (sslContext != null && con instanceof HttpsURLConnection) {
				((HttpsURLConnection) con).setSSLSocketFactory(sslContext.getSocketFactory());
			}
			if (token != null && !token.isEmpty()) {
				con.setRequestProperty("Authorization", "Bearer " + token);
			}
			con.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
			con.setReadTimeout(REQUEST_TIMEOUT_MILLIS);
			int responseCode = con.getResponseCode();
			String responseMessage = con.getResponseMessage();
			Principal peerPrincipal = null;
			if (sslContext != null && con instanceof HttpsURLConnection) {
				peerPrincipal = ((HttpsURLConnection) con).getPeerPrincipal();
			}
			LOGGER.info("Sending 'GET' request to URL : {}", url);
			LOGGER.info("Response Code : {} - {}", responseCode, responseMessage);
			if (responseCode == HttpURLConnection.HTTP_OK) {
				return new HttpResult(responseCode, responseMessage, peerPrincipal, con.getInputStream());
			} else {
				return new HttpResult(responseCode, responseMessage, peerPrincipal, null);
			}
		} catch (RuntimeException ex) {
			LOGGER.info("Sending 'GET' request to URL : {} failed!", url, ex);
			return new HttpResult(0, ex.getMessage(), null, null);
		}
	}

}
