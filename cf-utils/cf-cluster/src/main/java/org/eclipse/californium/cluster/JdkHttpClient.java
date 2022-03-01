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

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.Principal;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.util.Asn1DerDecoder;
import org.eclipse.californium.elements.util.Bytes;
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
	 * @param verifyHostname {@code true} to verify principal of server
	 *            certificate for weak hostname verification
	 * @param sslContext ssl context for https
	 * @return http result.
	 * @throws IOException if an i/o error occurred
	 * @throws GeneralSecurityException if an encryption error occurred
	 * @since 3.0 (added serverPrincipal)
	 */
	public HttpResult get(String url, String token, boolean verifyHostname, SSLContext sslContext)
			throws IOException, GeneralSecurityException {
		return get(url, REQUEST_TIMEOUT_MILLIS, token, verifyHostname, sslContext);
	}

	/**
	 * Execute http GET request.
	 * 
	 * @param url url for GET
	 * @param requestTimeoutMillis request timeout in milliseconds
	 * @param token optional bearer token
	 * @param verifyHostname {@code true} to verify principal of server
	 *            certificate for weak hostname verification
	 * @param sslContext ssl context for https
	 * @return http result.
	 * @throws IOException if an i/o error occurred
	 * @throws GeneralSecurityException if an encryption error occurred
	 * @since 3.4
	 */
	public HttpResult get(String url, int requestTimeoutMillis, String token, final boolean verifyHostname,
			SSLContext sslContext) throws IOException, GeneralSecurityException {

		try {
			URL get = new URL(url);
			HttpURLConnection con = (HttpURLConnection) get.openConnection();
			if (sslContext != null && con instanceof HttpsURLConnection) {
				HttpsURLConnection httpsCon = (HttpsURLConnection) con;
				httpsCon.setSSLSocketFactory(sslContext.getSocketFactory());
				httpsCon.setHostnameVerifier(new HostnameVerifier() {

					@Override
					public boolean verify(String hostname, SSLSession session) {
						if (verifyHostname) {
							String cn = "???";
							try {
								Principal principal = session.getPeerPrincipal();
								if (principal instanceof X500Principal) {
									cn = Asn1DerDecoder.readCNFromDN(((X500Principal) principal).getEncoded());
								}
							} catch (SSLPeerUnverifiedException e) {
							}
							LOGGER.warn("Hostname: {} for {} suspicious!", hostname, cn);
							return false;
						} else {
							return true;
						}
					}
				});
			}
			if (token != null && !token.isEmpty()) {
				con.setRequestProperty("Authorization", "Bearer " + token);
			}
			con.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
			con.setReadTimeout(requestTimeoutMillis);
			int responseCode = con.getResponseCode();
			String responseMessage = con.getResponseMessage();
			Principal peerPrincipal = null;
			if (sslContext != null && con instanceof HttpsURLConnection) {
				peerPrincipal = ((HttpsURLConnection) con).getPeerPrincipal();
			}
			LOGGER.info("Sending 'GET' request to URL : {}", url);
			LOGGER.info("Response Code : {} - {}", responseCode, responseMessage);
			InputStream content = null;
			try {
				content = con.getInputStream();
			} catch (FileNotFoundException ex) {
				// errors, e.g. 404 may have no content
				content = new ByteArrayInputStream(Bytes.EMPTY);
			}
			return new HttpResult(responseCode, responseMessage, peerPrincipal, content);
		} catch (RuntimeException ex) {
			LOGGER.info("Sending 'GET' request to URL : {} failed!", url, ex);
			return new HttpResult(0, ex.getMessage(), null, null);
		}
	}

}
