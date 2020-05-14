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
 *    Achim Kraus (Bosch.IO GmbH) - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.interoperability.test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.List;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.SslContextUtil.Credentials;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;

/**
 * Connector utility.
 * 
 * Build and configure {@link DTLSConnector}.
 */
public class ConnectorUtil {

	public static final int PORT = 5684;

	private static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	private static final char[] TRUST_STORE_PASSWORD = "rootPass".toCharArray();
	private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";
	private static final String CLIENT_NAME = "client";
	private static final String SERVER_NAME = "server";
	private static final String SERVER_RSA_NAME = "serverrsa";
	public static final String TRUST_CA = "ca";
	public static final String TRUST_ROOT = "root";

	/**
	 * DTLS connector.
	 */
	private DTLSConnector connector;
	/**
	 * Credentials for ECDSA base cipher suites.
	 */
	private SslContextUtil.Credentials credentials;
	/**
	 * Credentials for ECDSA base cipher suites with RSA chain.
	 */
	private SslContextUtil.Credentials credentialsRsa;
	private Certificate[] trustCa;
	private Certificate[] trustRoot;
	private Certificate[] trustAll;

	/**
	 * Create new utility instance.
	 * 
	 * @param client {@code true} to use client credentials, {@code false}, for
	 *            server credentials.
	 */
	public ConnectorUtil(boolean client) {
		try {
			credentials = SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION,
					client ? CLIENT_NAME : SERVER_NAME, KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
			credentialsRsa = client ? null
					: SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION,
							SERVER_RSA_NAME, KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
			trustCa = SslContextUtil.loadTrustedCertificates(SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION,
					TRUST_CA, TRUST_STORE_PASSWORD);
			trustRoot = SslContextUtil.loadTrustedCertificates(SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION,
					TRUST_ROOT, TRUST_STORE_PASSWORD);
			trustAll = new Certificate[0];
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Shutdown the connector.
	 */
	public void shutdown() {
		if (connector != null) {
			connector.destroy();
			connector = null;
		}
	}

	/**
	 * Build connector.
	 * 
	 * @param bind address to bind connector to
	 * @param trust alias of trusted certificate, or {@code null} to trust all
	 *            received certificates.
	 * @param cipherSuites cipher suites to support.
	 */
	public void build(InetSocketAddress bind, String trust, CipherSuite... cipherSuites) {
		build(bind, false, null, trust, cipherSuites);
	}

	/**
	 * Build connector.
	 * 
	 * @param bind address to bind connector to
	 * @param rsa use mixed certifcate path (includes RSA certificate). Server
	 *            only!
	 * @param dtlsBuilder preconfigured dtls builder. Maybe {@link null}.
	 * @param trust alias of trusted certificate, or {@code null} to trust all
	 *            received certificates.
	 * @param cipherSuites cipher suites to support.
	 */
	public void build(InetSocketAddress bind, boolean rsa, DtlsConnectorConfig.Builder dtlsBuilder, String trust,
			CipherSuite... cipherSuites) {
		List<CipherSuite> suites = Arrays.asList(cipherSuites);
		if (dtlsBuilder == null) {
			dtlsBuilder = new DtlsConnectorConfig.Builder();
		}
		dtlsBuilder.setAddress(bind);
		dtlsBuilder.setRecommendedCipherSuitesOnly(false);
		dtlsBuilder.setConnectionThreadCount(2);
		dtlsBuilder.setReceiverThreadCount(2);
		if (CipherSuite.containsPskBasedCipherSuite(suites)) {
			dtlsBuilder
					.setPskStore(new StaticPskStore(OpenSslUtil.OPENSSL_PSK_IDENTITY, OpenSslUtil.OPENSSL_PSK_SECRET));
		}
		if (CipherSuite.containsCipherSuiteRequiringCertExchange(suites)) {
			if (credentials != null && dtlsBuilder.getIncompleteConfig().getPrivateKey() == null) {
				Credentials credentials = rsa ? this.credentialsRsa : this.credentials;
				dtlsBuilder.setIdentity(credentials.getPrivateKey(), credentials.getCertificateChain(),
						CertificateType.X_509, CertificateType.RAW_PUBLIC_KEY);
				if (TRUST_CA.equals(trust)) {
					dtlsBuilder.setTrustStore(trustCa);
				} else if (TRUST_ROOT.equals(trust)) {
					dtlsBuilder.setTrustStore(trustRoot);
				} else {
					dtlsBuilder.setTrustStore(trustAll);
				}
			}
		}
		dtlsBuilder.setSupportedCipherSuites(suites);
		connector = new DTLSConnector(dtlsBuilder.build());
	}

	/**
	 * Get connector.
	 * 
	 * @return connector
	 */
	public Connector getConnector() {
		return connector;
	}

}
