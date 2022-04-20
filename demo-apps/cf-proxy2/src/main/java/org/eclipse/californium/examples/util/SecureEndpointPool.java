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
 *    Bosch.IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.examples.util;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.proxy2.EndpointPool;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConfig.DtlsRole;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.x509.SingleCertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.StaticNewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.StaticNewAdvancedCertificateVerifier.Builder;

/**
 * A pool of secure Endpoints.
 */
public class SecureEndpointPool extends EndpointPool {

	private static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	private static final char[] TRUST_STORE_PASSWORD = "rootPass".toCharArray();
	private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";
	private static final String CLIENT_NAME = "client";
	private static final String SERVER_NAME = "server";

	private DtlsConnectorConfig dtlsConfig;

	/**
	 * Create endpoint pool with specific configuration and executors.
	 * 
	 * @param size size of pool
	 * @param init initial size of pool
	 * @param config configuration to create endpoints.
	 * @param mainExecutor main executor for endpoints
	 * @param secondaryExecutor secondary executor for endpoints
	 * @param dtlsConfig DTLS connector configuration
	 */
	public SecureEndpointPool(int size, int init, Configuration config, ScheduledExecutorService mainExecutor,
			ScheduledExecutorService secondaryExecutor, DtlsConnectorConfig dtlsConfig) {
		super(size, config, mainExecutor, secondaryExecutor);
		this.dtlsConfig = dtlsConfig;
		this.scheme = init(init);
	}

	/**
	 * Create new endpoint.
	 * 
	 * Maybe overriden to create endpoints using other schemes and protocols.
	 * 
	 * @return new created secure endpoint.
	 * @throws IOException an i/o error occurred
	 */
	@Override
	protected Endpoint createEndpoint() throws IOException {
		DTLSConnector dtlsConnector = new DTLSConnector(dtlsConfig);
		dtlsConnector.setExecutor(mainExecutor);
		Endpoint endpoint = new CoapEndpoint.Builder().setConfiguration(config).setConnector(dtlsConnector).build();
		endpoint.setExecutors(mainExecutor, secondaryExecutor);
		try {
			endpoint.start();
			return endpoint;
		} catch (IOException e) {
			endpoint.destroy();
			throw e;
		}
	}

	public static DtlsConnectorConfig.Builder setupClient(Configuration config) throws IOException, GeneralSecurityException {
		config.set(DtlsConfig.DTLS_ROLE, DtlsRole.CLIENT_ONLY);
		SslContextUtil.Credentials clientCredentials = SslContextUtil.loadCredentials(
				SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, CLIENT_NAME, KEY_STORE_PASSWORD,
				KEY_STORE_PASSWORD);
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(
				SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION, null, TRUST_STORE_PASSWORD);
		DtlsConnectorConfig.Builder dtlsConfig = DtlsConnectorConfig.builder(config);
		dtlsConfig.setCertificateIdentityProvider(new SingleCertificateProvider(clientCredentials.getPrivateKey(), clientCredentials.getCertificateChain(),
				CertificateType.X_509, CertificateType.RAW_PUBLIC_KEY));
		Builder verifierBuilder = StaticNewAdvancedCertificateVerifier.builder();
		verifierBuilder.setTrustedCertificates(trustedCertificates);
		verifierBuilder.setTrustAllRPKs();
		dtlsConfig.setAdvancedCertificateVerifier(verifierBuilder.build());

		return dtlsConfig;
	}


	public static DtlsConnectorConfig.Builder setupServer(Configuration config) throws IOException, GeneralSecurityException {
		SslContextUtil.Credentials serverCredentials = SslContextUtil.loadCredentials(
				SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, SERVER_NAME, KEY_STORE_PASSWORD,
				KEY_STORE_PASSWORD);
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(
				SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION, null, TRUST_STORE_PASSWORD);
		DtlsConnectorConfig.Builder dtlsConfig = DtlsConnectorConfig.builder(config);
		dtlsConfig.setCertificateIdentityProvider(new SingleCertificateProvider(serverCredentials.getPrivateKey(), serverCredentials.getCertificateChain(),
				CertificateType.X_509, CertificateType.RAW_PUBLIC_KEY));
		Builder verifierBuilder = StaticNewAdvancedCertificateVerifier.builder();
		verifierBuilder.setTrustedCertificates(trustedCertificates);
		verifierBuilder.setTrustAllRPKs();
		dtlsConfig.setAdvancedCertificateVerifier(verifierBuilder.build());

		return dtlsConfig;
	}
}
