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
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.proxy2.EndpointPool;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.SingleNodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
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

	private DtlsConnectorConfig dtlsConfig;

	/**
	 * Create endpoint pool with specific network configuration and executors.
	 * 
	 * @param size size of pool
	 * @param init initial size of pool
	 * @param config network configuration to create endpoints.
	 * @param mainExecutor main executor for endpoints
	 * @param secondaryExecutor secondary executor for endpoints
	 */
	public SecureEndpointPool(int size, int init, NetworkConfig config, ScheduledExecutorService mainExecutor,
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
	 * @throws IOException
	 */
	@Override
	protected Endpoint createEndpoint() throws IOException {
		DTLSConnector dtlsConnector = new DTLSConnector(dtlsConfig);
		dtlsConnector.setExecutor(mainExecutor);
		Endpoint endpoint = new CoapEndpoint.Builder().setNetworkConfig(config).setConnector(dtlsConnector).build();
		endpoint.setExecutors(mainExecutor, secondaryExecutor);
		try {
			endpoint.start();
			return endpoint;
		} catch (IOException e) {
			endpoint.destroy();
			throw e;
		}
	}

	public static DtlsConnectorConfig.Builder setup(NetworkConfig config) throws IOException, GeneralSecurityException {
		int maxPeers = config.getInt(Keys.MAX_ACTIVE_PEERS);
		int staleTimeout = config.getInt(NetworkConfig.Keys.MAX_PEER_INACTIVITY_PERIOD);
		int retransmissionTimeout = config.getInt(Keys.ACK_TIMEOUT);
		int receiverThreads = config.getInt(NetworkConfig.Keys.NETWORK_STAGE_RECEIVER_THREAD_COUNT);
		Integer healthStatusInterval = config.getInt(NetworkConfig.Keys.HEALTH_STATUS_INTERVAL); // seconds
		Integer cidLength = config.getOptInteger(Keys.DTLS_CONNECTION_ID_LENGTH);
		Integer recvBufferSize = config.getOptInteger(Keys.UDP_CONNECTOR_RECEIVE_BUFFER);
		Integer sendBufferSize = config.getOptInteger(Keys.UDP_CONNECTOR_SEND_BUFFER);
		SslContextUtil.Credentials clientCredentials = SslContextUtil.loadCredentials(
				SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, CLIENT_NAME, KEY_STORE_PASSWORD,
				KEY_STORE_PASSWORD);
		Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(
				SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION, null, TRUST_STORE_PASSWORD);
		DtlsConnectorConfig.Builder dtlsConfig = new DtlsConnectorConfig.Builder();
		dtlsConfig.setIdentity(clientCredentials.getPrivateKey(), clientCredentials.getCertificateChain(),
				CertificateType.X_509, CertificateType.RAW_PUBLIC_KEY);
		Builder verifierBuilder = StaticNewAdvancedCertificateVerifier.builder();
		verifierBuilder.setTrustedCertificates(trustedCertificates);
		verifierBuilder.setTrustAllRPKs();
		dtlsConfig.setAdvancedCertificateVerifier(verifierBuilder.build());

		List<CipherSuite> list = CipherSuite.getCipherSuitesByKeyExchangeAlgorithm(true,
				KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN);
		dtlsConfig.setSupportedCipherSuites(list);
		if (cidLength != null) {
			dtlsConfig.setConnectionIdGenerator(new SingleNodeConnectionIdGenerator(cidLength));
		}
		dtlsConfig.setSocketReceiveBufferSize(recvBufferSize);
		dtlsConfig.setSocketSendBufferSize(sendBufferSize);
		dtlsConfig.setClientOnly();
		dtlsConfig.setRetransmissionTimeout(retransmissionTimeout);
		dtlsConfig.setMaxConnections(maxPeers);
		dtlsConfig.setReceiverThreadCount(receiverThreads);
		dtlsConfig.setStaleConnectionThreshold(staleTimeout);
		dtlsConfig.setHealthStatusInterval(healthStatusInterval);

		return dtlsConfig;
	}
}
