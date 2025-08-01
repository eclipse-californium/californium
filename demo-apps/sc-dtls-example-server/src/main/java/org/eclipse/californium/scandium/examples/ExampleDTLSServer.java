/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.scandium.examples;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.pskstore.MultiPskStore;
import org.eclipse.californium.scandium.dtls.x509.SingleCertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.StaticCertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ExampleDTLSServer {

	private static final int DEFAULT_PORT = 5684;
	private static final Logger LOG = LoggerFactory
			.getLogger(ExampleDTLSServer.class.getName());
	private static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	private static final char[] TRUST_STORE_PASSWORD = "rootPass".toCharArray();
	private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";

	static {
		DtlsConfig.register();
	}

	/**
	 * Special configuration defaults handler.
	 */
	private static final DefinitionsProvider DEFAULTS = (config) -> {
		config.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 6);
		config.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false);
	};

	private DTLSConnector dtlsConnector;

	public ExampleDTLSServer() {
		MultiPskStore pskStore = new MultiPskStore();
		// put in the PSK store the default identity/psk for tinydtls tests
		pskStore.setKey("Client_identity", "secretPSK".getBytes());
		try {
			// load the key store
			SslContextUtil.Credentials serverCredentials = SslContextUtil.loadCredentials(
					SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, "server", KEY_STORE_PASSWORD,
					KEY_STORE_PASSWORD);
			Certificate[] trustedCertificates = SslContextUtil.loadTrustedCertificates(
					SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION, "root", TRUST_STORE_PASSWORD);

			Configuration configuration = Configuration.createWithFile(Configuration.DEFAULT_FILE, "DTLS example server", DEFAULTS);
			DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder(configuration)
					.setAddress(new InetSocketAddress(DEFAULT_PORT))
					.setPskStore(pskStore)
					.setCertificateIdentityProvider(
							new SingleCertificateProvider(serverCredentials.getPrivateKey(), serverCredentials.getCertificateChain(), CertificateType.RAW_PUBLIC_KEY, CertificateType.X_509))
					.setCertificateVerifier(StaticCertificateVerifier.builder()
							.setTrustedCertificates(trustedCertificates).setTrustAllRPKs().build());

			dtlsConnector = new DTLSConnector(builder.build());
			dtlsConnector
					.setRawDataReceiver(new RawDataChannelImpl(dtlsConnector));

		} catch (GeneralSecurityException | IOException e) {
			LOG.error("Could not load the keystore", e);
		}
	}

	public void start() {
		try {
			dtlsConnector.start();
			System.out.println("DTLS example server started");
		} catch (IOException e) {
			throw new IllegalStateException(
					"Unexpected error starting the DTLS UDP server", e);
		}
	}

	private class RawDataChannelImpl implements RawDataChannel {

		private Connector connector;

		public RawDataChannelImpl(Connector con) {
			this.connector = con;
		}

		@Override
		public void receiveData(final RawData raw) {
			if (LOG.isInfoEnabled()) {
				LOG.info("Received request: {}", new String(raw.getBytes()));
			}
			RawData response = RawData.outbound("ACK".getBytes(),
					raw.getEndpointContext(), null, false);
			connector.send(response);
		}
	}

	public static void main(String[] args) {

		ExampleDTLSServer server = new ExampleDTLSServer();
		server.start();
		try {
			for (;;) {
				Thread.sleep(5000);
			}
		} catch (InterruptedException e) {
		}
	}
}
