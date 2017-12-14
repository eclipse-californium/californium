/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.plugtests;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.List;

import javax.net.ssl.SSLContext;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.tcp.TcpServerConnector;
import org.eclipse.californium.elements.tcp.TlsServerConnector;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * Base for test servers.
 */
public abstract class AbstractTestServer extends CoapServer {

	public enum Protocol {
		UDP, DTLS, TCP, TLS
	}

	// exit codes for runtime errors
	private static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	private static final char[] TRUST_STORE_PASSWORD = "rootPass".toCharArray();
	private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";
	private static final String SERVER_NAME = "server";
	private static final String PSK_IDENTITY_PREFIX = "cali.";
	private static final byte[] PSK_SECRET = ".fornium".getBytes();

	public void addEndpoints(NetworkConfig config, boolean loopback, List<Protocol> protocols) {
		int coapPort = config.getInt(NetworkConfig.Keys.COAP_PORT);
		int coapsPort = config.getInt(NetworkConfig.Keys.COAP_SECURE_PORT);
		int tcpThreads = config.getInt(NetworkConfig.Keys.TCP_WORKER_THREADS);
		int tcpIdleTimeout = config.getInt(NetworkConfig.Keys.TCP_CONNECTION_IDLE_TIMEOUT);

		SslContextUtil.Credentials serverCredentials = null;
		Certificate[] trustedCertificates = null;
		SSLContext serverSslContext = null;

		if (protocols.contains(Protocol.DTLS) || protocols.contains(Protocol.TLS)) {
			try {
				serverCredentials = SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION,
						SERVER_NAME, KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
				trustedCertificates = SslContextUtil.loadTrustedCertificates(
						SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION, null, TRUST_STORE_PASSWORD);
				serverSslContext = SslContextUtil.createSSLContext(SERVER_NAME, serverCredentials.getPrivateKey(),
						serverCredentials.getCertificateChain(), trustedCertificates);
			} catch (GeneralSecurityException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		for (InetAddress addr : EndpointManager.getEndpointManager().getNetworkInterfaces()) {
			if (!loopback && addr.isLoopbackAddress()) {
				continue;
			}
			if (protocols.contains(Protocol.UDP) || protocols.contains(Protocol.TCP)) {
				InetSocketAddress bindToAddress = new InetSocketAddress(addr, coapPort);
				if (protocols.contains(Protocol.UDP)) {
					CoapEndpoint.CoapEndpointBuilder builder = new CoapEndpoint.CoapEndpointBuilder();
					builder.setInetSocketAddress(bindToAddress);
					builder.setNetworkConfig(config);
					addEndpoint(builder.build());
				}
				if (protocols.contains(Protocol.TCP)) {
					TcpServerConnector connector = new TcpServerConnector(bindToAddress, tcpThreads, tcpIdleTimeout);
					CoapEndpoint.CoapEndpointBuilder builder = new CoapEndpoint.CoapEndpointBuilder();
					builder.setConnector(connector);
					builder.setNetworkConfig(config);
					addEndpoint(builder.build());
				}
			}
			if (protocols.contains(Protocol.DTLS) || protocols.contains(Protocol.TLS)) {
				InetSocketAddress bindToAddress = new InetSocketAddress(addr, coapsPort);
				if (protocols.contains(Protocol.DTLS)) {
					DtlsConnectorConfig.Builder dtlsConfig = new DtlsConnectorConfig.Builder();
					dtlsConfig.setAddress(bindToAddress);
					dtlsConfig.setSupportedCipherSuites(new CipherSuite[] { CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
							CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256,
							CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 });
					dtlsConfig.setPskStore(new PlugPskStore());
					dtlsConfig.setIdentity(serverCredentials.getPrivateKey(), serverCredentials.getCertificateChain(),
							true);
					dtlsConfig.setTrustStore(trustedCertificates);

					DTLSConnector connector = new DTLSConnector(dtlsConfig.build());
					CoapEndpoint.CoapEndpointBuilder builder = new CoapEndpoint.CoapEndpointBuilder();
					builder.setConnector(connector);
					builder.setNetworkConfig(config);

					addEndpoint(builder.build());
				}
				if (protocols.contains(Protocol.TLS)) {
					TlsServerConnector connector = new TlsServerConnector(serverSslContext, bindToAddress, tcpThreads,
							tcpIdleTimeout);
					CoapEndpoint.CoapEndpointBuilder builder = new CoapEndpoint.CoapEndpointBuilder();
					builder.setConnector(connector);
					builder.setNetworkConfig(config);
					addEndpoint(builder.build());
				}
			}
		}
	}

	private static class PlugPskStore implements PskStore {

		@Override
		public byte[] getKey(String identity) {
			if (identity.startsWith(PSK_IDENTITY_PREFIX)) {
				return PSK_SECRET;
			}
			return null;
		}

		@Override
		public byte[] getKey(ServerNames serverNames, String identity) {
			return getKey(identity);
		}

		@Override
		public String getIdentity(InetSocketAddress inetAddress) {
			return PSK_IDENTITY_PREFIX + "sandbox";
		}

	}
}
