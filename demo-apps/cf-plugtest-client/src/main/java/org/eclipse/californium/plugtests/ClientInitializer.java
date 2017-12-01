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
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Enumeration;

import javax.net.ssl.SSLContext;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.tcp.TcpClientConnector;
import org.eclipse.californium.elements.tcp.TlsClientConnector;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.util.ByteArrayUtils;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * Client initializer.
 */
public class ClientInitializer {

	private static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	private static final char[] TRUST_STORE_PASSWORD = "rootPass".toCharArray();
	private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";
	private static final String CLIENT_NAME = "client";
	private static final String PSK_IDENTITY_PREFIX = "cali.";
	private static final byte[] PSK_SECRET = ".fornium".getBytes();
	private static final int MAX_RESOURCE_SIZE = 8192;

	/**
	 * Initialize client.
	 * 
	 * @param args the arguments
	 */
	public static Arguments init(NetworkConfig config, String[] args) {

		// Config used for plugtest
		if (config.getInt(NetworkConfig.Keys.MAX_RESOURCE_BODY_SIZE) < MAX_RESOURCE_SIZE) {
			config.setInt(NetworkConfig.Keys.MAX_RESOURCE_BODY_SIZE, MAX_RESOURCE_SIZE);
		}
		int index = 0;
		boolean json = false;
		boolean verbose = false;
		boolean ping[] = { true };
		boolean rpc = false;
		boolean x509 = false;
		if (args[index].equals("-s")) {
			++index;
			ping[0] = false;
		}
		if (args[index].equals("-v")) {
			++index;
			verbose = true;
		}
		if (args[index].equals("-j")) {
			++index;
			json = true;
		}
		if (args[index].equals("-r")) {
			++index;
			rpc = true;
		} else if (args[index].equals("-x")) {
			++index;
			x509 = true;
		}

		String uri = args[index];

		// allow quick hostname as argument

		if (uri.indexOf("://") == -1) {
			uri = "coap://" + uri;
		}
		if (uri.endsWith("/")) {
			uri = uri.substring(uri.length() - 1);
		}

		setupEndpoint(uri, verbose, rpc, x509, ping);

		return new Arguments(uri, ping[0], verbose, json);
	}

	private static void setupEndpoint(String uri, boolean verbose, boolean rpc, boolean x509, boolean ping[]) {
		NetworkConfig config = NetworkConfig.getStandard();
		Connector connector = null;

		if (uri.startsWith(CoAP.COAP_SECURE_URI_SCHEME)) {
			SslContextUtil.Credentials clientCredentials = null;
			Certificate[] trustedCertificates = null;
			SSLContext serverSslContext = null;
			try {
				clientCredentials = SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION,
						CLIENT_NAME, KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
				trustedCertificates = SslContextUtil.loadTrustedCertificates(
						SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION, null, TRUST_STORE_PASSWORD);
				serverSslContext = SslContextUtil.createSSLContext(CLIENT_NAME, clientCredentials.getPrivateKey(),
						clientCredentials.getCertificateChain(), trustedCertificates);
			} catch (GeneralSecurityException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}

			if (uri.startsWith(CoAP.COAP_SECURE_URI_SCHEME + "://")) {
				DtlsConnectorConfig.Builder dtlsConfig = new DtlsConnectorConfig.Builder();
				if (rpc || x509) {
					dtlsConfig.setIdentity(clientCredentials.getPrivateKey(), clientCredentials.getCertificateChain(),
							rpc);
					dtlsConfig.setTrustStore(trustedCertificates);
				} else {
					byte[] id = null;
					try {
						Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
						if (nets.hasMoreElements()) {
							id = nets.nextElement().getHardwareAddress();
						}
					} catch (Throwable e) {
					}
					if (id == null) {
						id = new byte[8];
						SecureRandom random = new SecureRandom();
						random.nextBytes(id);
					}
					dtlsConfig.setPskStore(new PlugPskStore(ByteArrayUtils.toHex(id)));
				}
				connector = new DTLSConnector(dtlsConfig.build());
			} else if (uri.startsWith(CoAP.COAP_SECURE_TCP_URI_SCHEME + "://")) {
				int tcpThreads = config.getInt(NetworkConfig.Keys.TCP_WORKER_THREADS);
				int tcpConnectTimeout = config.getInt(NetworkConfig.Keys.TCP_CONNECT_TIMEOUT);
				int tcpIdleTimeout = config.getInt(NetworkConfig.Keys.TCP_CONNECTION_IDLE_TIMEOUT);
				connector = new TlsClientConnector(serverSslContext, tcpThreads, tcpConnectTimeout, tcpIdleTimeout);
				ping[0] = false;
			}
		} else if (uri.startsWith(CoAP.COAP_TCP_URI_SCHEME + "://")) {
			int tcpThreads = config.getInt(NetworkConfig.Keys.TCP_WORKER_THREADS);
			int tcpConnectTimeout = config.getInt(NetworkConfig.Keys.TCP_CONNECT_TIMEOUT);
			int tcpIdleTimeout = config.getInt(NetworkConfig.Keys.TCP_CONNECTION_IDLE_TIMEOUT);
			connector = new TcpClientConnector(tcpThreads, tcpConnectTimeout, tcpIdleTimeout);
			ping[0] = false;
		} else if (uri.startsWith(CoAP.COAP_URI_SCHEME + "://")) {
			connector = new UDPConnector();
		}

		CoapEndpoint endpoint = new CoapEndpoint(connector, config);
		if (verbose) {
			endpoint.addInterceptor(new MessageTracer());
		}
		EndpointManager.getEndpointManager().setDefaultEndpoint(endpoint);
	}

	private static class PlugPskStore implements PskStore {

		private final String identity;

		public PlugPskStore(String id) {
			identity = PSK_IDENTITY_PREFIX + id;
			System.out.println("DTLS-PSK-Identity: " + identity + " (" + (id.length() / 2) + " bytes)");
		}

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
			return identity;
		}

	}

	public static class Arguments {

		public final boolean ping;
		public final boolean verbose;
		public final boolean json;
		public final String uri;

		public Arguments(String uri, boolean ping, boolean verbose, boolean json) {
			this.uri = uri;
			this.ping = ping;
			this.verbose = verbose;
			this.json = json;
		}
	}
}
