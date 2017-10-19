/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Achim Kraus (Bosch Software Innovations GmbH) - add TCP and encryption support.
 ******************************************************************************/
package org.eclipse.californium.plugtests;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;

import javax.net.ssl.SSLContext;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.network.interceptors.OriginTracer;
import org.eclipse.californium.elements.tcp.TcpServerConnector;
import org.eclipse.californium.elements.tcp.TlsServerConnector;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.plugtests.resources.Create;
import org.eclipse.californium.plugtests.resources.DefaultTest;
import org.eclipse.californium.plugtests.resources.Large;
import org.eclipse.californium.plugtests.resources.LargeCreate;
import org.eclipse.californium.plugtests.resources.LargePost;
import org.eclipse.californium.plugtests.resources.LargeSeparate;
import org.eclipse.californium.plugtests.resources.LargeUpdate;
import org.eclipse.californium.plugtests.resources.Link1;
import org.eclipse.californium.plugtests.resources.Link2;
import org.eclipse.californium.plugtests.resources.Link3;
import org.eclipse.californium.plugtests.resources.LocationQuery;
import org.eclipse.californium.plugtests.resources.LongPath;
import org.eclipse.californium.plugtests.resources.MultiFormat;
import org.eclipse.californium.plugtests.resources.Observe;
import org.eclipse.californium.plugtests.resources.ObserveLarge;
import org.eclipse.californium.plugtests.resources.ObserveNon;
import org.eclipse.californium.plugtests.resources.ObservePumping;
import org.eclipse.californium.plugtests.resources.ObserveReset;
import org.eclipse.californium.plugtests.resources.Path;
import org.eclipse.californium.plugtests.resources.Query;
import org.eclipse.californium.plugtests.resources.Separate;
import org.eclipse.californium.plugtests.resources.Shutdown;
import org.eclipse.californium.plugtests.resources.Validate;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.util.ServerNames;

// ETSI Plugtest environment
//import java.net.InetSocketAddress;
//import org.eclipse.californium.core.network.CoAPEndpoint;

/**
 * The class PlugtestServer implements the test specification for the ETSI IoT
 * CoAP Plugtests, London, UK, 7--9 Mar 2014.
 */
public class PlugtestServer extends CoapServer {

	// exit codes for runtime errors
	public static final int ERR_INIT_FAILED = 1;
	private static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	private static final char[] TRUST_STORE_PASSWORD = "rootPass".toCharArray();
	private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";
	private static final String SERVER_NAME = "server";
	private static final String PSK_IDENTITY_PREFIX = "cali.";
	private static final byte[] PSK_SECRET = ".fornium".getBytes();
	private static final int MAX_RESOURCE_SIZE = 8192;

	private static final NetworkConfig CONFIG = NetworkConfig.getStandard();
	
	// allows port configuration in Californium.properties

	public static void main(String[] args) {
		CONFIG // used for plugtest
		.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 64).setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 64)
		.setInt(NetworkConfig.Keys.NOTIFICATION_CHECK_INTERVAL_COUNT, 4)
		.setInt(NetworkConfig.Keys.NOTIFICATION_CHECK_INTERVAL_TIME, 30000)
		.setInt(NetworkConfig.Keys.HEALTH_STATUS_INTERVAL, 300)
		.setString(NetworkConfig.Keys.HEALTH_STATUS_PRINT_LEVEL, "INFO");

		if (CONFIG.getInt(NetworkConfig.Keys.MAX_RESOURCE_BODY_SIZE) < MAX_RESOURCE_SIZE) {
			CONFIG.setInt(NetworkConfig.Keys.MAX_RESOURCE_BODY_SIZE, MAX_RESOURCE_SIZE);
		}

		
		// create server
		try {
			PlugtestServer server = new PlugtestServer();
			// ETSI Plugtest environment
//			server.addEndpoint(new CoAPEndpoint(new InetSocketAddress("::1", port)));
//			server.addEndpoint(new CoAPEndpoint(new InetSocketAddress("127.0.0.1", port)));
//			server.addEndpoint(new CoAPEndpoint(new InetSocketAddress("2a01:c911:0:2010::10", port)));
//			server.addEndpoint(new CoAPEndpoint(new InetSocketAddress("10.200.1.2", port)));
			server.addEndpoints(true, true, true, true, false);
			server.start();

			// add special interceptor for message traces
			for (Endpoint ep : server.getEndpoints()) {
				System.out.println("listen on " + ep.getUri());
				ep.addInterceptor(new MessageTracer());
				// Eclipse IoT metrics
				ep.addInterceptor(new OriginTracer());
			}

			System.out.println(PlugtestServer.class.getSimpleName() + " started ...");

		} catch (Exception e) {

			System.err.printf("Failed to create " + PlugtestServer.class.getSimpleName() + ": %s\n", e.getMessage());
			e.printStackTrace(System.err);
			System.err.println("Exiting");
			System.exit(ERR_INIT_FAILED);
		}

	}

	private void addEndpoints(boolean udp, boolean tcp, boolean secure, boolean plain, boolean altPort) {
		int coapPort = CONFIG.getInt(NetworkConfig.Keys.COAP_PORT);
		int coapsPort = CONFIG.getInt(NetworkConfig.Keys.COAP_SECURE_PORT);
		int tcpThreads = CONFIG.getInt(NetworkConfig.Keys.TCP_WORKER_THREADS);
		int tcpIdleTimeout = CONFIG.getInt(NetworkConfig.Keys.TCP_CONNECTION_IDLE_TIMEOUT);

		SslContextUtil.Credentials serverCredentials = null;
		Certificate[] trustedCertificates = null;
		SSLContext serverSslContext = null;

		if (altPort) {
			coapPort += 100;
			coapsPort += 100;
		}
		
		if (secure) {
			try {
				serverCredentials = SslContextUtil.loadCredentials(
						SslContextUtil.CLASSPATH_PROTOCOL + KEY_STORE_LOCATION, SERVER_NAME, KEY_STORE_PASSWORD,
						KEY_STORE_PASSWORD);
				trustedCertificates = SslContextUtil.loadTrustedCertificates(
						SslContextUtil.CLASSPATH_PROTOCOL + TRUST_STORE_LOCATION, null, TRUST_STORE_PASSWORD);
				serverSslContext = SslContextUtil.createSSLContext(SERVER_NAME, serverCredentials.getPrivateKey(),
						serverCredentials.getCertificateChain(), trustedCertificates);
			} catch (GeneralSecurityException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		for (InetAddress addr : EndpointManager.getEndpointManager().getNetworkInterfaces()) {
			if (plain) {
				InetSocketAddress bindToAddress = new InetSocketAddress(addr, coapPort);
				if (udp) {
					addEndpoint(new CoapEndpoint(bindToAddress, CONFIG));
				}
				if (tcp) {
					TcpServerConnector connector = new TcpServerConnector(bindToAddress, tcpThreads, tcpIdleTimeout);
					addEndpoint(new CoapEndpoint(connector, CONFIG));
				}
			}
			if (secure) {
				InetSocketAddress bindToAddress = new InetSocketAddress(addr, coapsPort);
				if (udp) {
					DtlsConnectorConfig.Builder dtlsConfig = new DtlsConnectorConfig.Builder();
					dtlsConfig.setAddress(bindToAddress);
					dtlsConfig.setSupportedCipherSuites(new CipherSuite[] { CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
							CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 });
					dtlsConfig.setPskStore(new PlugPskStore());
					dtlsConfig.setIdentity(serverCredentials.getPrivateKey(), serverCredentials.getCertificateChain(),
							true);
					dtlsConfig.setTrustStore(trustedCertificates);

					DTLSConnector connector = new DTLSConnector(dtlsConfig.build());

					addEndpoint(new CoapEndpoint(connector, CONFIG));
				}
				if (tcp) {
					TlsServerConnector connector = new TlsServerConnector(serverSslContext, bindToAddress, tcpThreads,
							tcpIdleTimeout);
					addEndpoint(new CoapEndpoint(connector, CONFIG));
				}
			}
		}
	}

	public PlugtestServer() throws SocketException {

		// add resources to the server
		add(new DefaultTest());
		add(new LongPath());
		add(new Query());
		add(new Separate());
		add(new Large());
		add(new LargeUpdate());
		add(new LargeCreate());
		add(new LargePost());
		add(new LargeSeparate());
		add(new Observe());
		add(new ObserveNon());
		add(new ObserveReset());
		add(new ObserveLarge());
		add(new ObservePumping());
		add(new ObservePumping(Type.NON));
		add(new LocationQuery());
		add(new MultiFormat());
		add(new Link1());
		add(new Link2());
		add(new Link3());
		add(new Path());
		add(new Validate());
		add(new Create());
		add(new Shutdown());
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
