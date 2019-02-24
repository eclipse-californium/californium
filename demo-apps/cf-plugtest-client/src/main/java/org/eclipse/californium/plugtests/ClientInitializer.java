/*******************************************************************************
 * Copyright (c) 2017, 2018 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove MAC usage for
 *                                                    PSK identity.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add argument -i (identity)
 *    Achim Kraus (Bosch Software Innovations GmbH) - add createEndpoint to create
 *                                                    more client endpoints.
 ******************************************************************************/
package org.eclipse.californium.plugtests;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSessionContext;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.tcp.TcpClientConnector;
import org.eclipse.californium.elements.tcp.TlsClientConnector;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.util.ByteArrayUtils;
import org.eclipse.californium.scandium.util.ServerNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Client initializer.
 */
public class ClientInitializer {

	private static final Logger LOGGER = LoggerFactory.getLogger(ClientInitializer.class.getCanonicalName());

	public static final String PSK_IDENTITY_PREFIX = "cali.";

	private static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	private static final char[] TRUST_STORE_PASSWORD = "rootPass".toCharArray();
	private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";
	private static final String CLIENT_NAME = "client";
	private static final byte[] PSK_SECRET = ".fornium".getBytes();

	/**
	 * Initialize client.
	 * 
	 * @param args the arguments
	 */
	public static Arguments init(NetworkConfig config, String[] args) {
		int index = 0;
		boolean json = false;
		boolean verbose = false;
		boolean ping = true;
		boolean rpk = false;
		boolean x509 = false;
		String id = null;
		String secret = null;

		if (args[index].equals("-s")) {
			++index;
			ping = false;
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
			rpk = true;
		} else if (args[index].equals("-x")) {
			++index;
			x509 = true;
		} else if (args[index].equals("-i")) {
			++index;
			id = args[index];
			++index;
			secret = args[index];
			++index;
		}

		String uri = args[index];

		// allow quick hostname as argument

		if (uri.indexOf("://") == -1) {
			uri = "coap://" + uri;
		}
		if (uri.endsWith("/")) {
			uri = uri.substring(uri.length() - 1);
		}

		ping = ping && !uri.startsWith(CoAP.COAP_TCP_URI_SCHEME + "://")
				&& !uri.startsWith(CoAP.COAP_SECURE_TCP_URI_SCHEME + "://");
		String[] leftArgs = Arrays.copyOfRange(args, index + 1, args.length);
		Arguments arguments = new Arguments(uri, id, secret, rpk, x509, ping, verbose, json, leftArgs);
		CoapEndpoint coapEndpoint = createEndpoint(config, arguments, null);
		EndpointManager.getEndpointManager().setDefaultEndpoint(coapEndpoint);

		return arguments;
	}

	/**
	 * Create endpoint from arguments.
	 * 
	 * @param config network configuration to use
	 * @param arguments arguments
	 * @param executor executor service. {@code null}, if no external executor should be used.
	 * @return created endpoint.
	 */
	public static CoapEndpoint createEndpoint(NetworkConfig config, Arguments arguments, ExecutorService executor) {
		Connector connector = null;
		int tcpThreads = config.getInt(NetworkConfig.Keys.TCP_WORKER_THREADS);
		int tcpConnectTimeout = config.getInt(NetworkConfig.Keys.TCP_CONNECT_TIMEOUT);
		int tlsHandshakeTimeout = config.getInt(NetworkConfig.Keys.TLS_HANDSHAKE_TIMEOUT);
		int tcpIdleTimeout = config.getInt(NetworkConfig.Keys.TCP_CONNECTION_IDLE_TIMEOUT);
		int maxPeers = config.getInt(Keys.MAX_ACTIVE_PEERS);
		int sessionTimeout = config.getInt(Keys.SECURE_SESSION_TIMEOUT);
		int staleTimeout = config.getInt(NetworkConfig.Keys.MAX_PEER_INACTIVITY_PERIOD);
		int senderThreads = config.getInt(NetworkConfig.Keys.NETWORK_STAGE_SENDER_THREAD_COUNT);
		int receiverThreads = config.getInt(NetworkConfig.Keys.NETWORK_STAGE_RECEIVER_THREAD_COUNT);
		Integer cidLength = config.getOptInteger(Keys.DTLS_CONNECTION_ID_LENGTH);

		if (arguments.uri.startsWith(CoAP.COAP_SECURE_URI_SCHEME)) {
			SslContextUtil.Credentials clientCredentials = null;
			Certificate[] trustedCertificates = null;
			SSLContext clientSslContext = null;
			try {
				clientCredentials = SslContextUtil.loadCredentials(SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION,
						CLIENT_NAME, KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
				trustedCertificates = SslContextUtil.loadTrustedCertificates(
						SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION, null, TRUST_STORE_PASSWORD);
				clientSslContext = SslContextUtil.createSSLContext(CLIENT_NAME, clientCredentials.getPrivateKey(),
						clientCredentials.getCertificateChain(), trustedCertificates);
				SSLSessionContext clientSessionContext = clientSslContext.getClientSessionContext();
				if (clientSessionContext != null) {
					clientSessionContext.setSessionTimeout(sessionTimeout);
					clientSessionContext.setSessionCacheSize(maxPeers);
				}
			} catch (GeneralSecurityException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}

			if (arguments.uri.startsWith(CoAP.COAP_SECURE_URI_SCHEME + "://")) {
				DtlsConnectorConfig.Builder dtlsConfig = new DtlsConnectorConfig.Builder();
				if (arguments.rpk) {
					dtlsConfig.setIdentity(clientCredentials.getPrivateKey(), clientCredentials.getCertificateChain(),
							CertificateType.RAW_PUBLIC_KEY);
					dtlsConfig.setRpkTrustAll();
				} else if (arguments.x509) {
					dtlsConfig.setIdentity(clientCredentials.getPrivateKey(), clientCredentials.getCertificateChain(),
							CertificateType.X_509);
					dtlsConfig.setTrustStore(trustedCertificates);
				} else if (arguments.id != null) {
					byte[] secret = arguments.secret == null ? null : arguments.secret.getBytes();
					dtlsConfig.setPskStore(new PlugPskStore(arguments.id, secret));
				} else {
					byte[] rid = new byte[8];
					SecureRandom random = new SecureRandom();
					random.nextBytes(rid);
					dtlsConfig.setPskStore(new PlugPskStore(ByteArrayUtils.toHex(rid)));
				}
				dtlsConfig.setConnectionIdLength(cidLength);
				dtlsConfig.setClientOnly();
				dtlsConfig.setMaxConnections(maxPeers);
				dtlsConfig.setConnectionThreadCount(senderThreads);
				dtlsConfig.setReceiverThreadCount(receiverThreads);
				dtlsConfig.setStaleConnectionThreshold(staleTimeout);
				DTLSConnector dtlsConnector = new DTLSConnector(dtlsConfig.build());
				if (executor != null) {
					dtlsConnector.setExecutor(executor);
				}
				connector = dtlsConnector;
			} else if (arguments.uri.startsWith(CoAP.COAP_SECURE_TCP_URI_SCHEME + "://")) {
				connector = new TlsClientConnector(clientSslContext, tcpThreads, tcpConnectTimeout, tlsHandshakeTimeout,
						tcpIdleTimeout);
			}
		} else if (arguments.uri.startsWith(CoAP.COAP_TCP_URI_SCHEME + "://")) {
			connector = new TcpClientConnector(tcpThreads, tcpConnectTimeout, tcpIdleTimeout);
		} else if (arguments.uri.startsWith(CoAP.COAP_URI_SCHEME + "://")) {
			connector = new UDPConnector();
		}

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConnector(connector);
		builder.setNetworkConfig(config);
		CoapEndpoint endpoint = builder.build();
		if (arguments.verbose) {
			endpoint.addInterceptor(new MessageTracer());
		}
		return endpoint;
	}

	public static class PlugPskStore implements PskStore {

		private final String identity;
		private final byte[] secret;

		public PlugPskStore(String id, byte[] secret) {
			this.identity = id;
			this.secret = secret;
			LOGGER.info("DTLS-PSK-Identity: {})", identity);
		}

		public PlugPskStore(String id) {
			identity = PSK_IDENTITY_PREFIX + id;
			secret = null;
			LOGGER.info("DTLS-PSK-Identity: {} ({} random bytes)", identity, (id.length() / 2));
		}

		@Override
		public byte[] getKey(String identity) {
			if (secret != null) {
				return secret;
			}
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

		@Override
		public String getIdentity(InetSocketAddress peerAddress, ServerNames virtualHost) {
			return getIdentity(peerAddress);
		}
	}

	public static class Arguments {

		public final boolean ping;
		public final boolean verbose;
		public final boolean json;
		public final boolean rpk;
		public final boolean x509;
		public final String id;
		public final String secret;
		public final String uri;
		public final String[] args;

		/**
		 * Create new arguments instance.
		 * 
		 * @param uri destination URI
		 * @param id client id
		 * @param secret client secret (PSK only). if {@code null} and
		 *            {@link ClientInitializer#PSK_IDENTITY_PREFIX} is used, use
		 *            {@link ClientInitializer#PSK_SECRET}
		 * @param rpk {@code true}, if raw public key is preferred,
		 *            {@code false}, otherwise
		 * @param x509 {@code true}, if x.509 should be used, {@code false},
		 *            otherwise
		 * @param ping {@code true}, if client starts communication with ping,
		 *            {@code false}, otherwise
		 * @param verbose {@code true}, enable verbose mode, {@code false},
		 *            otherwise
		 * @param json {@code true}, json content should be used, {@code false},
		 *            otherwise
		 * @param args left arguments
		 */
		public Arguments(String uri, String id, String secret, boolean rpk, boolean x509, boolean ping, boolean verbose,
				boolean json, String[] args) {
			this.uri = uri;
			this.id = id;
			this.secret = secret;
			this.rpk = rpk;
			this.x509 = x509;
			this.ping = ping;
			this.verbose = verbose;
			this.json = json;
			this.args = args;
		}

		/**
		 * Create arguments clone with different PSK identity and secret.
		 * 
		 * @param id psk identity
		 * @param secret secret (PSK only). if {@code null} and
		 *            {@link ClientInitializer#PSK_IDENTITY_PREFIX} is used, use
		 *            {@link ClientInitializer#PSK_SECRET}
		 * @return create arguments clone.
		 */
		public Arguments create(String id, String secret) {
			return new Arguments(uri, id, secret, rpk, x509, ping, verbose, json, args);
		}
	}
}
