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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSessionContext;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.tcp.TcpClientConnector;
import org.eclipse.californium.elements.tcp.TlsClientConnector;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.pskstore.StringPskStore;
import org.eclipse.californium.scandium.dtls.SingleNodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.util.SecretUtil;
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
	private static final SecretKey PSK_SECRET = SecretUtil.create(".fornium".getBytes(), "PSK");

	private static SslContextUtil.Credentials clientCredentials = null;
	private static Certificate[] trustedCertificates = null;

	/**
	 * Initialize client.
	 * 
	 * @param config        network configuration to use
	 * @param args          the arguments
	 * @param ephemeralPort {@code true}, use ephemeral port, {@code false} use port
	 *                      from network configuration.
	 * @throws IOException if an i/o error occurs
	 */
	public static Arguments init(NetworkConfig config, String[] args, boolean ephemeralPort) throws IOException {
		int index = 0;
		boolean json = false;
		boolean cbor = false;
		boolean verbose = false;
		boolean ping = true;
		boolean rpk = false;
		boolean x509 = false;
		boolean ecdhe = false;
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
		} else if (args[index].equals("-c")) {
			++index;
			cbor = true;
		}
		if (args[index].equals("-r")) {
			++index;
			rpk = true;
		} else if (args[index].equals("-x")) {
			++index;
			x509 = true;
		} else if (args[index].equals("-e")) {
			++index;
			ecdhe = true;
		} 
		if (!rpk && !x509 && args[index].equals("-i")) {
			++index;
			id = args[index];
			++index;
			secret = args[index];
			++index;
		}

		String uri = args[index];

		// allow quick hostname as argument

		if (uri.indexOf("://") == -1) {
			if (rpk || x509 || id != null) {
				uri = CoAP.COAP_SECURE_URI_SCHEME + "://" + uri;
			} else {
				uri = CoAP.COAP_URI_SCHEME + "://" + uri;
			}
		}
		if (uri.endsWith("/")) {
			uri = uri.substring(uri.length() - 1);
		}

		ping = ping && !uri.startsWith(CoAP.COAP_TCP_URI_SCHEME + "://")
				&& !uri.startsWith(CoAP.COAP_SECURE_TCP_URI_SCHEME + "://");
		String[] leftArgs = Arrays.copyOfRange(args, index + 1, args.length);
		Arguments arguments = new Arguments(uri, id, secret, rpk, x509, ecdhe, ping, verbose, json, cbor, null, null, leftArgs);
		CoapEndpoint coapEndpoint = createEndpoint(config, arguments, null, ephemeralPort);
		coapEndpoint.start();
		LOGGER.info("endpoint started at {}", coapEndpoint.getAddress());
		EndpointManager.getEndpointManager().setDefaultEndpoint(coapEndpoint);

		return arguments;
	}

	/**
	 * Create endpoint from arguments.
	 * 
	 * @param config        network configuration to use
	 * @param arguments     arguments
	 * @param executor      executor service. {@code null}, if no external executor
	 *                      should be used.
	 * @param ephemeralPort {@code true}, use ephemeral port, {@code false} use port
	 *                      from network configuration.
	 * @return created endpoint.
	 */
	public static CoapEndpoint createEndpoint(NetworkConfig config, Arguments arguments, ExecutorService executor,
			boolean ephemeralPort) {
//		Connector connector = null;
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
		Integer recvBufferSize = config.getOptInteger(Keys.UDP_CONNECTOR_RECEIVE_BUFFER);
		Integer sendBufferSize = config.getOptInteger(Keys.UDP_CONNECTOR_SEND_BUFFER);

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		if (arguments.uri.startsWith(CoAP.COAP_SECURE_URI_SCHEME)) {
			if (clientCredentials == null || trustedCertificates == null) {
				try {
					clientCredentials = SslContextUtil.loadCredentials(
							SslContextUtil.CLASSPATH_SCHEME + KEY_STORE_LOCATION, CLIENT_NAME, KEY_STORE_PASSWORD,
							KEY_STORE_PASSWORD);
					trustedCertificates = SslContextUtil.loadTrustedCertificates(
							SslContextUtil.CLASSPATH_SCHEME + TRUST_STORE_LOCATION, null, TRUST_STORE_PASSWORD);
				} catch (GeneralSecurityException e) {
					e.printStackTrace();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			SSLContext clientSslContext = null;
			if (clientCredentials != null && trustedCertificates != null) {
				try {
					clientSslContext = SslContextUtil.createSSLContext(CLIENT_NAME, clientCredentials.getPrivateKey(),
							clientCredentials.getCertificateChain(), trustedCertificates);
					SSLSessionContext clientSessionContext = clientSslContext.getClientSessionContext();
					if (clientSessionContext != null) {
						clientSessionContext.setSessionTimeout(sessionTimeout);
						clientSessionContext.setSessionCacheSize(maxPeers);
					}
				} catch (GeneralSecurityException e) {
					e.printStackTrace();
				}
			}
			if (arguments.uri.startsWith(CoAP.COAP_SECURE_URI_SCHEME + "://")) {
				int coapsPort = ephemeralPort ? 0 : config.getInt(Keys.COAP_SECURE_PORT);
				DtlsConnectorConfig.Builder dtlsConfig = new DtlsConnectorConfig.Builder();
				KeyExchangeAlgorithm keyExchange = null;
				if (arguments.rpk) {
					if (arguments.privateKey != null && arguments.publicKey != null) {
						dtlsConfig.setIdentity(arguments.privateKey, arguments.publicKey);
					} else {
						dtlsConfig.setIdentity(clientCredentials.getPrivateKey(),
								clientCredentials.getCertificateChain(), CertificateType.RAW_PUBLIC_KEY);
					}
					dtlsConfig.setRpkTrustAll();
					keyExchange = KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN;
				} else if (arguments.x509) {
					dtlsConfig.setIdentity(clientCredentials.getPrivateKey(), clientCredentials.getCertificateChain(),
							CertificateType.X_509);
					dtlsConfig.setTrustStore(trustedCertificates);
					keyExchange = KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN;
				} else if (arguments.id != null) {
					byte[] secret = arguments.secret == null ? null : arguments.secret.getBytes();
					dtlsConfig.setPskStore(new PlugPskStore(arguments.id, secret));
					keyExchange = arguments.ecdhe ? KeyExchangeAlgorithm.ECDHE_PSK : KeyExchangeAlgorithm.PSK;
				} else {
					byte[] rid = new byte[8];
					SecureRandom random = new SecureRandom();
					random.nextBytes(rid);
					dtlsConfig.setPskStore(new PlugPskStore(StringUtil.byteArray2Hex(rid)));
					keyExchange = arguments.ecdhe ? KeyExchangeAlgorithm.ECDHE_PSK : KeyExchangeAlgorithm.PSK;
				}
				if (keyExchange != null) {
					dtlsConfig.setRecommendedCipherSuitesOnly(false);
					List<CipherSuite> list = CipherSuite.getCipherSuitesByKeyExchangeAlgorithm(false, keyExchange);
					dtlsConfig.setSupportedCipherSuites(list);
				}
				if (cidLength != null) {
					dtlsConfig.setConnectionIdGenerator(new SingleNodeConnectionIdGenerator(cidLength));
				}
				dtlsConfig.setSocketReceiveBufferSize(recvBufferSize); 
				dtlsConfig.setSocketSendBufferSize(sendBufferSize); 
				dtlsConfig.setClientOnly();
				dtlsConfig.setMaxConnections(maxPeers);
				dtlsConfig.setConnectionThreadCount(senderThreads);
				dtlsConfig.setReceiverThreadCount(receiverThreads);
				dtlsConfig.setStaleConnectionThreshold(staleTimeout);
				dtlsConfig.setAddress(new InetSocketAddress(coapsPort));
				DTLSConnector dtlsConnector = new DTLSConnector(dtlsConfig.build());
				if (executor != null) {
					dtlsConnector.setExecutor(executor);
				}
				builder.setConnector(dtlsConnector);
			} else if (arguments.uri.startsWith(CoAP.COAP_SECURE_TCP_URI_SCHEME + "://")) {
				builder.setConnector(new TlsClientConnector(clientSslContext, tcpThreads, tcpConnectTimeout, tlsHandshakeTimeout,
						tcpIdleTimeout));
			}
		} else if (arguments.uri.startsWith(CoAP.COAP_TCP_URI_SCHEME + "://")) {
			builder.setConnector(new TcpClientConnector(tcpThreads, tcpConnectTimeout, tcpIdleTimeout));
		} else if (arguments.uri.startsWith(CoAP.COAP_URI_SCHEME + "://")) {
			int coapPort = ephemeralPort ? 0 : config.getInt(Keys.COAP_PORT);
			builder.setConnectorWithAutoConfiguration(new UDPConnector(new InetSocketAddress(coapPort)));
		}

		builder.setNetworkConfig(config);
		CoapEndpoint endpoint = builder.build();
		if (arguments.verbose) {
			endpoint.addInterceptor(new MessageTracer());
		}
		return endpoint;
	}

	public static class PlugPskStore extends StringPskStore {

		private final String identity;
		private final SecretKey secret;

		public PlugPskStore(String id, byte[] secret) {
			this.identity = id;
			this.secret = secret == null ? null : SecretUtil.create(secret, "PSK");
			LOGGER.trace("DTLS-PSK-Identity: {}", identity);
		}

		public PlugPskStore(String id) {
			identity = PSK_IDENTITY_PREFIX + id;
			secret = null;
			LOGGER.trace("DTLS-PSK-Identity: {} ({} random bytes)", identity, (id.length() / 2));
		}

		@Override
		public SecretKey getKey(String identity) {
			if (secret != null) {
				return SecretUtil.create(secret);
			}
			if (identity.startsWith(PSK_IDENTITY_PREFIX)) {
				return SecretUtil.create(PSK_SECRET);
			}
			return null;
		}

		@Override
		public SecretKey getKey(ServerNames serverNames, String identity) {
			return getKey(identity);
		}

		@Override
		public String getIdentityAsString(InetSocketAddress inetAddress) {
			return identity;
		}

		@Override
		public String getIdentityAsString(InetSocketAddress peerAddress, ServerNames virtualHost) {
			return getIdentityAsString(peerAddress);
		}
	}

	public static class Arguments {

		public final boolean ping;
		public final boolean verbose;
		public final boolean json;
		public final boolean cbor;
		public final boolean rpk;
		public final boolean x509;
		public final boolean ecdhe;
		public final String id;
		public final String secret;
		public final String uri;
		public final String[] args;
		public final PrivateKey privateKey;
		public final PublicKey publicKey;

		/**
		 * Create new arguments instance.
		 * 
		 * @param uri     destination URI
		 * @param id      client id
		 * @param secret  client secret (PSK only). if {@code null} and
		 *                {@link ClientInitializer#PSK_IDENTITY_PREFIX} is used, use
		 *                {@link ClientInitializer#PSK_SECRET}
		 * @param rpk     {@code true}, if raw public key is preferred, {@code false},
		 *                otherwise
		 * @param x509    {@code true}, if x.509 should be used, {@code false},
		 *                otherwise
		 * @param ping    {@code true}, if client starts communication with ping,
		 *                {@code false}, otherwise
		 * @param verbose {@code true}, enable verbose mode, {@code false}, otherwise
		 * @param json    {@code true}, json content should be used, {@code false},
		 *                otherwise
		 * @param cbor    {@code true}, cbor content should be used, {@code false},
		 *                otherwise
		 * @param args    left arguments
		 */
		public Arguments(String uri, String id, String secret, boolean rpk, boolean x509, boolean ecdhe, boolean ping, boolean verbose,
				boolean json, boolean cbor, PrivateKey privateKey, PublicKey publicKey, String[] args) {
			this.uri = uri;
			this.id = id;
			this.secret = secret;
			this.rpk = rpk;
			this.x509 = x509;
			this.ecdhe = ecdhe;
			this.ping = ping;
			this.verbose = verbose;
			this.json = json;
			this.cbor = cbor;
			this.args = args;
			this.privateKey = null;
			this.publicKey = null;
		}

		/**
		 * Create arguments clone with different PSK identity and secret.
		 * 
		 * @param id     psk identity
		 * @param secret secret (PSK only). if {@code null} and
		 *               {@link ClientInitializer#PSK_IDENTITY_PREFIX} is used, use
		 *               {@link ClientInitializer#PSK_SECRET}
		 * @return create arguments clone.
		 */
		public Arguments create(String id, String secret) {
			return new Arguments(uri, id, secret, false, false, ecdhe, ping, verbose, json, cbor, privateKey, publicKey, args);
		}

		/**
		 * Create arguments clone with different ec key pair.
		 * @return create arguments clone.
		 */
		public Arguments create(PrivateKey privateKey, PublicKey publicKey) {
			return new Arguments(uri, null, null, true, false, false, ping, verbose, json, cbor, privateKey, publicKey,args);
		}
	}
}
