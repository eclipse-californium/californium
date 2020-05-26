/*******************************************************************************
 * Copyright (c) 2017, 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove MAC usage for
 *                                                    PSK identity.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add argument -i (identity)
 *    Achim Kraus (Bosch Software Innovations GmbH) - add createEndpoint to create
 *                                                    more client endpoints.
 *    Achim Kraus (Bosch.IO GmbH)                   - moved from cf-plugtest-client
 ******************************************************************************/
package org.eclipse.californium.cli;

import java.io.IOException;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSessionContext;

import org.eclipse.californium.cli.ConnectorConfig.AuthenticationMode;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.tcp.netty.TcpClientConnector;
import org.eclipse.californium.elements.tcp.netty.TlsClientConnector;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.SingleNodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.dtls.pskstore.StringPskStore;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.scandium.util.ServerNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import picocli.CommandLine;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.ParseResult;

/**
 * Client initializer.
 */
public class ClientInitializer {

	private static final Logger LOGGER = LoggerFactory.getLogger(ClientInitializer.class);

	public static final String KEY_DTLS_RETRANSMISSION_TIMEOUT = "DTLS_RETRANSMISSION_TIMEOUT";

	public static final String PSK_IDENTITY_PREFIX = "cali.";

	private static final char[] KEY_STORE_PASSWORD = "endPass".toCharArray();
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	private static final char[] TRUST_STORE_PASSWORD = "rootPass".toCharArray();
	private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";
	private static final String CLIENT_NAME = "client";
	private static final SecretKey PSK_SECRET = SecretUtil.create(".fornium".getBytes(), "PSK");

	private static SslContextUtil.Credentials clientCredentials = null;
	private static Certificate[] trustedCertificates = null;

	private static String defaultIdentity;
	private static String defaultSecret;

	/**
	 * Set default PSK credentials
	 * 
	 * @param identity default identity. If {@code null}, use
	 *            {@link #PSK_IDENTITY_PREFIX} as default.
	 * @param secret default secret. If {@code null}, use {@link #PSK_SECRET} as
	 *            default.
	 */
	public static void setDefaultPskCredentials(String identity, String secret) {
		defaultIdentity = identity;
		defaultSecret = secret;
	}

	/**
	 * Initialize client.
	 * 
	 * @param args the arguments
	 * @param config command line configuration
	 * @param ephemeralPort {@code true}, use ephemeral port, {@code false} use
	 *            port from network configuration.
	 * @throws IOException if an i/o error occurs
	 */
	public static void init(String[] args, ClientBaseConfig config, boolean ephemeralPort) throws IOException {

		CommandLine cmd = new CommandLine(config);
		config.register(cmd);
		try {
			ParseResult result = cmd.parseArgs(args);
			if (result.isVersionHelpRequested()) {
				String version = StringUtil.CALIFORNIUM_VERSION == null ? "" : StringUtil.CALIFORNIUM_VERSION;
				System.out.println("\nCalifornium (Cf) " + cmd.getCommandName() + " " + version);
				cmd.printVersionHelp(System.out);
				System.out.println();
			}
			config.defaults();
			if (config.helpRequested) {
				cmd.usage(System.out);
				if (config.authHelpRequested) {
					System.out.println();
					System.out.println("   --auth: values");
					print("      ", ConnectorConfig.MAX_WIDTH, Arrays.asList(AuthenticationMode.values()), System.out);
				}
				if (config.cipherHelpRequested) {
					List<CipherSuite> list = new ArrayList<CipherSuite>();
					for (CipherSuite cipherSuite : CipherSuite.values()) {
						if (cipherSuite.isSupported() && !CipherSuite.TLS_NULL_WITH_NULL_NULL.equals(cipherSuite)) {
							list.add(cipherSuite);
						}
					}
					System.out.println();
					System.out.println("   --cipher: values");
					print("      ", ConnectorConfig.MAX_WIDTH, list, System.out);
				}
				return;
			}
		} catch (ParameterException ex) {
			System.err.println(ex.getMessage());
			System.err.println();
			cmd.usage(System.err);
			System.exit(-1);
		}

		if (config.secure && (config.identity == null && config.secret == null)) {
			config.identity = defaultIdentity;
			config.secret = new ConnectorConfig.Secret();
			config.secret.text = defaultSecret;
			if (config.authenticationModes.isEmpty()) {
				config.authenticationModes.add(AuthenticationMode.PSK);
			}
		}

		CoapEndpoint coapEndpoint = createEndpoint(config, null, ephemeralPort);
		coapEndpoint.start();
		LOGGER.info("endpoint started at {}", coapEndpoint.getAddress());
		EndpointManager.getEndpointManager().setDefaultEndpoint(coapEndpoint);
	}

	/**
	 * Create endpoint from arguments.
	 * 
	 * @param arguments arguments
	 * @param executor executor service. {@code null}, if no external executor
	 *            should be used.
	 * @param ephemeralPort {@code true}, use ephemeral port, {@code false} use
	 *            port from network configuration.
	 * @return created endpoint.
	 */
	public static CoapEndpoint createEndpoint(ClientBaseConfig clientConfig, ExecutorService executor,
			boolean ephemeralPort) {
		NetworkConfig config = clientConfig.networkConfig;
		int tcpThreads = config.getInt(Keys.TCP_WORKER_THREADS);
		int tcpConnectTimeout = config.getInt(Keys.TCP_CONNECT_TIMEOUT);
		int tlsHandshakeTimeout = config.getInt(Keys.TLS_HANDSHAKE_TIMEOUT);
		int tcpIdleTimeout = config.getInt(Keys.TCP_CONNECTION_IDLE_TIMEOUT);
		int maxPeers = config.getInt(Keys.MAX_ACTIVE_PEERS);
		int sessionTimeout = config.getInt(Keys.SECURE_SESSION_TIMEOUT);
		int staleTimeout = config.getInt(Keys.MAX_PEER_INACTIVITY_PERIOD);
		int senderThreads = config.getInt(Keys.NETWORK_STAGE_SENDER_THREAD_COUNT);
		int receiverThreads = config.getInt(Keys.NETWORK_STAGE_RECEIVER_THREAD_COUNT);
		int retransmissionTimeout = config.getInt(Keys.ACK_TIMEOUT);
		Integer healthStatusInterval = config.getInt(Keys.HEALTH_STATUS_INTERVAL); // seconds
		Integer cidLength = config.getOptInteger(Keys.DTLS_CONNECTION_ID_LENGTH);
		Integer recvBufferSize = config.getOptInteger(Keys.UDP_CONNECTOR_RECEIVE_BUFFER);
		Integer sendBufferSize = config.getOptInteger(Keys.UDP_CONNECTOR_SEND_BUFFER);
		Integer dtlsRetransmissionTimeout = config.getOptInteger(KEY_DTLS_RETRANSMISSION_TIMEOUT);
		if (dtlsRetransmissionTimeout != null) {
			retransmissionTimeout = dtlsRetransmissionTimeout;
		}

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		if (clientConfig.uri.startsWith(CoAP.COAP_SECURE_URI_SCHEME)) {
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
			if (clientConfig.uri.startsWith(CoAP.COAP_SECURE_URI_SCHEME + "://")) {
				int coapsPort = ephemeralPort ? 0 : config.getInt(Keys.COAP_SECURE_PORT);
				DtlsConnectorConfig.Builder dtlsConfig = new DtlsConnectorConfig.Builder();
				boolean psk = false;
				List<KeyExchangeAlgorithm> keyExchangeAlgorithms = new ArrayList<KeyExchangeAlgorithm>();
				List<CertificateType> certificateTypes = new ArrayList<CertificateType>();
				for (ConnectorConfig.AuthenticationMode auth : clientConfig.authenticationModes) {
					switch (auth) {
					case NONE:
						break;
					case PSK:
						psk = true;
						keyExchangeAlgorithms.add(KeyExchangeAlgorithm.PSK);
						break;
					case RPK:
						certificateTypes.add(CertificateType.RAW_PUBLIC_KEY);
						keyExchangeAlgorithms.add(KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN);
						dtlsConfig.setRpkTrustAll();
						break;
					case X509:
						certificateTypes.add(CertificateType.X_509);
						dtlsConfig.setTrustStore(trustedCertificates);
						keyExchangeAlgorithms.add(KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN);
						break;
					case ECDHE_PSK:
						psk = true;
						keyExchangeAlgorithms.add(KeyExchangeAlgorithm.ECDHE_PSK);
						break;
					}
				}

				if (!certificateTypes.isEmpty()) {
					dtlsConfig.setIdentity(clientCredentials.getPrivateKey(), clientCredentials.getCertificateChain(),
							certificateTypes);
				}

				if (psk) {
					if (clientConfig.identity != null) {
						dtlsConfig.setPskStore(new PlugPskStore(clientConfig.identity, clientConfig.secretKey));
					} else {
						byte[] rid = new byte[8];
						SecureRandom random = new SecureRandom();
						random.nextBytes(rid);
						dtlsConfig.setPskStore(new PlugPskStore(StringUtil.byteArray2Hex(rid)));
					}
				}
				if (!keyExchangeAlgorithms.isEmpty()) {
					if (clientConfig.cipherSuites == null || clientConfig.cipherSuites.isEmpty()) {
						clientConfig.cipherSuites = CipherSuite.getCipherSuitesByKeyExchangeAlgorithm(false, true,
								keyExchangeAlgorithms);
					}
				}
				if (clientConfig.cipherSuites != null && !clientConfig.cipherSuites.isEmpty()) {
					dtlsConfig.setRecommendedCipherSuitesOnly(false);
					dtlsConfig.setSupportedCipherSuites(clientConfig.cipherSuites);
					if (clientConfig.verbose) {
						System.out.println("cipher suites:");
						print("   ", 50, clientConfig.cipherSuites, System.out);
					}
				}

				if (cidLength != null) {
					dtlsConfig.setConnectionIdGenerator(new SingleNodeConnectionIdGenerator(cidLength));
				}
				dtlsConfig.setSocketReceiveBufferSize(recvBufferSize);
				dtlsConfig.setSocketSendBufferSize(sendBufferSize);
				dtlsConfig.setClientOnly();
				dtlsConfig.setRetransmissionTimeout(retransmissionTimeout);
				dtlsConfig.setMaxConnections(maxPeers);
				dtlsConfig.setConnectionThreadCount(senderThreads);
				dtlsConfig.setReceiverThreadCount(receiverThreads);
				dtlsConfig.setStaleConnectionThreshold(staleTimeout);
				dtlsConfig.setAddress(new InetSocketAddress(coapsPort));
				dtlsConfig.setHealthStatusInterval(healthStatusInterval);
				DTLSConnector dtlsConnector = new DTLSConnector(dtlsConfig.build());
				if (executor != null) {
					dtlsConnector.setExecutor(executor);
				}
				builder.setConnector(dtlsConnector);
			} else if (clientConfig.uri.startsWith(CoAP.COAP_SECURE_TCP_URI_SCHEME + "://")) {
				builder.setConnector(new TlsClientConnector(clientSslContext, tcpThreads, tcpConnectTimeout,
						tlsHandshakeTimeout, tcpIdleTimeout));
			}
		} else if (clientConfig.uri.startsWith(CoAP.COAP_TCP_URI_SCHEME + "://")) {
			builder.setConnector(new TcpClientConnector(tcpThreads, tcpConnectTimeout, tcpIdleTimeout));
		} else if (clientConfig.uri.startsWith(CoAP.COAP_URI_SCHEME + "://")) {
			int coapPort = ephemeralPort ? 0 : config.getInt(Keys.COAP_PORT);
			builder.setConnectorWithAutoConfiguration(new UDPConnector(new InetSocketAddress(coapPort)));
		}

		builder.setNetworkConfig(config);
		CoapEndpoint endpoint = builder.build();
		if (clientConfig.verbose) {
			endpoint.addInterceptor(new MessageTracer());
		}
		return endpoint;
	}

	public static void print(String tab, int width, List<?> values, PrintStream out) {
		StringBuilder line = new StringBuilder();
		line.append(tab);
		for (Object value : values) {
			String name = value.toString();
			if (line.length() + name.length() > width) {
				out.println(line);
				line.setLength(tab.length());
			}
			line.append(name).append(" ");
		}
		out.println(line);
	}

	public static class PlugPskStore extends StringPskStore {

		private final String identity;
		private final SecretKey secret;

		public PlugPskStore(String id, byte[] secret) {
			this.identity = id;
			this.secret = secret == null ? PSK_SECRET : SecretUtil.create(secret, "PSK");
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
}
