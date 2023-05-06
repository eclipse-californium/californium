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
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;

import javax.crypto.SecretKey;

import org.eclipse.californium.cli.ConnectorConfig.AuthenticationMode;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.SslContextUtil.Credentials;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig.Builder;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.HandshakeResultHandler;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.RecordLayer;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedPskStore;
import org.eclipse.californium.scandium.dtls.x509.SingleCertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.StaticNewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.util.ListUtils;
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

	/**
	 * TCP module initializer class.
	 * 
	 * @since 2.4
	 */
	private static final String DEFAULT_TCP_MODULE = "org.eclipse.californium.cli.tcp.netty.Initialize";

	private static final List<String> loadErrors = new ArrayList<>();
	private static final Map<String, CliConnectorFactory> connectorFactories = new ConcurrentHashMap<>();
	private static final Set<String> registeredProtocols = new TreeSet<>();

	static {
		connectorFactories.put(CoAP.PROTOCOL_UDP, new UdpConnectorFactory());
		connectorFactories.put(CoAP.PROTOCOL_DTLS, new DtlsConnectorFactory());
		String factories = StringUtil.getConfiguration("CONNECTOR_FACTORIES");
		if (factories == null) {
			factories = DEFAULT_TCP_MODULE;
		}
		if (!factories.isEmpty()) {
			String[] initializers = factories.split("#");
			for (String initializer : initializers) {
				registeredProtocols.clear();
				try {
					Class.forName(initializer);
				} catch (ClassNotFoundException e) {
					loadErrors.add(initializer);
				}
				if (!registeredProtocols.isEmpty()) {
					LOGGER.info("loaded {} - {}", initializer, registeredProtocols);
					registeredProtocols.clear();
				}
			}
		}
	}

	/**
	 * Associate the cli connector factory with the protocol.
	 * 
	 * @param protocol protocol
	 * @param factory factory
	 * @return previous associated factory, or {@code null}, if none was
	 *         previously associated.
	 * @since 2.4
	 */
	public static CliConnectorFactory registerConnectorFactory(String protocol, CliConnectorFactory factory) {
		registeredProtocols.add(protocol);
		return connectorFactories.put(protocol, factory);
	}

	/**
	 * Remove Association for the protocol.
	 * 
	 * @param protocol protocol
	 * @return associated factory, or {@code null}, if none is associated.
	 * @since 2.4
	 */
	public static CliConnectorFactory unregisterConnectorFactory(String protocol) {
		registeredProtocols.remove(protocol);
		return connectorFactories.remove(protocol);
	}

	/**
	 * Initialize client and endpoint.
	 * 
	 * @param args the arguments
	 * @param config command line configuration
	 * @throws IOException if an i/o error occurs
	 * @see #init(String[], ClientBaseConfig, boolean)
	 */
	public static void init(String[] args, ClientBaseConfig config) throws IOException {
		init(args, config, true);
	}

	/**
	 * Initialize client and optionally an endpoint.
	 * 
	 * @param args the arguments
	 * @param config command line configuration
	 * @param createEndpoint {@code true}, create endpoint and connector,
	 *            {@code false}, otherwise.
	 * @throws IOException if an i/o error occurs
	 * @see #init(String[], ClientBaseConfig)
	 * @since 2.4
	 */
	public static void init(String[] args, ClientBaseConfig config, boolean createEndpoint) throws IOException {

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
			ex.printStackTrace();
			System.err.println(ex.getMessage());
			System.err.println();
			cmd.usage(System.err);
			System.err.println();

			StringBuilder line = new StringBuilder();
			for (String arg : args) {
				line.append(arg).append(" ");
			}
			System.err.println(line);
			System.exit(-1);
		}

		if (createEndpoint) {
			registerEndpoint(config, null);
		}
	}

	/**
	 * Create and register a {@link CoapEndpoint} at the
	 * {@link EndpointManager}.
	 * 
	 * @param config client's config
	 * @param executor executor service. {@code null}, if no external executor
	 *            should be used.
	 * @throws IOException if an i/o error occurs
	 */
	public static void registerEndpoint(ClientBaseConfig config, ExecutorService executor) throws IOException {
		CoapEndpoint coapEndpoint = createEndpoint(config, null);
		coapEndpoint.start();
		LOGGER.info("endpoint started at {}", coapEndpoint.getAddress());
		EndpointManager.getEndpointManager().setDefaultEndpoint(coapEndpoint);
	}

	/**
	 * Create endpoint from client's config-arguments.
	 * 
	 * @param config client's config
	 * @param executor executor service. {@code null}, if no external executor
	 *            should be used.
	 * @return created endpoint.
	 * @throws IllegalArgumentException if scheme is not provided or not
	 *             supported
	 */
	public static CoapEndpoint createEndpoint(ClientBaseConfig config, ExecutorService executor) {

		String scheme = CoAP.getSchemeFromUri(config.uri);
		if (scheme != null) {
			String protocol = CoAP.getProtocolForScheme(scheme);
			if (protocol != null) {
				CliConnectorFactory factory = connectorFactories.get(protocol);
				if (factory != null) {
					CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
					builder.setLoggingTag(config.tag);
					Connector connector = factory.create(config, executor);
					builder.setConnector(connector);
					builder.setConfiguration(config.configuration);
					CoapEndpoint endpoint = builder.build();
					if (config.verbose) {
						endpoint.addInterceptor(new MessageTracer());
					}
					return endpoint;
				} else {
					if (CoAP.isTcpProtocol(protocol) && loadErrors.contains(DEFAULT_TCP_MODULE)) {
						throw new IllegalArgumentException(
								"Protocol '" + protocol + " is not supported! TCP-module not found!");
					} else {
						throw new IllegalArgumentException("Protocol '" + protocol + "' is not supported!");
					}
				}
			} else {
				throw new IllegalArgumentException("Scheme '" + scheme + "' is unknown!");
			}
		} else {
			throw new IllegalArgumentException("Missing scheme in " + config.uri);
		}
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

	/**
	 * UDP connector factory.
	 * 
	 * @since 2.4
	 */
	public static class UdpConnectorFactory implements CliConnectorFactory {

		@Override
		public Connector create(ClientBaseConfig clientConfig, ExecutorService executor) {
			int localPort = clientConfig.localPort == null ? 0 : clientConfig.localPort;
			return new UDPConnector(new InetSocketAddress(localPort), clientConfig.configuration);
		}
	}

	/**
	 * DTLS connector factory.
	 * 
	 * @since 2.4
	 */
	public static class DtlsConnectorFactory implements CliConnectorFactory {

		public static DtlsConnectorConfig.Builder createDtlsConfig(ClientBaseConfig clientConfig) {
			Configuration config = clientConfig.configuration;
			int localPort = clientConfig.localPort == null ? 0 : clientConfig.localPort;

			int extra = RecordLayer.IPV4_HEADER_LENGTH + 20 + Record.RECORD_HEADER_BYTES;
			Integer cidLength = clientConfig.cidLength;
			if (cidLength == null) {
				cidLength = config.get(DtlsConfig.DTLS_CONNECTION_ID_LENGTH);
			}
			if (cidLength != null) {
				extra += cidLength;
			}
			if (clientConfig.mtu != null && clientConfig.recordSizeLimit == null) {
				clientConfig.recordSizeLimit = clientConfig.mtu - extra;
			} else if (clientConfig.mtu == null && clientConfig.recordSizeLimit != null) {
				clientConfig.mtu = clientConfig.recordSizeLimit + extra;
			}

			// config.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, false);

			if (clientConfig.mtu != null) {
				config.set(DtlsConfig.DTLS_MAX_TRANSMISSION_UNIT, clientConfig.mtu);
			}
			if (clientConfig.recordSizeLimit != null) {
				config.set(DtlsConfig.DTLS_RECORD_SIZE_LIMIT, clientConfig.recordSizeLimit);
			}
			if (clientConfig.cidLength != null) {
				config.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, clientConfig.cidLength);
			}
			if (clientConfig.dtlsAutoHandshake != null) {
				config.setFromText(DtlsConfig.DTLS_AUTO_HANDSHAKE_TIMEOUT, clientConfig.dtlsAutoHandshake);
				LOGGER.info("set [{}] to {}", DtlsConfig.DTLS_AUTO_HANDSHAKE_TIMEOUT.getKey(),
						config.getAsText(DtlsConfig.DTLS_AUTO_HANDSHAKE_TIMEOUT));
			}
			if (clientConfig.noCertificatesSubjectVerification != null) {
				config.set(DtlsConfig.DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT,
						!clientConfig.noCertificatesSubjectVerification);
			}
			if (clientConfig.noServerNameIndication != null) {
				config.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, !clientConfig.noServerNameIndication);
			}
			if (clientConfig.extendedMasterSecretMode != null) {
				config.set(DtlsConfig.DTLS_EXTENDED_MASTER_SECRET_MODE, clientConfig.extendedMasterSecretMode);
			}

			DtlsConnectorConfig.Builder dtlsConfig = DtlsConnectorConfig.builder(config);
			StaticNewAdvancedCertificateVerifier.Builder verifierBuilder = StaticNewAdvancedCertificateVerifier.builder();
			boolean psk = false;
			boolean cert = false;
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
					cert = true;
					certificateTypes.add(CertificateType.RAW_PUBLIC_KEY);
					ListUtils.addIfAbsent(keyExchangeAlgorithms, KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN);
					verifierBuilder.setTrustAllRPKs();
					break;
				case X509:
					cert = true;
					certificateTypes.add(CertificateType.X_509);
					verifierBuilder.setTrustedCertificates(clientConfig.trust.trusts);
					ListUtils.addIfAbsent(keyExchangeAlgorithms, KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN);
					break;
				case ECDHE_PSK:
					psk = true;
					keyExchangeAlgorithms.add(KeyExchangeAlgorithm.ECDHE_PSK);
					break;
				}
			}
			if (cert) {
				verifierBuilder.setSupportedCertificateTypes(certificateTypes);
				dtlsConfig.setAdvancedCertificateVerifier(verifierBuilder.build());
			}

			if (clientConfig.authentication != null && clientConfig.authentication.credentials != null) {
				Credentials identity = clientConfig.authentication.credentials;
				if (certificateTypes.contains(CertificateType.X_509)) {
					dtlsConfig.setCertificateIdentityProvider(new SingleCertificateProvider(identity.getPrivateKey(),
							identity.getCertificateChain(), certificateTypes));
				} else if (certificateTypes.contains(CertificateType.RAW_PUBLIC_KEY)) {
					dtlsConfig.setCertificateIdentityProvider(
							new SingleCertificateProvider(identity.getPrivateKey(), identity.getPublicKey()));
				}
			}

			if (psk) {
				if (clientConfig.identity != null) {
					dtlsConfig
							.setAdvancedPskStore(new PlugPskStore(clientConfig.identity, clientConfig.getPskSecretKey()));
				} else {
					byte[] rid = new byte[8];
					SecureRandom random = new SecureRandom();
					random.nextBytes(rid);
					dtlsConfig.setAdvancedPskStore(new PlugPskStore(StringUtil.byteArray2Hex(rid)));
				}
			}
			if (clientConfig.cipherSuites != null && !clientConfig.cipherSuites.isEmpty()) {
				dtlsConfig.set(DtlsConfig.DTLS_CIPHER_SUITES, clientConfig.cipherSuites);
				if (clientConfig.verbose) {
					System.out.println("cipher suites:");
					print("   ", 50, clientConfig.cipherSuites, System.out);
				}
			} else if (!keyExchangeAlgorithms.isEmpty()) {
				boolean recommendedOnly = config.get(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY);
				List<CipherSuite> preselect = config.get(DtlsConfig.DTLS_PRESELECTED_CIPHER_SUITES);
				List<CipherSuite> keyExchange = CipherSuite.getCipherSuitesByKeyExchangeAlgorithm(recommendedOnly, true,
						keyExchangeAlgorithms);
				if (preselect != null && !preselect.isEmpty()) {
					keyExchange = CipherSuite.preselectCipherSuites(preselect, keyExchange);
				}
				dtlsConfig.set(DtlsConfig.DTLS_PRESELECTED_CIPHER_SUITES, keyExchange);
			}
			dtlsConfig.setAddress(new InetSocketAddress(localPort));
			return dtlsConfig;
		}

		@Override
		public Connector create(ClientBaseConfig clientConfig, ExecutorService executor) {
			Builder dtlsConfig = createDtlsConfig(clientConfig);
			DTLSConnector dtlsConnector = new DTLSConnector(dtlsConfig.build());
			if (executor != null) {
				dtlsConnector.setExecutor(executor);
			}
			return dtlsConnector;
		}
	}

	public static class PlugPskStore implements AdvancedPskStore {

		private final PskPublicInformation identity;
		private final SecretKey secret;

		public PlugPskStore(String id, byte[] secret) {
			this.identity = new PskPublicInformation(id);
			this.secret = secret == null ? ConnectorConfig.PSK_SECRET
					: SecretUtil.create(secret, PskSecretResult.ALGORITHM_PSK);
			LOGGER.trace("DTLS-PSK-Identity: {}", identity);
		}

		public PlugPskStore(String id, SecretKey secret) {
			this.identity = new PskPublicInformation(id);
			this.secret = secret == null ? ConnectorConfig.PSK_SECRET : SecretUtil.create(secret);
			LOGGER.trace("DTLS-PSK-Identity: {}", identity);
		}

		public PlugPskStore(String id) {
			identity = new PskPublicInformation(ConnectorConfig.PSK_IDENTITY_PREFIX + id);
			secret = null;
			LOGGER.trace("DTLS-PSK-Identity: {} ({} random bytes)", identity, (id.length() / 2));
		}

		@Override
		public boolean hasEcdhePskSupported() {
			return true;
		}

		@Override
		public PskSecretResult requestPskSecretResult(ConnectionId cid, ServerNames serverName,
				PskPublicInformation identity, String hmacAlgorithm, SecretKey otherSecret, byte[] seed,
				boolean useExtendedMasterSecret) {

			SecretKey secret = null;
			if (this.identity.equals(identity)) {
				if (this.secret == null
						&& identity.getPublicInfoAsString().startsWith(ConnectorConfig.PSK_IDENTITY_PREFIX)) {
					secret = SecretUtil.create(ConnectorConfig.PSK_SECRET);
				} else {
					secret = SecretUtil.create(this.secret);
				}
			}
			return new PskSecretResult(cid, this.identity, secret);
		}

		@Override
		public PskPublicInformation getIdentity(InetSocketAddress peerAddress, ServerNames virtualHost) {
			return identity;
		}

		@Override
		public void setResultHandler(HandshakeResultHandler resultHandler) {
		}
	}
}
