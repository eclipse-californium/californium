/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.cloud;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.cloud.http.HttpService;
import org.eclipse.californium.cloud.http.HttpService.CoapProxyHandler;
import org.eclipse.californium.cloud.http.HttpService.ForwardHandler;
import org.eclipse.californium.cloud.resources.Devices;
import org.eclipse.californium.cloud.resources.Diagnose;
import org.eclipse.californium.cloud.resources.MyContext;
import org.eclipse.californium.cloud.util.DeviceGredentialsProvider;
import org.eclipse.californium.cloud.util.DeviceManager;
import org.eclipse.californium.cloud.util.DeviceParser;
import org.eclipse.californium.cloud.util.ResourceStore;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.config.CoapConfig.MatcherMode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.interceptors.HealthStatisticLogger;
import org.eclipse.californium.core.observe.ObserveStatisticLogger;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.PrincipalEndpointContextMatcher;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.config.IntegerDefinition;
import org.eclipse.californium.elements.config.SystemConfig;
import org.eclipse.californium.elements.config.TimeDefinition;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.CounterStatisticManager;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.EncryptedPersistentComponentUtil;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil.InetAddressFilter;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil.SimpleInetAddressFilter;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.SslContextUtil.Credentials;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.elements.util.SystemResourceMonitors;
import org.eclipse.californium.elements.util.SystemResourceMonitors.SystemResourceMonitor;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.DtlsHealthLogger;
import org.eclipse.californium.scandium.MdcConnectionListener;
import org.eclipse.californium.scandium.auth.ApplicationLevelInfoSupplier;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConfig.DtlsRole;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedPskStore;
import org.eclipse.californium.scandium.dtls.x509.CertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.NewAdvancedCertificateVerifier;
import org.eclipse.californium.unixhealth.NetSocketHealthLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import picocli.CommandLine;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.ParseResult;

/**
 * The basic cloud server.
 * 
 * Creates {@link Endpoint}s using DTLS. Adds resources {@link Diagnose} and
 * {@link MyContext}.
 * 
 * @since 3.12
 */
public class BaseServer extends CoapServer {

	static {
		// only coap + dtls
		CoapConfig.register();
		DtlsConfig.register();
	}

	private static final Logger LOGGER = LoggerFactory.getLogger(CoapServer.class);
	private static final Logger STATISTIC_LOGGER = LoggerFactory.getLogger("org.eclipse.californium.statistics");

	private static final int DEFAULT_MAX_CONNECTIONS = 200000;
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 8192;
	private static final int DEFAULT_MAX_MESSAGE_SIZE = 1280;
	private static final int DEFAULT_BLOCK_SIZE = 1024;

	/**
	 * Name of private key file for DTLS 1.2 (device communication).
	 */
	public static final String DTLS_PRIVATE_KEY = "privkey.pem";
	/**
	 * Name of public key file for DTLS 1.2 (device communication).
	 */
	public static final String DTLS_PUBLIC_KEY = "pubkey.pem";

	// exit codes for runtime errors
	public static final int ERR_INIT_FAILED = 1;

	public static final List<CipherSuite> PRESELECTED_CIPHER_SUITES = Arrays.asList(
			CipherSuite.TLS_PSK_WITH_AES_128_CCM_8, CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256,
			CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256,
			CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);

	public enum InterfaceType {
		LOCAL, EXTERNAL, IPV4, IPV6,
	}

	/**
	 * Interval to read number of dropped UDP messages.
	 */
	public static final TimeDefinition UDP_DROPS_READ_INTERVAL = new TimeDefinition("UDP_DROPS_READ_INTERVAL",
			"Interval to read UDP drops from OS (currently only Linux).", 2000, TimeUnit.MILLISECONDS);
	/**
	 * Maximum device in cache.
	 */
	public static final IntegerDefinition CACHE_MAX_DEVICES = new IntegerDefinition("CACHE_MAX_DEVICES",
			"Cache maximum devices.", 5000, 100);
	/**
	 * Threshold for stale devices.
	 */
	public static final TimeDefinition CACHE_STALE_DEVICE_THRESHOLD = new TimeDefinition("CACHE_STALE_DEVICE_THRESHOLD",
			"Threshold for stale devices. Devices will only get removed for new ones, "
					+ "if at least for that threshold no messages are exchanged with that device.",
			24, TimeUnit.HOURS);
	/**
	 * Interval to reload HTTPS credentials.
	 */
	public static final TimeDefinition HTTPS_CREDENTIALS_RELOAD_INTERVAL = new TimeDefinition(
			"HTTPS_CREDENTIALS_RELOAD_INTERVAL",
			"Reload HTTPS credentials interval. 0 to load credentials only on startup.", 30, TimeUnit.MINUTES);
	/**
	 * Interval to reload device credentials.
	 */
	public static final TimeDefinition DEVICE_CREDENTIALS_RELOAD_INTERVAL = new TimeDefinition(
			"DEVICE_CREDENTIALS_RELOAD_INTERVAL",
			"Reload device credentials interval. 0 to load credentials only on startup.", 60, TimeUnit.SECONDS);

	/**
	 * Default configuration setup.
	 * 
	 * @see Configuration#createWithFile(File, String, DefinitionsProvider)
	 */
	public static DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			int processors = Runtime.getRuntime().availableProcessors();
			config.set(SystemConfig.HEALTH_STATUS_INTERVAL, 300, TimeUnit.SECONDS);
			config.set(CoapConfig.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.set(CoapConfig.MAX_MESSAGE_SIZE, DEFAULT_MAX_MESSAGE_SIZE);
			config.set(CoapConfig.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.NOTIFICATION_CHECK_INTERVAL_COUNT, 4);
			config.set(CoapConfig.NOTIFICATION_CHECK_INTERVAL_TIME, 30, TimeUnit.SECONDS);
			config.set(CoapConfig.MAX_ACTIVE_PEERS, DEFAULT_MAX_CONNECTIONS);
			config.set(CoapConfig.PEERS_MARK_AND_SWEEP_MESSAGES, 16);
			config.set(CoapConfig.DEDUPLICATOR, CoapConfig.DEDUPLICATOR_PEERS_MARK_AND_SWEEP);
			config.set(CoapConfig.RESPONSE_MATCHING, MatcherMode.PRINCIPAL_IDENTITY);
			config.set(CoapConfig.ACK_TIMEOUT, 2500, TimeUnit.MILLISECONDS);
			config.set(DtlsConfig.DTLS_ROLE, DtlsRole.SERVER_ONLY);
			config.set(DtlsConfig.DTLS_RETRANSMISSION_TIMEOUT, 2500, TimeUnit.MILLISECONDS);
			config.set(DtlsConfig.DTLS_ADDITIONAL_ECC_TIMEOUT, 8, TimeUnit.SECONDS);
			config.set(DtlsConfig.DTLS_AUTO_HANDSHAKE_TIMEOUT, null, TimeUnit.SECONDS);
			config.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 6);
			config.set(DtlsConfig.DTLS_PRESELECTED_CIPHER_SUITES, PRESELECTED_CIPHER_SUITES);
			config.set(DtlsConfig.DTLS_MAX_CONNECTIONS, DEFAULT_MAX_CONNECTIONS);
			config.set(DtlsConfig.DTLS_REMOVE_STALE_DOUBLE_PRINCIPALS, true);
			config.set(DtlsConfig.DTLS_SERVER_USE_SESSION_ID, false);
			config.set(DtlsConfig.DTLS_RECEIVE_BUFFER_SIZE, 1000000);
			config.set(DtlsConfig.DTLS_RECEIVER_THREAD_COUNT, processors > 3 ? 2 : 1);
			config.set(DtlsConfig.DTLS_MAC_ERROR_FILTER_QUIET_TIME, 4, TimeUnit.SECONDS);
			config.set(DtlsConfig.DTLS_MAC_ERROR_FILTER_THRESHOLD, 8);
			config.set(UDP_DROPS_READ_INTERVAL, 2000, TimeUnit.MILLISECONDS);
			config.set(CACHE_MAX_DEVICES, 5000);
			config.set(CACHE_STALE_DEVICE_THRESHOLD, 24, TimeUnit.HOURS);
			config.set(HTTPS_CREDENTIALS_RELOAD_INTERVAL, 30, TimeUnit.MINUTES);
			config.set(DEVICE_CREDENTIALS_RELOAD_INTERVAL, 30, TimeUnit.SECONDS);
		}
	};

	public static class ServerConfig {

		@Option(names = { "-h", "--help" }, usageHelp = true, description = "display a help message")
		public boolean helpRequested;

		@ArgGroup(exclusive = true)
		public NetworkConfig network;

		public static class NetworkConfig {

			@Option(names = "--wildcard-interface", description = "Use local wildcard-address for coap endpoints.")
			public boolean wildcard;

			@ArgGroup(exclusive = false)
			public NetworkSelectConfig selectInterfaces;
		}

		public static class NetworkSelectConfig {

			@Option(names = "--no-loopback", negatable = true, description = "enable coap endpoints on loopback network.")
			public boolean loopback = true;

			@Option(names = "--no-external", negatable = true, description = "enable coap endpoints on external network.")
			public boolean external = true;

			@Option(names = "--no-ipv4", negatable = true, description = "enable coap endpoints for ipv4.")
			public boolean ipv4 = true;

			@Option(names = "--no-ipv6", negatable = true, description = "enable coap endpoints for ipv6.")
			public boolean ipv6 = true;

			@Option(names = "--interfaces-pattern", split = ",", description = "interface regex patterns for coap endpoints.")
			public List<String> interfacePatterns;

			public InetAddressFilter getFilter(String tag) {
				if (interfacePatterns == null || interfacePatterns.isEmpty()) {
					return new SimpleInetAddressFilter(tag, external, loopback, ipv4, ipv6);
				} else {
					String[] patterns = new String[interfacePatterns.size()];
					patterns = interfacePatterns.toArray(patterns);
					return new SimpleInetAddressFilter(tag, external, loopback, ipv4, ipv6, patterns);
				}
			}
		}

		@ArgGroup(exclusive = false)
		public HttpsConfig https;

		public static class HttpsConfig {

			@Option(names = "--https-port", required = true, description = "Port of https service.")
			public int port;

			@Option(names = "--https-credentials", required = true, description = "Folder containing https credentials in 'privkey.pem' and 'fullchain.pem'.")
			public String credentials;

			@Option(names = "--https-password64", description = "Folder containing https credentials in 'privkey.pem' and 'fullchain.pem'.")
			public String password64;
		}

		@ArgGroup(exclusive = false)
		public CoapsConfig coaps;

		public static class CoapsConfig {

			@Option(names = "--coaps-credentials", required = true, description = "Folder containing coaps credentials in 'privkey.pem' and 'pubkey.pem'")
			public String credentials;

			@Option(names = "--coaps-password64", required = false, description = "Password for device store. Base 64 encoded.")
			public String password64;

		}

		@ArgGroup(exclusive = false)
		public DeviceStore deviceStore;

		public static class DeviceStore {

			@Option(names = "--device-file", required = true, description = "Filename of device store for coap.")
			public String file;

			@Option(names = "--device-file-password64", required = false, description = "Password for device store. Base 64 encoded.")
			public String password64;

		}

		@ArgGroup(exclusive = false)
		public Store store;

		public static class Store {

			@Option(names = "--store-file", required = true, description = "file-store for dtls state.")
			public String file;

			@Option(names = "--store-max-age", required = true, description = "maximum age of connections in hours to store dtls state.")
			public Integer maxAge;

			@Option(names = "--store-password64", required = false, description = "password to store dtls state. Base 64 encoded.")
			public String password64;

		}

		@Option(names = "--diagnose", description = "enable 'diagnose'-resource.")
		public boolean diagnose;

		public boolean noCoap;

		/**
		 * Setup dependent defaults.
		 */
		public void defaults() {
			if (network == null) {
				network = new NetworkConfig();
				network.wildcard = true;
			}
		}
	}

	public static final String CALIFORNIUM_BUILD_VERSION;

	static {
		String version = StringUtil.CALIFORNIUM_VERSION;
		if (version != null) {
			String build = StringUtil.readFile(new File("build"), null);
			if (build != null && !build.isEmpty()) {
				version = version + "_" + build;
			}
		} else {
			version = "";
		}
		CALIFORNIUM_BUILD_VERSION = version;
	}

	private static String toLog(PublicKey key) {
		byte[] data = key.getEncoded();
		return StringUtil.byteArray2Hex(Arrays.copyOfRange(data, data.length - 6, data.length));
	}

	public static void start(String[] args, String name, ServerConfig cliArguments, BaseServer server) {

		CommandLine cmd = new CommandLine(cliArguments);
		try {
			ParseResult result = cmd.parseArgs(args);
			if (result.isVersionHelpRequested()) {
				System.out.println("\nCalifornium (Cf) " + cmd.getCommandName() + " " + CALIFORNIUM_BUILD_VERSION);
				cmd.printVersionHelp(System.out);
				System.out.println();
			}
			if (result.isUsageHelpRequested()) {
				cmd.usage(System.out);
				return;
			}
		} catch (ParameterException ex) {
			System.err.println(ex.getMessage());
			System.err.println();
			cmd.usage(System.err);
			System.exit(-1);
		}

		cliArguments.defaults();

		// print startup message
		long max = Runtime.getRuntime().maxMemory();
		StringBuilder builder = new StringBuilder(name);
		if (!CALIFORNIUM_BUILD_VERSION.isEmpty()) {
			builder.append(", version ").append(CALIFORNIUM_BUILD_VERSION);
		}
		builder.append(", ").append(max / (1024 * 1024)).append("MB heap, started ...");
		LOGGER.info("{}", builder);

		// management statistic
		STATISTIC_LOGGER.error("start!");
		ManagementStatistic management = new ManagementStatistic(STATISTIC_LOGGER);

		boolean http = false;
		if (cliArguments.https != null) {
			if (cliArguments.https.port > 0) {
				LOGGER.info("Create HTTPS service at port {}, credentials {}", cliArguments.https.port,
						cliArguments.https.credentials);
				http = HttpService.createHttpService(cliArguments.https.port, cliArguments.https.credentials,
						cliArguments.https.password64, false);
			} else {
				LOGGER.info("HTTPS service at port {} is not supported! Must be [1-65535]", cliArguments.https.port);
			}
		}

		// create server
		try {
			server.initialize(cliArguments);
			if (!cliArguments.noCoap && server.getEndpoints().isEmpty()) {
				System.err.println("no endpoint available!");
				System.exit(ERR_INIT_FAILED);
			}
		} catch (Exception e) {
			System.err.printf("Failed to create " + BaseServer.class.getSimpleName() + ": %s\n", e.getMessage());
			e.printStackTrace(System.err);
			System.err.println("Exiting");
			System.exit(ERR_INIT_FAILED);
		}

		if (cliArguments.store != null) {
			server.setupPersistence(cliArguments.store);
		}

		server.start();

		LOGGER.info("{} started ...", name);

		if (http) {
			if (HttpService.startHttpService()) {
				LOGGER.info("HTTPS service at port {} started", cliArguments.https.port);
				long interval = server.getConfig().get(HTTPS_CREDENTIALS_RELOAD_INTERVAL, TimeUnit.MINUTES);
				SystemResourceMonitor httpsCredentialsMonitor = HttpService.getHttpService().getFileMonitor();
				server.monitors.addOptionalMonitor("https credentials", interval, TimeUnit.MINUTES,
						httpsCredentialsMonitor);
			}
		}
		long interval = server.getConfig().get(SystemConfig.HEALTH_STATUS_INTERVAL, TimeUnit.MILLISECONDS);
		long inputTimeout = interval < 15000 ? interval : 15000;
		long lastGcCount = 0;
		long lastDumpNanos = ClockUtil.nanoRealtime();
		for (;;) {
			try {
				Thread.sleep(inputTimeout);
			} catch (InterruptedException e) {
				break;
			}
			long gcCount = management.getCollectionCount();
			if (lastGcCount < gcCount) {
				management.printManagementStatistic();
				lastGcCount = gcCount;
				long clones = DatagramWriter.COPIES.get();
				long takes = DatagramWriter.TAKES.get();
				if (clones + takes > 0) {
					STATISTIC_LOGGER.info("DatagramWriter {} clones, {} takes, {}%", clones, takes,
							(takes * 100L) / (takes + clones));
				}
			}
			long now = ClockUtil.nanoRealtime();
			if ((now - lastDumpNanos - TimeUnit.MILLISECONDS.toNanos(interval)) > 0) {
				lastDumpNanos = now;
				server.dump();
			}
		}
		LOGGER.info("Executor shutdown ...");
		if (http) {
			HttpService.stopHttpService();
			LOGGER.info("HTTPS service at port {} stopped", cliArguments.https.port);
		}
		server.stop();
		server.destroy();
		exit();
		LOGGER.info("Exit ...");
	}

	public static void exit() {
		int count = Thread.activeCount();
		while (count > 0) {
			int size = Thread.activeCount();
			Thread[] all = new Thread[size];
			int available = Thread.enumerate(all);
			if (available < size) {
				size = available;
			}
			count = 0;
			for (int index = 0; index < size; ++index) {
				Thread thread = all[index];
				if (!thread.isDaemon() && thread.isAlive()) {
					++count;
					LOGGER.info("Thread [{}] {}", thread.getId(), thread.getName());
				}
			}
			if (count == 1) {
				break;
			}
			try {
				Thread.sleep(500);
			} catch (InterruptedException e) {
				break;
			}
		}
	}

	protected SystemResourceMonitors monitors;

	protected DeviceGredentialsProvider deviceCredentials;

	public BaseServer(Configuration config) {
		super(config);
		setVersion(CALIFORNIUM_BUILD_VERSION);
		setTag("CLOUD-DEMO");
	}

	@Override
	public void start() {
		if (!getEndpoints().isEmpty()) {
			super.start();
		}
		monitors.start();
	}

	@Override
	public void stop() {
		if (!getEndpoints().isEmpty()) {
			super.stop();
		}
		monitors.stop();
	}

	/**
	 * Initialize demo server.
	 * 
	 * @param cliArguments command line arguments
	 * @throws SocketException if an I/O error occurred.
	 */
	public void initialize(ServerConfig cliArguments) throws SocketException {
		Configuration config = getConfig();
		// executors
		ScheduledExecutorService secondaryExecutor = ExecutorsUtil
				.newDefaultSecondaryScheduler("CoapServer(secondary)#");

		monitors = new SystemResourceMonitors(secondaryExecutor);

		setupDeviceCredentials(cliArguments);

		if (!cliArguments.noCoap) {
			addEndpoints(cliArguments);

			ScheduledExecutorService executor = ExecutorsUtil.newScheduledThreadPool(//
					config.get(CoapConfig.PROTOCOL_STAGE_THREAD_COUNT), //
					new NamedThreadFactory("CoapServer(main)#")); //$NON-NLS-1$
			addResource(cliArguments, executor);

			setExecutors(executor, secondaryExecutor, false);

			// additional health loggers
			setupUdpHealthLogger(secondaryExecutor);
			setupObserveHealthLogger();
		}
		setupHttpService(cliArguments);

		LOGGER.info("{} initialized.", getTag());
	}

	/**
	 * Setup device credentials.
	 * 
	 * Load the private and public key of the DTLS 1.2 server for the device
	 * communication and the device credentials.
	 * 
	 * @param cliArguments command line arguments.
	 */
	public void setupDeviceCredentials(ServerConfig cliArguments) {
		PrivateKey privateKey = null;
		PublicKey publicKey = null;
		if (cliArguments.coaps != null) {
			try {
				String path = cliArguments.coaps.credentials;
				if (!path.endsWith("/")) {
					path += "/";
				}
				String privateKeyPath = path + DTLS_PRIVATE_KEY;
				Credentials credentials = SslContextUtil.loadCredentials(privateKeyPath, null, null, null);
				privateKey = credentials.getPrivateKey();
				publicKey = credentials.getPublicKey();
				if (privateKey == null) {
					LOGGER.info("PEM credentials {}, missing private key!", privateKeyPath);
				} else if (publicKey != null) {
					LOGGER.info("PEM credentials {}, public key: ...{}", privateKeyPath, toLog(publicKey));
				} else {
					String publicKeyPath = path + DTLS_PUBLIC_KEY;
					credentials = SslContextUtil.loadCredentials(publicKeyPath, null, null, null);
					publicKey = credentials.getPublicKey();
					if (publicKey != null) {
						LOGGER.info("PEM credentials {}, public key: ...{}", publicKeyPath, toLog(publicKey));
					} else {
						LOGGER.info("PEM credentials {}, missing public key!", publicKeyPath);
					}
				}
			} catch (IOException e) {
				LOGGER.info("Loading PEM credentials failed", e);
			} catch (GeneralSecurityException e) {
				LOGGER.info("Loading PEM credentials failed", e);
			}
		}
		setupDeviceCredentials(cliArguments, privateKey, publicKey);
	}

	/**
	 * Setup device credentials.
	 * 
	 * Load the device credentials.
	 * 
	 * @param cliArguments command line arguments.
	 * @param privateKey private key for DTLS 1.2 device communication.
	 * @param publicKey public key for DTLS 1.2 device communication.
	 */
	public void setupDeviceCredentials(ServerConfig cliArguments, PrivateKey privateKey, PublicKey publicKey) {
		if (cliArguments.deviceStore != null) {
			long interval = getConfig().get(DEVICE_CREDENTIALS_RELOAD_INTERVAL, TimeUnit.SECONDS);
			DeviceParser factory = new DeviceParser(true);
			ResourceStore<DeviceParser> configResource = new ResourceStore<>(factory).setTag("Devices ");
			configResource.loadAndCreateMonitor(cliArguments.deviceStore.file, cliArguments.deviceStore.password64,
					interval > 0);
			monitors.addMonitor("Devices", interval, TimeUnit.SECONDS, configResource.getMonitor());
			deviceCredentials = new DeviceManager(configResource, privateKey, publicKey);
		} else {
			deviceCredentials = new DeviceManager(null, privateKey, publicKey);
		}
	}

	/**
	 * Add CoAP endpoints.
	 * 
	 * @param cliArguments command line arguments.
	 */
	public void addEndpoints(ServerConfig cliArguments) {
		Configuration config = getConfig();
		int coapsPort = config.get(CoapConfig.COAP_SECURE_PORT);
		boolean healthLogger = config.get(SystemConfig.HEALTH_STATUS_INTERVAL, TimeUnit.MILLISECONDS) > 0;

		if (deviceCredentials.getCertificateVerifier() == null && deviceCredentials.getPskStore() == null) {
			// no device credentials
			LOGGER.warn("Missing device credentials!");
			return;
		}

		// Context matcher
		EndpointContextMatcher customContextMatcher = null;
		if (MatcherMode.PRINCIPAL == config.get(CoapConfig.RESPONSE_MATCHING)) {
			customContextMatcher = new PrincipalEndpointContextMatcher(true);
		}

		// explore network interfaces
		Collection<InetAddress> localAddresses;
		if (cliArguments.network.wildcard) {
			localAddresses = Collections.singleton(new InetSocketAddress(0).getAddress());
		} else {
			localAddresses = NetworkInterfacesUtil
					.getNetworkInterfaces(cliArguments.network.selectInterfaces.getFilter(getTag()));
		}
		for (InetAddress addr : localAddresses) {
			InetSocketAddress bindToAddress = new InetSocketAddress(addr, coapsPort);

			DtlsConnectorConfig.Builder dtlsConfigBuilder = DtlsConnectorConfig.builder(config);
			dtlsConfigBuilder.setAddress(bindToAddress);
			String tag = "dtls:" + StringUtil.toString(bindToAddress);
			dtlsConfigBuilder.setLoggingTag(tag);
			AdvancedPskStore pskStore = deviceCredentials.getPskStore();
			if (pskStore != null) {
				dtlsConfigBuilder.setAdvancedPskStore(pskStore);
			}
			CertificateProvider certificateProvider = deviceCredentials.getCertificateProvider();
			if (certificateProvider != null) {
				dtlsConfigBuilder.setCertificateIdentityProvider(certificateProvider);
			}
			NewAdvancedCertificateVerifier certificateVerifier = deviceCredentials.getCertificateVerifier();
			if (certificateVerifier != null) {
				dtlsConfigBuilder.setAdvancedCertificateVerifier(certificateVerifier);
			}
			ApplicationLevelInfoSupplier infoSupplier = deviceCredentials.getInfoSupplier();
			if (infoSupplier != null) {
				dtlsConfigBuilder.setApplicationLevelInfoSupplier(infoSupplier);
			}
			dtlsConfigBuilder.setConnectionListener(new MdcConnectionListener());

			// setup health logger
			if (healthLogger) {
				DtlsHealthLogger health = new DtlsHealthLogger(tag);
				dtlsConfigBuilder.setHealthHandler(health);
				add(health);
			}

			DTLSConnector connector = new DTLSConnector(dtlsConfigBuilder.build());

			tag = "coaps:" + StringUtil.toString(bindToAddress);

			CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
			builder.setLoggingTag(tag);
			builder.setConnector(connector);
			builder.setConfiguration(config);
			if (customContextMatcher != null) {
				builder.setEndpointContextMatcher(customContextMatcher);
			}

			CoapEndpoint endpoint = builder.build();
			if (healthLogger) {
				HealthStatisticLogger health = new HealthStatisticLogger(tag, true);
				endpoint.addPostProcessInterceptor(health);
				add(health);
			}
			addEndpoint(endpoint);
			LOGGER.info("{}listen on {} ({})", getTag(), endpoint.getUri(),
					addr.isLoopbackAddress() ? "LOCAL" : "EXTERNAL");
		}
	}

	/**
	 * Add resources to CoAP server.
	 * 
	 * @param cliArguments command line arguments.
	 * @param executor primary executor
	 */
	public void addResource(ServerConfig cliArguments, ScheduledExecutorService executor) {
		// add resources to the server
		if (cliArguments.diagnose) {
			add(new Diagnose(this));
		}
		add(new Devices(getConfig()));
		add(new MyContext(MyContext.RESOURCE_NAME, CALIFORNIUM_BUILD_VERSION, false));
	}

	/**
	 * Setup HTTP service.
	 * 
	 * @param cliArguments command line arguments.
	 */
	public void setupHttpService(ServerConfig cliArguments) {
		HttpService httpService = HttpService.getHttpService();
		if (httpService != null) {
			ForwardHandler forward = new ForwardHandler("devices", "Devices:");
			httpService.createContext("/", forward);
			CoapProxyHandler proxy = new CoapProxyHandler(getMessageDeliverer(), httpService.getExecutor());
			httpService.createContext(Devices.RESOURCE_NAME, proxy);
			if (cliArguments.diagnose) {
				httpService.createContext(Diagnose.RESOURCE_NAME, proxy);
			}
		}
	}

	/**
	 * Setup UDP health logger.
	 * 
	 * Generate UDP statistic.
	 * 
	 * @param secondaryExecutor secondary executor for slow interval jobs
	 */
	public void setupUdpHealthLogger(ScheduledExecutorService secondaryExecutor) {
		Configuration config = getConfig();
		final NetSocketHealthLogger socketLogger = new NetSocketHealthLogger("udp");
		long interval = config.get(SystemConfig.HEALTH_STATUS_INTERVAL, TimeUnit.MILLISECONDS);
		if (interval > 0 && socketLogger.isEnabled()) {
			long readInterval = config.get(UDP_DROPS_READ_INTERVAL, TimeUnit.MILLISECONDS);
			if (interval > readInterval) {
				secondaryExecutor.scheduleAtFixedRate(new Runnable() {

					@Override
					public void run() {
						socketLogger.read();
					}
				}, readInterval, readInterval, TimeUnit.MILLISECONDS);
			}
			addDefaultEndpointObserver(new EndpointNetSocketObserver(socketLogger));
		}
	}

	/**
	 * Setup observe health logger.
	 * 
	 * Generate observer-notify statistic.
	 */
	public void setupObserveHealthLogger() {
		ObserveStatisticLogger obsStatLogger = new ObserveStatisticLogger(getTag());
		if (obsStatLogger.isEnabled()) {
			add(obsStatLogger);
			setObserveHealth(obsStatLogger);
			List<CounterStatisticManager> statistics = new ArrayList<>();
			statistics.add(obsStatLogger);
			Resource child = getRoot().getChild(Diagnose.RESOURCE_NAME);
			if (child instanceof Diagnose) {
				((Diagnose) child).update(statistics);
			}
		}
	}

	/**
	 * Setup persistence.
	 * 
	 * Support DTLS 1.2 graceful restart,
	 * 
	 * @param store store to keep persisted data
	 */
	public void setupPersistence(ServerConfig.Store store) {
		Runnable hook = new Runnable() {

			@Override
			public void run() {
				stop();
			}
		};
		char[] password64 = store.password64 == null ? null : store.password64.toCharArray();
		EncryptedPersistentComponentUtil serialization = new EncryptedPersistentComponentUtil();
		serialization.addProvider(this);
		serialization.loadAndRegisterShutdown(store.file, password64, TimeUnit.HOURS.toSeconds(store.maxAge), hook);
	}
}
