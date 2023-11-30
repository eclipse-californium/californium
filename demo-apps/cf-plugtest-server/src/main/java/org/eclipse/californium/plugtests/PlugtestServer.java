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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add TCP and encryption support.
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - split creating connectors into
 *                                                    AbstractTestServer.
 *    Achim Kraus (Bosch Software Innovations GmbH) - use special properties file
 *                                                    for configuration
 *    Rikard Höglund (RISE)                         - OSCORE support                                                    
 ******************************************************************************/
package org.eclipse.californium.plugtests;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.server.EncryptedServersSerializationUtil;
import org.eclipse.californium.core.server.resources.MyIpResource;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.config.CertificateAuthenticationMode;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.config.SystemConfig;
import org.eclipse.californium.elements.config.TcpConfig;
import org.eclipse.californium.elements.config.TimeDefinition;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.config.ValueException;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil.InetAddressFilter;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil.SimpleInetAddressFilter;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCoapStackFactory;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.plugtests.resources.Create;
import org.eclipse.californium.plugtests.resources.DefaultTest;
import org.eclipse.californium.plugtests.resources.Echo;
import org.eclipse.californium.plugtests.resources.Hono;
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
import org.eclipse.californium.plugtests.resources.MyContext;
import org.eclipse.californium.plugtests.resources.Observe;
import org.eclipse.californium.plugtests.resources.ObserveLarge;
import org.eclipse.californium.plugtests.resources.ObserveNon;
import org.eclipse.californium.plugtests.resources.ObservePumping;
import org.eclipse.californium.plugtests.resources.ObserveReset;
import org.eclipse.californium.plugtests.resources.Oscore;
import org.eclipse.californium.plugtests.resources.OscoreInfo;
import org.eclipse.californium.plugtests.resources.Path;
import org.eclipse.californium.plugtests.resources.Query;
import org.eclipse.californium.plugtests.resources.Separate;
import org.eclipse.californium.plugtests.resources.Shutdown;
import org.eclipse.californium.plugtests.resources.Validate;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.unixhealth.NetSocketHealthLogger;
import org.eclipse.californium.unixhealth.NetStatLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import picocli.CommandLine;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.ParseResult;

// ETSI Plugtest environment
//import java.net.InetSocketAddress;
//import org.eclipse.californium.core.network.CoAPEndpoint;

/**
 * The class PlugtestServer implements the test specification for the ETSI IoT
 * CoAP Plugtests, London, UK, 7--9 Mar 2014.
 */
@SuppressWarnings("deprecation")
public class PlugtestServer extends AbstractTestServer {

	/**
	 * @since 3.10
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(CoapServer.class);

	static {
		CoapConfig.register();
		UdpConfig.register();
		DtlsConfig.register();
		TcpConfig.register();
		System.setProperty("COAP_ROOT_RESOURCE_NOTE",
				"Note: the data sent to this server is public visible to other\n" +
				"      users! Don't send data, which requires data privacy.");
	}

	private static final File CONFIG_FILE = new File("CaliforniumPlugtest3.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Plugtest Server";
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 8192;
	private static final int DEFAULT_BLOCK_SIZE = 64;
	private static final int DEFAULT_NOTIFY_INTERVAL_MILLIS = 5000;
	private static final int MINIMUM_NOTIFY_INTERVAL_MILLIS = 5;

	// exit codes for runtime errors
	public static final int ERR_INIT_FAILED = 1;

	public static final List<CipherSuite> PRESELECTED_CIPHER_SUITES = Arrays.asList(
			CipherSuite.TLS_PSK_WITH_AES_128_CCM_8, CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256,
			CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256,
			CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);

	private static DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			config.set(SystemConfig.HEALTH_STATUS_INTERVAL, 300, TimeUnit.SECONDS);
			config.set(CoapConfig.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.set(CoapConfig.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.NOTIFICATION_CHECK_INTERVAL_COUNT, 4);
			config.set(CoapConfig.NOTIFICATION_CHECK_INTERVAL_TIME, 30, TimeUnit.SECONDS);
			config.set(CoapConfig.TCP_NUMBER_OF_BULK_BLOCKS, 1);
			config.set(CoapConfig.MAX_ACTIVE_PEERS, 10000);
			config.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false);
			config.set(DtlsConfig.DTLS_AUTO_HANDSHAKE_TIMEOUT, null, TimeUnit.SECONDS);
			config.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 6);
			config.set(DtlsConfig.DTLS_PRESELECTED_CIPHER_SUITES, PRESELECTED_CIPHER_SUITES);
			config.set(DtlsConfig.DTLS_MAX_CONNECTIONS, 10000);
			config.set(DtlsConfig.DTLS_REMOVE_STALE_DOUBLE_PRINCIPALS, false);
			config.set(DtlsConfig.DTLS_MAC_ERROR_FILTER_QUIET_TIME, 4, TimeUnit.SECONDS);
			config.set(DtlsConfig.DTLS_MAC_ERROR_FILTER_THRESHOLD, 8);
			config.set(DtlsConfig.DTLS_RETRANSMISSION_TIMEOUT, 3, TimeUnit.SECONDS);
			config.set(DtlsConfig.DTLS_ADDITIONAL_ECC_TIMEOUT, 8, TimeUnit.SECONDS);
			config.set(TcpConfig.TCP_CONNECT_TIMEOUT, 15, TimeUnit.SECONDS);
			config.set(TcpConfig.TCP_CONNECTION_IDLE_TIMEOUT, 60, TimeUnit.MINUTES);
			config.set(TcpConfig.TLS_HANDSHAKE_TIMEOUT, 60, TimeUnit.SECONDS);
			config.set(EXTERNAL_UDP_MAX_MESSAGE_SIZE, 64);
			config.set(EXTERNAL_UDP_PREFERRED_BLOCK_SIZE, 64);
			config.set(UDP_DROPS_READ_INTERVAL, 2000, TimeUnit.MILLISECONDS);
		}
	};

	public static class BaseConfig {

		@Option(names = { "-h", "--help" }, usageHelp = true, description = "display a help message")
		public boolean helpRequested;

		@Option(names = "--no-loopback", negatable = true, description = "enable endpoints on loopback network.")
		public boolean loopback = true;

		@Option(names = "--no-external", negatable = true, description = "enable endpoints on external network.")
		public boolean external = true;

		@Option(names = "--no-ipv4", negatable = true, description = "enable endpoints for ipv4.")
		public boolean ipv4 = true;

		@Option(names = "--no-ipv6", negatable = true, description = "enable endpoints for ipv6.")
		public boolean ipv6 = true;

		@Option(names = "--no-tcp", negatable = true, description = "enable endpoints for tcp.")
		public boolean tcp = true;

		@Option(names = "--dtls-only", description = "only dtls endpoints.")
		public boolean onlyDtls;

		@Option(names = "--trust-all", description = "trust all valid certificates.")
		public boolean trustall;

		@Option(names = "--client-auth", description = "client authentication. Values ${COMPLETION-CANDIDATES}.")
		public CertificateAuthenticationMode clientAuth;

		@Option(names = "--interfaces-pattern", split = ",", description = "interface regex patterns for endpoints.")
		public List<String> interfacePatterns;

		@Option(names = "--echo-delay", negatable = true, description = "enable delay option for echo resource.")
		public boolean echoDelay;

		@Option(names = "--no-oscore", negatable = true, description = "use OSCORE.")
		public boolean oscore = true;

		@Option(names = "--notify-interval", description = "Interval for plugtest notifies. e.g. 5[s]. Minimum "
				+ MINIMUM_NOTIFY_INTERVAL_MILLIS + "[ms], default " + DEFAULT_NOTIFY_INTERVAL_MILLIS + "[ms].")
		public String notifyInterval;

		@ArgGroup(exclusive = false)
		public Store store;

		public static class Store {

			@Option(names = "--store-file", required = true, description = "file store dtls state.")
			public String file;

			@Option(names = "--store-password64", required = false, description = "password to store dtls state. base 64 encoded.")
			public String password64;

			@Option(names = "--store-max-age", required = true, description = "maximum age of connections in hours.")
			public Integer maxAge;
		}

		@Option(names = "--psk-file", description = "file with PSK credentials. id=secret-base64.")
		public String pskFile;

		public List<Protocol> getProtocols() {
			List<Protocol> protocols = new ArrayList<>();
			protocols.add(Protocol.DTLS);
			if (!onlyDtls) {
				protocols.add(Protocol.UDP);
				if (tcp) {
					protocols.add(Protocol.TCP);
					protocols.add(Protocol.TLS);
				}
			} else {
				tcp = false;
			}
			return protocols;
		}

		public List<InterfaceType> getInterfaceTypes() {
			List<InterfaceType> types = new ArrayList<InterfaceType>();
			if (external) {
				types.add(InterfaceType.EXTERNAL);
			}
			if (loopback) {
				types.add(InterfaceType.LOCAL);
			}
			int s = types.size();
			if (s == 0) {
				System.err.println("Either --loopback or --external must be enabled!");
				System.exit(1);
			}
			if (ipv6) {
				types.add(InterfaceType.IPV6);
			}
			if (ipv4) {
				types.add(InterfaceType.IPV4);
			}
			if (s == types.size()) {
				System.err.println("Either --ipv4 or --ipv6 must be enabled!");
			}
			return types;
		}

		public InetAddressFilter getFilter(String tag) {
			if (interfacePatterns == null || interfacePatterns.isEmpty()) {
				return new SimpleInetAddressFilter(tag, external, loopback, ipv4, ipv6);
			} else {
				String[] patterns = new String[interfacePatterns.size()];
				patterns = interfacePatterns.toArray(patterns);
				return new SimpleInetAddressFilter(tag, external, loopback, ipv4, ipv6, patterns);
			}
		}

		public long getNotifyIntervalMillis() {
			long notifyIntervalMillis = DEFAULT_NOTIFY_INTERVAL_MILLIS;
			if (notifyInterval != null) {
				try {
					notifyIntervalMillis = TimeUnit.NANOSECONDS.toMillis(TimeDefinition.parse(notifyInterval));
					if (notifyIntervalMillis < MINIMUM_NOTIFY_INTERVAL_MILLIS) {
						notifyIntervalMillis = MINIMUM_NOTIFY_INTERVAL_MILLIS;
					}
				} catch (ValueException e) {
				}
			}
			return notifyIntervalMillis;
		}
	}

	@Command(name = "PlugtestServer", version = "(c) 2014, Institute for Pervasive Computing, ETH Zurich.")
	public static class Config extends BaseConfig {

	}

	private static final Config config = new Config();

	private static PlugtestServer server;
	private static EncryptedServersSerializationUtil serversSerialization = new EncryptedServersSerializationUtil();
	private static List<CoapServer> servers = new CopyOnWriteArrayList<>();
	private static byte[] state;

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

	public static void main(String[] args) {
		
		CommandLine cmd = new CommandLine(config);
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
		Configuration configuration = init(config);
		load(config);
		ScheduledExecutorService executor = ExecutorsUtil.newScheduledThreadPool(//
				configuration.get(CoapConfig.PROTOCOL_STAGE_THREAD_COUNT), //
				new NamedThreadFactory("CoapServer(main)#")); //$NON-NLS-1$
		ScheduledExecutorService secondaryExecutor = ExecutorsUtil
				.newDefaultSecondaryScheduler("CoapServer(secondary)#");

		EndpointNetSocketObserver socketObserver = null;
		final NetSocketHealthLogger socketLogger = new NetSocketHealthLogger("udp");
		long interval = configuration.get(SystemConfig.HEALTH_STATUS_INTERVAL, TimeUnit.MILLISECONDS);
		if (interval > 0 && socketLogger.isEnabled()) {
			long readInterval = configuration.get(UDP_DROPS_READ_INTERVAL, TimeUnit.MILLISECONDS);
			if (interval > readInterval) {
				secondaryExecutor.scheduleAtFixedRate(new Runnable() {

					@Override
					public void run() {
						socketLogger.read();
					}
				}, readInterval, readInterval, TimeUnit.MILLISECONDS);
			}
			socketObserver = new EndpointNetSocketObserver(socketLogger);
		}
		start(executor, secondaryExecutor, config, configuration, socketObserver, new ActiveInputReader());
		LOGGER.info("Executor shutdown ...");
		ExecutorsUtil.shutdownExecutorGracefully(500, executor, secondaryExecutor);
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

	public static Configuration init(BaseConfig config) {

		Configuration configuration = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);

		Configuration udpConfiguration = new Configuration(configuration)
				.set(CoapConfig.MAX_MESSAGE_SIZE, configuration.get(EXTERNAL_UDP_MAX_MESSAGE_SIZE))
				.set(CoapConfig.PREFERRED_BLOCK_SIZE, configuration.get(EXTERNAL_UDP_PREFERRED_BLOCK_SIZE));
		Map<Select, Configuration> protocolConfig = new HashMap<>();
		protocolConfig.put(new Select(Protocol.UDP, InterfaceType.EXTERNAL), udpConfiguration);

		// create server
		try {
			HashMapCtxDB oscoreCtxDb = null;
			byte[] oscoreServerRid = null;
			if (config.oscore) {
				oscoreCtxDb = new HashMapCtxDB();
				OSCoreCoapStackFactory.useAsDefault(oscoreCtxDb);
				oscoreServerRid = initOscore(configuration, oscoreCtxDb);
			}

			long notifyIntervalMillis = config.getNotifyIntervalMillis();

			server = new PlugtestServer(configuration, protocolConfig, notifyIntervalMillis, oscoreCtxDb, oscoreServerRid);
			server.setVersion(CALIFORNIUM_BUILD_VERSION);
			server.setTag("PLUG-TEST");
			add(server);
			// ETSI Plugtest environment
			// server.addEndpoint(new CoAPEndpoint(new InetSocketAddress("::1", port)));
			// server.addEndpoint(new CoAPEndpoint(new InetSocketAddress("127.0.0.1", port)));
			// server.addEndpoint(new CoAPEndpoint(new InetSocketAddress("2a01:c911:0:2010::10", port)));
			// server.addEndpoint(new CoAPEndpoint(new InetSocketAddress("10.200.1.2", port)));
			server.addEndpoints(config);
			if (server.getEndpoints().isEmpty()) {
				System.err.println("no endpoint available!");
				System.exit(ERR_INIT_FAILED);
			}
		} catch (Exception e) {

			System.err.printf("Failed to create " + PlugtestServer.class.getSimpleName() + ": %s\n", e.getMessage());
			e.printStackTrace(System.err);
			System.err.println("Exiting");
			System.exit(ERR_INIT_FAILED);
		}
		return configuration;
	}

	public static void add(CoapServer server) {
		servers.add(server);
		serversSerialization.add(server);
	}

	public static void load(BaseConfig config) {

		if (config.store != null) {
			char[] password64 = config.store.password64 == null ? null : config.store.password64.toCharArray();
			serversSerialization.loadAndRegisterShutdown(config.store.file, password64,
					TimeUnit.HOURS.toSeconds(config.store.maxAge));
		}
	}

	public static void load(String password) {
		if (state != null) {
			SecretKey key = toKey(password);
			ByteArrayInputStream in = new ByteArrayInputStream(state);
			serversSerialization.loadServers(in, key);
			if (key == null) {
				LOGGER.info("Loaded: {} Bytes", state.length);
			} else {
				LOGGER.info("Loaded: {} Bytes (pw: {})", state.length, password);
			}
			state = null;
			serversSerialization.start();
			SecretUtil.destroy(key);
			try {
				in.close();
			} catch (IOException e) {
			}
		} else {
			LOGGER.info("no data to load!");
		}
	}

	public static AbstractTestServer start(ScheduledExecutorService mainExecutor, ScheduledExecutorService secondaryExecutor,
			BaseConfig config, Configuration configuration, EndpointNetSocketObserver observer,
			ActiveInputReader inputReader) {

		if (server != null) {
			server.setExecutors(mainExecutor, secondaryExecutor, true);
			if (observer != null) {
				server.addDefaultEndpointObserver(observer);
			}
			server.add(new Echo(configuration, config.echoDelay ? mainExecutor : null));
			server.start();
			server.addLogger(true);

			LOGGER.info("{} started ...", PlugtestServer.class.getSimpleName());

			if (inputReader != null) {
				long interval = configuration.get(SystemConfig.HEALTH_STATUS_INTERVAL, TimeUnit.MILLISECONDS);
				if (interval > 0) {
					if (observer != null) {
						server.add(observer.getNetSocketHealth());
					}
					if (config.ipv4) {
						server.add(new NetStatLogger("udp", false));
					}
					if (config.ipv6) {
						server.add(new NetStatLogger("udp6", true));
					}
				} else {
					interval = 30000;
				}
				for (;;) {
					if (console(inputReader, interval)) {
						break;
					}
					dumpAll();
				}
				LOGGER.info("{} stopping ...", PlugtestServer.class.getSimpleName());
				shutdown();
			}
		}
		return server;
	}

	public static void dumpAll() {
		for (CoapServer server : servers) {
			server.dump();
		}
	}

	public static void shutdown() {
		if (server != null) {
			server.stop();
		}
	}

	public static void save(String password) {
		SecretKey key = toKey(password);
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		if (state != null) {
			Bytes.clear(state);
		}
		try {
			// max age 10 minutes
			serversSerialization.saveServers(out, key, 60 * 10);
			state = out.toByteArray();
			out.close();
			if (key == null) {
				LOGGER.info("Saved: {} Bytes", state.length);
			} else {
				LOGGER.info("Saved: {} Bytes (pw: {})", state.length, password);
			}
		} catch (IOException ex) {
			LOGGER.warn("saving failed:", ex);
		} finally {
			SecretUtil.destroy(key);
		}
	}

	public static SecretKey toKey(String password) {
		SecretKey key = null;
		if (password != null && !password.isEmpty()) {
			key = SecretUtil.create(password.getBytes(), "PW");
		}
		return key;
	}

	public static boolean console(ActiveInputReader reader, long timeout) {
		try {
			String line = reader.getLine(timeout);
			if (line != null) {
				System.out.println("> " + line);
				if (line.startsWith("save")) {
					save(line.substring(4));
				} else if (line.startsWith("load")) {
					load(line.substring(4));
				} else if (line.equals("exit")) {
					return true;
				}
			}
		} catch (RuntimeException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			return true;
		}
		return false;
	}

	/**
	 * Initializes an OSCORE context for the server built on a pre-defined
	 * configuration and adds it to the OSCORE context database. The created
	 * context will support the Appendix B.2. context rederivation procedure.
	 * 
	 * @param config the Configuration
	 * @param db the OSCORE context database
	 * 
	 * @return the RID of the server for the generated context
	 */
	public static byte[] initOscore(Configuration config, HashMapCtxDB db) {
		AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
		AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

		byte[] master_secret = StringUtil.hex2ByteArray("0102030405060708090a0b0c0d0e0f10");
		byte[] master_salt = StringUtil.hex2ByteArray("9e7ca92223786340");
		byte[] sid = StringUtil.hex2ByteArray("02");
		byte[] rid = StringUtil.hex2ByteArray("01");
		byte[] id_context = StringUtil.hex2ByteArray("37cbf3210017a2d3");
		int MAX_UNFRAGMENTED_SIZE = config.get(CoapConfig.MAX_RESOURCE_BODY_SIZE);

		OSCoreCtx ctx = null;
		try {
			ctx = new OSCoreCtx(master_secret, false, alg, sid, rid, kdf, 32, master_salt, id_context,
					MAX_UNFRAGMENTED_SIZE);
			ctx.setContextRederivationEnabled(true);
		} catch (OSException e) {
			LOGGER.error("Failed to derive OSCORE context");
			e.printStackTrace();
		}
		db.addContext(ctx);

		return rid;
	}

	public static class ActiveInputReader {

		BufferedReader in;
		Queue<String> buffer;
		Thread thread;

		public ActiveInputReader() {
			in = new BufferedReader(new InputStreamReader(System.in));
			buffer = new ConcurrentLinkedQueue<>();
			thread = new Thread(new Runnable() {

				@Override
				public void run() {
					read();
				}
			}, "INPUT");
			thread.setDaemon(true);
			thread.start();
		}

		public void read() {
			String line = null;
			try {
				while ((line = in.readLine()) != null) {
					buffer.add(line);
					synchronized (buffer) {
						buffer.notify();
					}
				}
			} catch (IOException e) {
			}
		}

		public String getLine(long timeout) throws InterruptedException {
			if (timeout >= 0) {
				synchronized (buffer) {
					buffer.wait(timeout);
				}
			}
			return buffer.poll();
		}
	}

	public PlugtestServer(Configuration config, Map<Select, Configuration> protocolConfig, long notifyIntervalMillis,
			HashMapCtxDB oscoreCtxDb, byte[] oscoreServerRid) throws SocketException {
		super(config, protocolConfig);

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
		add(new Observe(notifyIntervalMillis));
		add(new ObserveNon(notifyIntervalMillis));
		add(new ObserveReset());
		add(new ObserveLarge(notifyIntervalMillis));
		add(new ObservePumping(Type.CON, notifyIntervalMillis));
		add(new ObservePumping(Type.NON, notifyIntervalMillis));
		add(new LocationQuery());
		add(new MultiFormat());
		add(new Link1());
		add(new Link2());
		add(new Link3());
		add(new Path());
		add(new Validate());
		add(new Create());
		add(new Shutdown());
		add(new Hono("telemetry"));
		add(new Hono("event"));
		add(new MyIpResource(MyIpResource.RESOURCE_NAME, false));
		add(new MyContext(MyContext.RESOURCE_NAME, CALIFORNIUM_BUILD_VERSION, false));

		if (oscoreCtxDb != null && oscoreServerRid != null) {
			add(new Oscore());
			add(new OscoreInfo(oscoreCtxDb, oscoreServerRid));
		}
	}
}
