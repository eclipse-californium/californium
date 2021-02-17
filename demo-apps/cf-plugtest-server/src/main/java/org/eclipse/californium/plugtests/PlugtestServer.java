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
 ******************************************************************************/
package org.eclipse.californium.plugtests;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.SocketException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointObserver;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.core.network.interceptors.AnonymizedOriginTracer;
import org.eclipse.californium.core.network.interceptors.HealthStatisticLogger;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.server.ServersSerializationUtil;
import org.eclipse.californium.elements.tcp.netty.TlsServerConnector.ClientAuthMode;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DataStreamReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.plugtests.resources.Context;
import org.eclipse.californium.plugtests.resources.Create;
import org.eclipse.californium.plugtests.resources.DefaultTest;
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
import org.eclipse.californium.plugtests.resources.MyIp;
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
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction.Label;
import org.eclipse.californium.scandium.dtls.cipher.RandomManager;
import org.eclipse.californium.scandium.util.SecretUtil;

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
public class PlugtestServer extends AbstractTestServer {

	private static final File CONFIG_FILE = new File("CaliforniumPlugtest.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Plugtest Server";
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 8192;
	private static final int DEFAULT_BLOCK_SIZE = 64;

	// exit codes for runtime errors
	public static final int ERR_INIT_FAILED = 1;

	private static NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			config.setInt(Keys.DTLS_AUTO_RESUME_TIMEOUT, 0);
			config.setInt(Keys.DTLS_CONNECTION_ID_LENGTH, 6);
			config.setInt(Keys.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.NOTIFICATION_CHECK_INTERVAL_COUNT, 4);
			config.setInt(Keys.NOTIFICATION_CHECK_INTERVAL_TIME, 30000);
			config.setInt(Keys.HEALTH_STATUS_INTERVAL, 300);
			config.setInt(Keys.UDP_CONNECTOR_RECEIVE_BUFFER, 0);
			config.setInt(Keys.UDP_CONNECTOR_SEND_BUFFER, 0);
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

		@Option(names = "--client-auth", defaultValue = "NEEDED", description = "client authentication. Values ${COMPLETION-CANDIDATES}, default ${DEFAULT-VALUE}.")
		public ClientAuthMode clientAuth;

		@ArgGroup(exclusive = false)
		public Store store;

		@Option(names = "--interfaces-pattern", split = ",", description = "interface regex patterns for endpoints.")
		public List<String> interfacePatterns;

		public static class Store {

			@Option(names = "--store-file", required = true, description = "file store dtls state.")
			public String file;

			@Option(names = "--store-password64", required = false, description = "password to store dtls state. base 64 encoded.")
			public String password64;

			@Option(names = "--store-max-age", required = true, description = "maximum age of connections in hours.")
			public Integer maxAge;
		}

		public List<Protocol> getProtocols() {
			List<Protocol> protocols = new ArrayList<>();
			if (!onlyDtls) {
				protocols.add(Protocol.UDP);
			} else {
				tcp = false;
			}
			protocols.add(Protocol.DTLS);
			if (tcp) {
				protocols.add(Protocol.TCP);
				protocols.add(Protocol.TLS);
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
	}

	@Command(name = "PlugtestServer", version = "(c) 2014, Institute for Pervasive Computing, ETH Zurich.")
	public static class Config extends BaseConfig {

	}

	private static final Config config = new Config();

	private static PlugtestServer server;
	private static List<CoapServer> servers = new CopyOnWriteArrayList<>();
	private static BaseConfig.Store storeConfig;
	private static File store;
	private static byte[] state;

	public static void main(String[] args) {
		CommandLine cmd = new CommandLine(config);
		try {
			ParseResult result = cmd.parseArgs(args);
			if (result.isVersionHelpRequested()) {
				String version = StringUtil.CALIFORNIUM_VERSION == null ? "" : StringUtil.CALIFORNIUM_VERSION;
				System.out.println("\nCalifornium (Cf) " + cmd.getCommandName() + " " + version);
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
		init(config);
		load(config);
		NetworkConfig netConfig = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		ScheduledExecutorService executor = ExecutorsUtil.newScheduledThreadPool(//
				netConfig.getInt(NetworkConfig.Keys.PROTOCOL_STAGE_THREAD_COUNT), //
				new NamedThreadFactory("CoapServer(main)#")); //$NON-NLS-1$
		ScheduledExecutorService secondaryExecutor = ExecutorsUtil
				.newDefaultSecondaryScheduler("CoapServer(secondary)#");
		start(executor, secondaryExecutor, config, new ActiveInputReader());
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

	public static void init(BaseConfig config) {

		NetworkConfig netconfig = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);

		// create server
		try {
			List<Protocol> protocols = config.getProtocols();

			List<InterfaceType> types = config.getInterfaceTypes();

			server = new PlugtestServer(netconfig);
			server.setTag("PLUG-TEST");
			add(server);
			// ETSI Plugtest environment
//			server.addEndpoint(new CoAPEndpoint(new InetSocketAddress("::1", port)));
//			server.addEndpoint(new CoAPEndpoint(new InetSocketAddress("127.0.0.1", port)));
//			server.addEndpoint(new CoAPEndpoint(new InetSocketAddress("2a01:c911:0:2010::10", port)));
//			server.addEndpoint(new CoAPEndpoint(new InetSocketAddress("10.200.1.2", port)));
			server.addEndpoints(config.interfacePatterns, types, protocols, config);
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

	}

	public static void add(CoapServer server) {
		servers.add(server);
	}

	private static Cipher init(int mode, SecretKey password, byte[] seed) {
		try {
			CipherSuite cipherSuite = CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256;
			byte[] data = PseudoRandomFunction.doPRF(cipherSuite.getThreadLocalPseudoRandomFunctionMac(), password,
					Label.KEY_EXPANSION_LABEL, seed, 32);
			SecretKey key = SecretUtil.create(data, 0, 16, "AES");
			AlgorithmParameterSpec parameterSpec = new IvParameterSpec(data, 16, 16);
			Bytes.clear(data);
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(mode, key, parameterSpec);
			SecretUtil.destroy(key);
			return cipher;
		} catch (GeneralSecurityException ex) {
			LOGGER.warn("encryption error:", ex);
			return null;
		}
	}

	public static void loadServers(InputStream in, SecretKey key) {
		DataStreamReader reader = new DataStreamReader(in);
		byte[] seed = reader.readVarBytes(Byte.SIZE);
		if (seed != null && seed.length > 0) {
			if (key == null) {
				LOGGER.warn("missing key!");
				return;
			}
			Cipher cipher = init(Cipher.DECRYPT_MODE, key, seed);
			if (cipher == null) {
				LOGGER.warn("crypto error!");
				return;
			}
			in = new CipherInputStream(in, cipher);
		}
		ServersSerializationUtil.loadServers(in, servers);
	}

	public static void load(BaseConfig config) {

		if (config.store != null) {
			storeConfig = config.store;
			store = new File(config.store.file);
			if (store.exists()) {
				SecretKey key = null;
				if (config.store.password64 != null) {
					byte[] secret = StringUtil.base64ToByteArray(config.store.password64);
					key = SecretUtil.create(secret, "PW");
					Bytes.clear(secret);
				}
				try {
					FileInputStream in = new FileInputStream(store);
					try {
						loadServers(in, key);
					} finally {
						in.close();
					}
					LOGGER.info("Server state read.");
					store.delete();
				} catch (IOException ex) {
					LOGGER.warn("Reading server state failed!", ex);
				} catch (IllegalArgumentException ex) {
					LOGGER.warn("Reading server state failed!", ex);
				} finally {
					SecretUtil.destroy(key);
				}
			}
		}
	}

	public static void load(String password) {
		if (state != null) {
			SecretKey key = toKey(password);
			ByteArrayInputStream in = new ByteArrayInputStream(state);
			loadServers(in, key);
			LOGGER.info("Loaded: {} Bytes ({})", state.length, password);
			state = null;
			for (CoapServer server : servers) {
				server.start();
			}
			SecretUtil.destroy(key);
			try {
				in.close();
			} catch (IOException e) {
			}
		} else {
			LOGGER.info("no data to load!");
		}
	}

	public static void start(ScheduledExecutorService mainExecutor, ScheduledExecutorService secondaryExecutor,
			BaseConfig config, ActiveInputReader inputReader) {
		registerShutdown();

		if (server != null) {
			server.setExecutors(mainExecutor, secondaryExecutor, true);
			server.start();

			// add special interceptor for message traces
			for (Endpoint ep : server.getEndpoints()) {
				URI uri = ep.getUri();
				ep.addInterceptor(new MessageTracer());
				// Anonymized IoT metrics for validation. On success, remove the OriginTracer.
				ep.addInterceptor(new AnonymizedOriginTracer(uri.getPort() + "-" + uri.getScheme()));
				int interval = ep.getConfig().getInt(NetworkConfig.Keys.HEALTH_STATUS_INTERVAL);
				final HealthStatisticLogger healthLogger = new HealthStatisticLogger(uri.toASCIIString(),
						!CoAP.isTcpScheme(uri.getScheme()), interval, secondaryExecutor);
				if (healthLogger.isEnabled()) {
					ep.addPostProcessInterceptor(healthLogger);
					ep.addObserver(new EndpointObserver() {

						@Override
						public void stopped(Endpoint endpoint) {
							healthLogger.stop();
						}

						@Override
						public void started(Endpoint endpoint) {
							healthLogger.start();
						}

						@Override
						public void destroyed(Endpoint endpoint) {
							healthLogger.stop();
						}
					});
					healthLogger.start();
				}
			}

			LOGGER.info("{} started ...", PlugtestServer.class.getSimpleName());

			if (inputReader != null) {
				for (;;) {
					if (console(inputReader, 15000)) {
						break;
					}
				}
				LOGGER.info("{} stopping ...", PlugtestServer.class.getSimpleName());
				shutdown();
			}
		}
	}

	public static void shutdown() {
		if (server != null) {
			server.stop();
		}
	}

	public static void saveServers(OutputStream out, SecretKey key, long maxAgeInSeconds) throws IOException {
		DatagramWriter writer = new DatagramWriter();
		if (key != null) {
			byte[] seed = new byte[16];
			RandomManager.currentSecureRandom().nextBytes(seed);
			Cipher cipher = init(Cipher.ENCRYPT_MODE, key, seed);
			if (cipher != null) {
				writer.writeVarBytes(seed, Byte.SIZE);
				writer.writeTo(out);
				out = new CipherOutputStream(out, cipher);
			} else {
				LOGGER.warn("crypto error!");
				writer.reset();
				key = null;
			}
		}
		if (key == null) {
			writer.writeVarBytes(Bytes.EMPTY, Byte.SIZE);
			writer.writeTo(out);
		}
		ServersSerializationUtil.saveServers(out, maxAgeInSeconds, servers);
		out.close();
	}

	public static void save(String password) {
		SecretKey key = toKey(password);
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		if (state != null) {
			Bytes.clear(state);
		}
		try {
			// max age 10 minutes
			saveServers(out, key, 60 * 10);
			state = out.toByteArray();
			out.close();
		} catch (IOException ex) {
			LOGGER.warn("saving failed:", ex);
		} finally {
			SecretUtil.destroy(key);
		}
		LOGGER.info("Saved: {} Bytes ({})", state.length, password);
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

	private static void registerShutdown() {
		LOGGER.info("register shutdown hook.");
		Runtime.getRuntime().addShutdownHook(new Thread("SHUTDOWN") {

			@Override
			public void run() {
				LOGGER.info("Shutdown ...");
				if (store != null) {
					store.delete();
					SecretKey key = null;
					if (storeConfig.password64 != null) {
						byte[] secret = StringUtil.base64ToByteArray(storeConfig.password64);
						key = SecretUtil.create(secret, "PW");
						Bytes.clear(secret);
					}
					try {
						FileOutputStream out = new FileOutputStream(store);
						try {
							saveServers(out, key, TimeUnit.HOURS.toSeconds(storeConfig.maxAge));
						} finally {
							out.close();
						}
					} catch (IOException ex) {
						LOGGER.warn("Saving server state failed!", ex);
						store.delete();
					} finally {
						SecretUtil.destroy(key);
					}
				}
				LOGGER.info("Shutdown.");
			}
		});
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

	public PlugtestServer(NetworkConfig config) throws SocketException {
		super(config, null);

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
		add(new Hono("telemetry"));
		add(new Hono("event"));
		add(new MyIp(MyIp.RESOURCE_NAME, false));
		add(new Context(Context.RESOURCE_NAME, false));
	}
}
