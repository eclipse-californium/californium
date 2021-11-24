/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - use special properties file
 *                                                    for configuration
 *    Achim Kraus (Bosch Software Innovations GmbH) - add benchmark
 *    Achim Kraus (Bosch Software Innovations GmbH) - use executors util.
 ******************************************************************************/
package org.eclipse.californium.extplugtests;

import java.io.File;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.lang.management.OperatingSystemMXBean;
import java.lang.management.ThreadMXBean;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509KeyManager;

import org.eclipse.californium.cluster.CredentialsUtil;
import org.eclipse.californium.cluster.DtlsClusterManager;
import org.eclipse.californium.cluster.DtlsClusterManager.ClusterNodesDiscover;
import org.eclipse.californium.cluster.JdkK8sMonitorService;
import org.eclipse.californium.cluster.K8sManagementDiscoverClient;
import org.eclipse.californium.cluster.K8sManagementDiscoverJdkClient;
import org.eclipse.californium.cluster.Readiness;
import org.eclipse.californium.cluster.RestoreHttpClient;
import org.eclipse.californium.cluster.config.DtlsClusterManagerConfig;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.config.CoapConfig.MatcherMode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointObserver;
import org.eclipse.californium.core.network.interceptors.AnonymizedOriginTracer;
import org.eclipse.californium.core.network.interceptors.HealthStatisticLogger;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.server.resources.MyIpResource;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.config.SystemConfig;
import org.eclipse.californium.elements.config.TcpConfig;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.extplugtests.resources.Benchmark;
import org.eclipse.californium.extplugtests.resources.RequestStatistic;
import org.eclipse.californium.extplugtests.resources.ReverseObserve;
import org.eclipse.californium.extplugtests.resources.ReverseRequest;
import org.eclipse.californium.plugtests.AbstractTestServer;
import org.eclipse.californium.plugtests.PlugtestServer;
import org.eclipse.californium.plugtests.PlugtestServer.BaseConfig;
import org.eclipse.californium.plugtests.resources.Hono;
import org.eclipse.californium.plugtests.resources.MyContext;
import org.eclipse.californium.scandium.DtlsClusterConnector;
import org.eclipse.californium.scandium.DtlsClusterConnector.ClusterNodesProvider;
import org.eclipse.californium.scandium.DtlsManagedClusterConnector;
import org.eclipse.californium.scandium.MdcConnectionListener;
import org.eclipse.californium.scandium.config.DtlsClusterConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.pskstore.AsyncAdvancedPskStore;
import org.eclipse.californium.scandium.dtls.x509.AsyncKeyManagerCertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.AsyncNewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.unixhealth.NetStatLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import picocli.CommandLine;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.ITypeConverter;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.ParseResult;

/**
 * Extended test server.
 * 
 * Setup for larger blocks than the plugtest server and provides the request
 * statistic resource.
 */
public class ExtendedTestServer extends AbstractTestServer {

	private static final Logger STATISTIC_LOGGER = LoggerFactory
			.getLogger("org.eclipse.californium.extplugtests.statistics");

	private static final File CONFIG_FILE = new File("CaliforniumReceivetest3.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Receivetest Server";
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 8192;
	private static final int DEFAULT_BLOCK_SIZE = 1024;
	private static final long MEGA = 1024 * 1024L;

	private static DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			// start on alternative port, 5783 and 5784
			config.set(DTLS_HANDSHAKE_RESULT_DELAY, 0, TimeUnit.MILLISECONDS);
			config.set(CoapConfig.COAP_PORT, CoapConfig.COAP_PORT.getDefaultValue() + 100);
			config.set(CoapConfig.COAP_SECURE_PORT, CoapConfig.COAP_SECURE_PORT.getDefaultValue() + 100);
			config.set(CoapConfig.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.set(CoapConfig.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.PEERS_MARK_AND_SWEEP_MESSAGES, 16);
			config.set(CoapConfig.DEDUPLICATOR, CoapConfig.DEDUPLICATOR_PEERS_MARK_AND_SWEEP);
			config.set(CoapConfig.MAX_ACTIVE_PEERS, 1000000);
			config.set(CoapConfig.MAX_PEER_INACTIVITY_PERIOD, 60, TimeUnit.SECONDS);
			config.set(CoapConfig.RESPONSE_MATCHING, MatcherMode.PRINCIPAL_IDENTITY);
			config.set(DtlsConfig.DTLS_MAX_CONNECTIONS, 1000000);
			config.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false);
			config.set(DtlsConfig.DTLS_AUTO_HANDSHAKE_TIMEOUT, null, TimeUnit.SECONDS);
			config.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 6);
			config.set(DtlsConfig.DTLS_SUPPORT_DEPRECATED_CID, true);
			config.set(DtlsConfig.DTLS_PRESELECTED_CIPHER_SUITES, PlugtestServer.PRESELECTED_CIPHER_SUITES);
			config.set(TcpConfig.TCP_CONNECTION_IDLE_TIMEOUT, 1, TimeUnit.HOURS);
			config.set(TcpConfig.TLS_HANDSHAKE_TIMEOUT, 60, TimeUnit.SECONDS);
			config.set(SystemConfig.HEALTH_STATUS_INTERVAL, 60, TimeUnit.SECONDS);
			int processors = Runtime.getRuntime().availableProcessors();
			config.set(UdpConfig.UDP_RECEIVER_THREAD_COUNT, processors > 3 ? 2 : 1);
			config.set(UdpConfig.UDP_SENDER_THREAD_COUNT, processors);
			config.set(EXTERNAL_UDP_MAX_MESSAGE_SIZE, 64);
			config.set(EXTERNAL_UDP_PREFERRED_BLOCK_SIZE, 64);
		}

	};

	@Command(name = "ExtendedTestServer", version = "(c) 2017-2020, Bosch.IO GmbH and others.")
	private static class Config extends PlugtestServer.BaseConfig {

		@Option(names = "--no-plugtest", negatable = true, description = "enable plugtest server.")
		public boolean plugtest = true;

		@Option(names = "--benchmark", negatable = true, description = "enable benchmark resource.")
		public boolean benchmark;

		public static class SimpleCluster {

			@Option(names = "--dtls-cluster", split = ",", arity = "1..n", description = "configure DTLS-cluster-node. <dtls-interface>;<mgmt-interface>;<node-id>. use --- as <dtls-interface>, for other cluster-nodes.")
			public List<ClusterNode> dtlsClusterNodes;

			@Option(names = "--dtls-cluster-group", split = ",", description = "enable dynamic DTLS-cluster mode. List of <mgmt-interface1>,<mgmt-interface2>, ...")
			public List<InetSocketAddress> dtlsClusterGroup;

			@Option(names = "--dtls-cluster-group-security", description = "enable security for dynamic DTLS-cluster. Preshared secret for mgmt-interface.")
			public String dtlsClusterGroupSecurity;

		}

		public static class ClusterType {

			@ArgGroup(exclusive = false)
			public SimpleCluster simpleCluster;

			@Option(names = "--k8s-dtls-cluster", description = "enable k8s DTLS-cluster mode. <dtls-interface>;<mgmt-interface>;external-mgmt-port")
			public K8sCluster k8sCluster;

		}

		/**
		 * Cluster configuration.
		 */
		@ArgGroup(exclusive = false)
		public Cluster cluster;

		public static class Cluster {

			@ArgGroup(exclusive = true, multiplicity = "1")
			public ClusterType clusterType;

			@Option(names = "--no-dtls-cluster-backward", negatable = true, description = "send messages backwards to the original receiving connector.")
			public boolean backwardClusterMessages = true;

			@Option(names = "--dtls-cluster-mac", negatable = true, description = "use MAC for cluster traffic to protect original received address.")
			public Boolean dtlsClusterMac;

		}

		@Option(names = "--k8s-restore", description = "enable k8s restore for graceful restart. https interface to load connections.")
		public InetSocketAddress k8sRestore;

		@Option(names = "--k8s-monitor", description = "enable k8s monitor. http interface for k8s monitoring.")
		public InetSocketAddress k8sMonitor;

		public void register(CommandLine cmd) {
			cmd.registerConverter(ClusterNode.class, clusterDefinition);
			cmd.registerConverter(InetSocketAddress.class, addressDefinition);
			cmd.registerConverter(K8sCluster.class, k8sClusterDefinition);
		}

		public List<Protocol> getProtocols() {
			List<Protocol> protocols = super.getProtocols();
			if (cluster != null) {
				protocols.remove(Protocol.DTLS);
			}
			return protocols;
		}

		public List<InterfaceType> getInterfaceTypes() {
			if (cluster != null && cluster.clusterType.k8sCluster != null) {
				external = true;
				loopback = false;
				ipv4 = true;
				ipv6 = false;
			}
			return super.getInterfaceTypes();
		}

	}

	private static final Config config = new Config();

	static {
		CoapConfig.register();
		UdpConfig.register();
		DtlsConfig.register();
		TcpConfig.register();
		DtlsClusterManagerConfig.register();
	}

	private List<Readiness> components = new ArrayList<>();

	private static String version = StringUtil.CALIFORNIUM_VERSION;

	public static void main(String[] args) {
		String build = StringUtil.readFile(new File("build"), null);
		if (build != null && !build.isEmpty()) {
			version = version + "_" + build;
		}
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
		STATISTIC_LOGGER.error("start!");
		startManagamentStatistic();
		try {
			K8sManagementDiscoverClient k8sGroup = null;
			DtlsClusterConnectorConfig.Builder clusterConfigBuilder = DtlsClusterConnectorConfig.builder();
			Configuration configuration = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
			if (config.cluster != null) {
				int nodeId = -1;
				clusterConfigBuilder.setBackwardMessage(config.cluster.backwardClusterMessages);
				if (config.cluster.clusterType.k8sCluster != null) {
					clusterConfigBuilder.setAddress(config.cluster.clusterType.k8sCluster.cluster);
					clusterConfigBuilder.setClusterMac(config.cluster.dtlsClusterMac);
					K8sManagementDiscoverClient.setConfiguration(clusterConfigBuilder);
					k8sGroup = new K8sManagementDiscoverJdkClient(config.cluster.clusterType.k8sCluster.externalPort);
					nodeId = k8sGroup.getNodeID();
					LOGGER.info("dynamic k8s-cluster!");
				} else if (config.cluster.clusterType.simpleCluster != null) {
					for (ClusterNode cluster : config.cluster.clusterType.simpleCluster.dtlsClusterNodes) {
						if (cluster.dtls != null) {
							nodeId = cluster.nodeId;
							break;
						}
					}
					if (nodeId < 0) {
						throw new IllegalArgumentException("at least one cluster node must have a dtls interface!");
					}
					if (config.cluster.clusterType.simpleCluster.dtlsClusterGroup != null) {
						LOGGER.info("dynamic dtls-cluster!");
						String secret = config.cluster.clusterType.simpleCluster.dtlsClusterGroupSecurity;
						if (secret != null) {
							SecretKey key = SecretUtil.create(secret.getBytes(), "PSK");
							clusterConfigBuilder.setSecure("dtls-mgmt", key);
							SecretUtil.destroy(key);
							clusterConfigBuilder.setClusterMac(config.cluster.dtlsClusterMac);
						}
					} else {
						LOGGER.info("static dtls-cluster!");
					}
				}
				configuration.set(DtlsConfig.DTLS_CONNECTION_ID_NODE_ID, nodeId);
			} else if (config.plugtest) {
				// start standard plugtest server
				PlugtestServer.init(config);
			}

			Configuration udpConfiguration = new Configuration(configuration)
					.set(CoapConfig.MAX_MESSAGE_SIZE, configuration.get(EXTERNAL_UDP_MAX_MESSAGE_SIZE))
					.set(CoapConfig.PREFERRED_BLOCK_SIZE, configuration.get(EXTERNAL_UDP_PREFERRED_BLOCK_SIZE));
			Map<Select, Configuration> protocolConfig = new HashMap<>();
			protocolConfig.put(new Select(Protocol.UDP, InterfaceType.EXTERNAL), udpConfiguration);

			// create server
			List<Protocol> protocols = config.getProtocols();

			List<InterfaceType> types = config.getInterfaceTypes();

			ScheduledExecutorService executor = ExecutorsUtil.newScheduledThreadPool(//
					configuration.get(CoapConfig.PROTOCOL_STAGE_THREAD_COUNT), //
					new NamedThreadFactory("ExtCoapServer(main)#")); //$NON-NLS-1$
			ScheduledExecutorService secondaryExecutor = ExecutorsUtil
					.newDefaultSecondaryScheduler("ExtCoapServer(secondary)#");

			ExtendedTestServer server = new ExtendedTestServer(configuration, protocolConfig, !config.benchmark);
			server.setTag("EXTENDED-TEST");
			server.setExecutors(executor, secondaryExecutor, false);
			server.add(new ReverseRequest(configuration, executor));
			ReverseObserve reverseObserver = new ReverseObserve(configuration, executor);
			server.add(reverseObserver);
			if (k8sGroup != null) {
				DtlsClusterConnectorConfig clusterConfig = clusterConfigBuilder.build();
				server.addClusterEndpoint(secondaryExecutor, config.cluster.clusterType.k8sCluster.dtls,
						k8sGroup.getNodeID(), clusterConfig, null, k8sGroup, config);
			} else if (config.cluster != null && config.cluster.clusterType.simpleCluster != null) {
				ClusterGroup group = null;
				DtlsClusterConnector.ClusterNodesProvider nodes = null;
				if (config.cluster.clusterType.simpleCluster.dtlsClusterGroup == null) {
					nodes = new DtlsClusterConnector.ClusterNodesProvider() {

						@Override
						public InetSocketAddress getClusterNode(int nodeId) {
							for (ClusterNode node : config.cluster.clusterType.simpleCluster.dtlsClusterNodes) {
								if (node.nodeId == nodeId) {
									return node.cluster;
								}
							}
							return null;
						}

						@Override
						public boolean available(InetSocketAddress destinationConnector) {
							return true;
						}
					};
				}
				for (ClusterNode cluster : config.cluster.clusterType.simpleCluster.dtlsClusterNodes) {
					if (cluster.dtls != null) {
						DtlsClusterConnectorConfig clusterConfig = DtlsClusterConnectorConfig
								.builder(clusterConfigBuilder.getIncompleteConfig()).setAddress(cluster.cluster)
								.build();
						if (config.cluster.clusterType.simpleCluster.dtlsClusterGroup != null) {
							group = new ClusterGroup(config.cluster.clusterType.simpleCluster.dtlsClusterGroup);
						}
						server.addClusterEndpoint(secondaryExecutor, cluster.dtls, cluster.nodeId, clusterConfig, nodes,
								group, config);
					}
				}
			}
			server.addEndpoints(config.interfacePatterns, types, protocols, config);
			if (server.getEndpoints().isEmpty()) {
				System.err.println("no endpoint available!");
				System.exit(PlugtestServer.ERR_INIT_FAILED);
			}
			for (Endpoint ep : server.getEndpoints()) {
				ep.addNotificationListener(reverseObserver);
			}
			InetSocketAddress httpLocal = config.k8sMonitor;
			InetSocketAddress httpsRestore = config.k8sRestore;
			SSLContext context = null;
			RestoreHttpClient client = null;
			SSLContext clientContext = null;
	
			if (httpsRestore != null) {
				context = CredentialsUtil.getClusterInternalHttpsServerContext();
			}
			if (httpLocal != null || httpsRestore != null) {
				final JdkK8sMonitorService monitor = new JdkK8sMonitorService(httpLocal, httpsRestore, context);
				monitor.addServer(server);
				if (context != null && k8sGroup != null) {
					clientContext = CredentialsUtil.getClusterInternalHttpsClientContext();
					if (clientContext != null) {
						client = new RestoreHttpClient();
						monitor.addComponent(client);
					}
				}
				monitor.start();
			}

			PlugtestServer.add(server);
			PlugtestServer.load(config);
			// start standard plugtest server and shutdown
			PlugtestServer.start(executor, secondaryExecutor, config, null);

			server.start();

			// add special interceptor for message traces
			for (Endpoint ep : server.getEndpoints()) {
				URI uri = ep.getUri();
				if (!config.benchmark) {
					// Anonymized IoT metrics for validation.
					ep.addInterceptor(new AnonymizedOriginTracer(uri.getPort() + "-" + uri.getScheme()));
					ep.addInterceptor(new MessageTracer());
				}
				if (ep.getPostProcessInterceptors().isEmpty()) {
					long interval = ep.getConfig().get(SystemConfig.HEALTH_STATUS_INTERVAL, TimeUnit.MILLISECONDS);
					final HealthStatisticLogger healthLogger = new HealthStatisticLogger(uri.toASCIIString(),
							!CoAP.isTcpScheme(uri.getScheme()), interval, TimeUnit.MILLISECONDS, executor);
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
			}

			PlugtestServer.ActiveInputReader reader = new PlugtestServer.ActiveInputReader();
			if (!config.benchmark) {
				LOGGER.info("{} without benchmark started ...", ExtendedTestServer.class.getSimpleName());
				while (!server.isReady()) {
					Thread.sleep(500);
				}
				if (httpsRestore != null && client != null) {
					client.restore(k8sGroup, httpsRestore.getPort(), clientContext, server);
				}
				for (;;) {
					if (PlugtestServer.console(reader, 15000)) {
						break;
					}
				}
			} else {
				NetStatLogger netstat = new NetStatLogger("udp");
				Runtime runtime = Runtime.getRuntime();
				long max = runtime.maxMemory();
				StringBuilder builder = new StringBuilder(ExtendedTestServer.class.getSimpleName());
				if (StringUtil.CALIFORNIUM_VERSION != null) {
					builder.append(", version ").append(StringUtil.CALIFORNIUM_VERSION);
				}
				builder.append(", ").append(max / (1024 * 1024)).append("MB heap, started ...");
				LOGGER.info("{}", builder);
				while (!server.isReady()) {
					Thread.sleep(500);
				}
				if (httpsRestore != null && client != null) {
					client.restore(k8sGroup, httpsRestore.getPort(), clientContext, server);
				}
				long lastGcCount = 0;
				for (;;) {
					if (PlugtestServer.console(reader, 15000)) {
						break;
					}
					long used = runtime.totalMemory() - runtime.freeMemory();
					int fill = (int) ((used * 100L) / max);
					if (fill > 80) {
						LOGGER.info("Maxium heap size: {}M  {}% used.", max / (1024 * 1024), fill);
						LOGGER.info("Heap may exceed! Enlarge the maxium heap size.");
						LOGGER.info("Or consider to reduce the value of " + CoapConfig.EXCHANGE_LIFETIME);
						LOGGER.info("in \"{}\" or set", CONFIG_FILE);
						LOGGER.info("{} to {} or", CoapConfig.DEDUPLICATOR, CoapConfig.NO_DEDUPLICATOR);
						LOGGER.info("{} in that file.", CoapConfig.PEERS_MARK_AND_SWEEP_MESSAGES);
					}
					long gcCount = 0;
					for (GarbageCollectorMXBean gcMXBean : ManagementFactory.getGarbageCollectorMXBeans()) {
						long count = gcMXBean.getCollectionCount();
						if (0 < count) {
							gcCount += count;
						}
					}
					if (lastGcCount < gcCount) {
						printManagamentStatistic();
						lastGcCount = gcCount;
						netstat.dump();
						long clones = DatagramWriter.COPIES.get();
						long takes = DatagramWriter.TAKES.get();
						if (clones + takes > 0) {
							STATISTIC_LOGGER.info("DatagramWriter {} clones, {} takes, {}%", clones, takes,
									(takes * 100L) / (takes + clones));
						}
					}
				}
			}
			PlugtestServer.shutdown();
			server.stop();
			LOGGER.info("Executor shutdown ...");
			ExecutorsUtil.shutdownExecutorGracefully(500, executor, secondaryExecutor);
			PlugtestServer.exit();
			LOGGER.info("Exit ...");
		} catch (Exception e) {

			System.err.printf("Failed to create " + ExtendedTestServer.class.getSimpleName() + ": %s\n",
					e.getMessage());
			e.printStackTrace(System.err);
			System.err.println("Exiting");
			System.exit(PlugtestServer.ERR_INIT_FAILED);
		}
	}

	private static void startManagamentStatistic() {
		ThreadMXBean mxBean = ManagementFactory.getThreadMXBean();
		if (mxBean.isThreadCpuTimeSupported() && !mxBean.isThreadCpuTimeEnabled()) {
			mxBean.setThreadCpuTimeEnabled(true);
		}
	}

	private static void printManagamentStatistic() {
		OperatingSystemMXBean osMxBean = ManagementFactory.getOperatingSystemMXBean();
		int processors = osMxBean.getAvailableProcessors();
		Logger logger = STATISTIC_LOGGER;
		logger.info("{} processors", processors);
		ThreadMXBean threadMxBean = ManagementFactory.getThreadMXBean();
		if (threadMxBean.isThreadCpuTimeSupported() && threadMxBean.isThreadCpuTimeEnabled()) {
			long alltime = 0;
			long[] ids = threadMxBean.getAllThreadIds();
			for (long id : ids) {
				long time = threadMxBean.getThreadCpuTime(id);
				if (0 < time) {
					alltime += time;
				}
			}
			long pTime = alltime / processors;
			logger.info("cpu-time: {} ms (per-processor: {} ms)", TimeUnit.NANOSECONDS.toMillis(alltime),
					TimeUnit.NANOSECONDS.toMillis(pTime));
		}
		long gcCount = 0;
		long gcTime = 0;
		for (GarbageCollectorMXBean gcMxBean : ManagementFactory.getGarbageCollectorMXBeans()) {
			long count = gcMxBean.getCollectionCount();
			if (0 < count) {
				gcCount += count;
			}
			long time = gcMxBean.getCollectionTime();
			if (0 < time) {
				gcTime += time;
			}
		}
		logger.info("gc: {} ms, {} calls", gcTime, gcCount);
		MemoryMXBean memoryMxBean = ManagementFactory.getMemoryMXBean();
		printMemoryUsage(logger, "heap", memoryMxBean.getHeapMemoryUsage());
		printMemoryUsage(logger, "non-heap", memoryMxBean.getNonHeapMemoryUsage());
		double loadAverage = osMxBean.getSystemLoadAverage();
		if (!(loadAverage < 0.0d)) {
			logger.info("average load: {}", String.format("%.2f", loadAverage));
		}
	}

	private static void printMemoryUsage(Logger logger, String title, MemoryUsage memoryUsage) {
		long max = memoryUsage.getMax();
		if (max > 0) {
			if (max > MEGA) {
				logger.info("{}: {} m-bytes used of {}/{}.", title, memoryUsage.getUsed() / MEGA,
						memoryUsage.getCommitted() / MEGA, max / MEGA);
			} else {
				logger.info("{}: {} bytes used of {}/{}.", title, memoryUsage.getUsed(), memoryUsage.getCommitted(),
						max);
			}
			return;
		}
		max = memoryUsage.getCommitted();
		if (max > MEGA) {
			logger.info("{}: {} m-bytes used of {}.", title, memoryUsage.getUsed() / MEGA, max / MEGA);
		} else {
			logger.info("{}: {} bytes used of {}.", title, memoryUsage.getUsed(), max);
		}
	}

	public ExtendedTestServer(Configuration config, Map<Select, Configuration> protocolConfig, boolean noBenchmark)
			throws SocketException {
		super(config, protocolConfig);
		int maxResourceSize = config.get(CoapConfig.MAX_RESOURCE_BODY_SIZE);
		// add resources to the server
		add(new RequestStatistic());
		add(new Benchmark(noBenchmark, maxResourceSize));
		add(new Hono("telemetry"));
		add(new Hono("event"));
		add(new MyIpResource(MyIpResource.RESOURCE_NAME, true));
		add(new MyContext(MyContext.RESOURCE_NAME, version, true));
	}

	private boolean isReady() {
		for (Readiness component : components) {
			if (!component.isReady()) {
				return false;
			}
		}
		return true;
	}

	private void addClusterEndpoint(ScheduledExecutorService secondaryExecutor, InetSocketAddress dtlsInterface,
			int nodeId, DtlsClusterConnectorConfig clusterConfiguration, ClusterNodesProvider nodesProvider,
			ClusterNodesDiscover nodesDiscoverer, BaseConfig cliConfig) {
		if (nodesDiscoverer == null ^ nodesProvider != null) {
			throw new IllegalArgumentException("either nodes-provider or -dicoverer is required!");
		}
		InterfaceType interfaceType = dtlsInterface.getAddress().isLoopbackAddress() ? InterfaceType.LOCAL
				: InterfaceType.EXTERNAL;
		Configuration configuration = getConfig(Protocol.DTLS, interfaceType);
		int handshakeResultDelayMillis = configuration.getTimeAsInt(DTLS_HANDSHAKE_RESULT_DELAY, TimeUnit.MILLISECONDS);
		long healthStatusIntervalMillis = configuration.get(SystemConfig.HEALTH_STATUS_INTERVAL, TimeUnit.MILLISECONDS);
		Integer cidLength = configuration.get(DtlsConfig.DTLS_CONNECTION_ID_LENGTH);
		if (cidLength == null || cidLength < 6) {
			throw new IllegalArgumentException("cid length must be at least 6 for cluster!");
		}
		initCredentials();
		DtlsConnectorConfig.Builder dtlsConfigBuilder = DtlsConnectorConfig.builder(configuration);
		if (cliConfig.clientAuth != null) {
			configuration.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, cliConfig.clientAuth);
		}
		// set node-id in dtls-config-builder's Configuration clone
		dtlsConfigBuilder.set(DtlsConfig.DTLS_CONNECTION_ID_NODE_ID, nodeId);
		AsyncAdvancedPskStore asyncPskStore = new AsyncAdvancedPskStore(new PlugPskStore());
		asyncPskStore.setDelay(handshakeResultDelayMillis);
		dtlsConfigBuilder.setAdvancedPskStore(asyncPskStore);
		dtlsConfigBuilder.setAddress(dtlsInterface);
		X509KeyManager keyManager = SslContextUtil.getX509KeyManager(serverCredentials);
		AsyncKeyManagerCertificateProvider certificateProvider = new AsyncKeyManagerCertificateProvider(keyManager,
				CertificateType.RAW_PUBLIC_KEY, CertificateType.X_509);
		certificateProvider.setDelay(handshakeResultDelayMillis);
		dtlsConfigBuilder.setCertificateIdentityProvider(certificateProvider);
		AsyncNewAdvancedCertificateVerifier.Builder verifierBuilder = AsyncNewAdvancedCertificateVerifier.builder();
		if (cliConfig.trustall) {
			verifierBuilder.setTrustAllCertificates();
		} else {
			verifierBuilder.setTrustedCertificates(trustedCertificates);
		}
		verifierBuilder.setTrustAllRPKs();
		AsyncNewAdvancedCertificateVerifier verifier = verifierBuilder.build();
		verifier.setDelay(handshakeResultDelayMillis);
		dtlsConfigBuilder.setAdvancedCertificateVerifier(verifier);
		dtlsConfigBuilder.setConnectionListener(new MdcConnectionListener());
		dtlsConfigBuilder.setLoggingTag("node-" + nodeId);
		DtlsConnectorConfig dtlsConnectorConfig = dtlsConfigBuilder.build();
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		EndpointObserver endpointObserver = null;
		if (nodesDiscoverer != null) {
			DtlsManagedClusterConnector connector = new DtlsManagedClusterConnector(dtlsConnectorConfig,
					clusterConfiguration);
			final DtlsClusterManager manager = new DtlsClusterManager(connector, dtlsConnectorConfig.getConfiguration(),
					nodesDiscoverer, secondaryExecutor);
			builder.setConnector(connector);
			endpointObserver = new EndpointObserver() {

				@Override
				public void stopped(Endpoint endpoint) {
					manager.stop();
				}

				@Override
				public void started(Endpoint endpoint) {
					manager.start();
				}

				@Override
				public void destroyed(Endpoint endpoint) {
					manager.stop();
				}
			};
			components.add( manager);
		} else if (nodesProvider != null) {
			builder.setConnector(new DtlsClusterConnector(dtlsConnectorConfig, clusterConfiguration, nodesProvider));
		}
		// use dtls-config-builder's Configuration clone with the set node-id
		builder.setConfiguration(dtlsConnectorConfig.getConfiguration());
		CoapEndpoint endpoint = builder.build();
		if (healthStatusIntervalMillis > 0) {
			String tag = CoAP.COAP_SECURE_URI_SCHEME;
			tag += "-" + nodeId;
			final HealthStatisticLogger healthLogger = new HealthStatisticLogger(tag, true, healthStatusIntervalMillis,
					 TimeUnit.MILLISECONDS, secondaryExecutor);
			if (healthLogger.isEnabled()) {
				endpoint.addPostProcessInterceptor(healthLogger);
				endpoint.addObserver(new EndpointObserver() {

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
		if (endpointObserver != null) {
			endpoint.addObserver(endpointObserver);
		}
		addEndpoint(endpoint);
		print(endpoint, interfaceType);
	}

	private static class ClusterGroup implements ClusterNodesDiscover {

		private final List<InetSocketAddress> group;

		private ClusterGroup(List<InetSocketAddress> group) {
			this.group = group;
		}

		@Override
		public List<InetSocketAddress> getClusterNodesDiscoverScope() {
			return group;
		}

		@Override
		public int getInitialClusterNodes() {
			return group.size();
		}
	}

	private static class ClusterNode {

		final InetSocketAddress dtls;
		final InetSocketAddress cluster;
		final int nodeId;

		private ClusterNode(String[] args) throws Exception {
			if (args.length != 3) {
				throw new IllegalArgumentException(
						"a cluster definition must contain 3 parts, <dtls-intf>;<mgmt-intf>;nodeid");
			}
			if (args[0].equals("---")) {
				dtls = null;
			} else {
				dtls = addressDefinition.convert(args[0]);
			}
			cluster = addressDefinition.convert(args[1]);
			nodeId = Integer.parseInt(args[2]);
		}

	}

	private static ITypeConverter<ClusterNode> clusterDefinition = new ITypeConverter<ClusterNode>() {

		@Override
		public ClusterNode convert(String value) throws Exception {
			return new ClusterNode(value.split(";"));
		}
	};

	private static ITypeConverter<InetSocketAddress> addressDefinition = new ITypeConverter<InetSocketAddress>() {

		@Override
		public InetSocketAddress convert(String value) throws Exception {
			if (value.startsWith(":")) {
				// port only => any local address
				int port = Integer.parseInt(value.substring(1));
				System.out.println("'" + value + "' => <any>:" + port);
				return new InetSocketAddress(port);
			} else {
				// use dummy schema
				URI uri = new URI("cluster://" + value);
				String host = uri.getHost();
				int port = uri.getPort();
				System.out.println("'" + value + "' => " + host + ":" + port);
				return new InetSocketAddress(host, port);
			}
		}

	};

	private static class K8sCluster {

		final InetSocketAddress dtls;
		final InetSocketAddress cluster;
		final int externalPort;

		private K8sCluster(String[] args) throws Exception {
			if (args.length != 3) {
				throw new IllegalArgumentException(
						"a k8s cluster definition must contain 2 parts, <dtls-intf>;<mgmt-intf>;ext-mgmt-port");
			}
			dtls = addressDefinition.convert(args[0]);
			cluster = addressDefinition.convert(args[1]);
			externalPort = Integer.parseInt(args[2]);
		}

	}

	private static ITypeConverter<K8sCluster> k8sClusterDefinition = new ITypeConverter<K8sCluster>() {

		@Override
		public K8sCluster convert(String value) throws Exception {
			return new K8sCluster(value.split(";"));
		}
	};
}
