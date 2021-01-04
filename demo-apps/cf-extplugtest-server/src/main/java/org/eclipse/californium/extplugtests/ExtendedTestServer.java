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
import java.lang.management.OperatingSystemMXBean;
import java.lang.management.ThreadMXBean;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import org.eclipse.californium.cluster.DtlsClusterManagerConfig;
import org.eclipse.californium.cluster.DtlsClusterManager;
import org.eclipse.californium.cluster.DtlsClusterManager.ClusterNodesDiscover;
import org.eclipse.californium.cluster.K8sManagementDiscoverClient;
import org.eclipse.californium.cluster.K8sManagementDiscoverJdkClient;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointContextMatcherFactory.MatcherMode;
import org.eclipse.californium.core.network.EndpointObserver;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.config.NetworkConfigDefaultHandler;
import org.eclipse.californium.core.network.interceptors.AnonymizedOriginTracer;
import org.eclipse.californium.core.network.interceptors.HealthStatisticLogger;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.elements.PrincipalEndpointContextMatcher;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.extplugtests.resources.Benchmark;
import org.eclipse.californium.extplugtests.resources.RequestStatistic;
import org.eclipse.californium.extplugtests.resources.ReverseObserve;
import org.eclipse.californium.extplugtests.resources.ReverseRequest;
import org.eclipse.californium.plugtests.AbstractTestServer;
import org.eclipse.californium.plugtests.PlugtestServer;
import org.eclipse.californium.plugtests.PlugtestServer.BaseConfig;
import org.eclipse.californium.plugtests.resources.Context;
import org.eclipse.californium.plugtests.resources.MyIp;
import org.eclipse.californium.scandium.DtlsClusterConnector;
import org.eclipse.californium.scandium.DtlsClusterConnector.ClusterNodesProvider;
import org.eclipse.californium.scandium.DtlsManagedClusterConnector;
import org.eclipse.californium.scandium.MdcConnectionListener;
import org.eclipse.californium.scandium.config.DtlsClusterConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.MultiNodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.AsyncAdvancedPskStore;
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

	private static final File CONFIG_FILE = new File("CaliforniumReceivetest.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for Receivetest Server";
	private static final int DEFAULT_MAX_RESOURCE_SIZE = 8192;
	private static final int DEFAULT_BLOCK_SIZE = 1024;

	private static NetworkConfigDefaultHandler DEFAULTS = new NetworkConfigDefaultHandler() {

		@Override
		public void applyDefaults(NetworkConfig config) {
			// start on alternative port, 5783 and 5784
			config.setInt(Keys.COAP_PORT, config.getInt(Keys.COAP_PORT) + 100);
			config.setInt(Keys.COAP_SECURE_PORT, config.getInt(Keys.COAP_SECURE_PORT) + 100);
			config.setInt(Keys.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.setInt(Keys.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.setInt(Keys.PEERS_MARK_AND_SWEEP_MESSAGES, 16);
			config.setString(Keys.DEDUPLICATOR, Keys.DEDUPLICATOR_PEERS_MARK_AND_SWEEP);
			config.setInt(Keys.MAX_ACTIVE_PEERS, 1000000);
			config.setInt(Keys.DTLS_AUTO_RESUME_TIMEOUT, 0);
			config.setInt(Keys.DTLS_CONNECTION_ID_LENGTH, 6);
			config.setInt(Keys.DTLS_CONNECTION_ID_NODE_ID, 1);
			config.setInt(Keys.MAX_PEER_INACTIVITY_PERIOD, 60); // 24h
			config.setInt(Keys.TCP_CONNECTION_IDLE_TIMEOUT, 60 * 60 * 12); // 12h
			config.setInt(Keys.TLS_HANDSHAKE_TIMEOUT, 60 * 1000); // 60s
			config.setInt(Keys.SECURE_SESSION_TIMEOUT, 60 * 60 * 24); // 24h
			config.setInt(Keys.HEALTH_STATUS_INTERVAL, 60); // 60s
			config.setInt(Keys.UDP_CONNECTOR_RECEIVE_BUFFER, 0);
			config.setInt(Keys.UDP_CONNECTOR_SEND_BUFFER, 0);
			config.setInt(KEY_DTLS_HANDSHAKE_RESULT_DELAY, 0);
			int processors = Runtime.getRuntime().availableProcessors();
			config.setInt(Keys.NETWORK_STAGE_RECEIVER_THREAD_COUNT, processors > 3 ? 2 : 1);
			config.setInt(Keys.NETWORK_STAGE_SENDER_THREAD_COUNT, processors);
		}

	};

	private static final class Time implements ClockUtil.Realtime {
		
		@Override
		public long nanoRealtime() {
			return System.nanoTime() + getTestTimeShiftNanos();
		}

		/**
		 * Current test time shift in nanoseconds.
		 * 
		 * @see #addTestTimeShift(long, TimeUnit)
		 * @see #setTestTimeShift(long, TimeUnit)
		 * @see #getTestTimeShiftNanos()
		 */
		private long timeShiftNanos;

		/**
		 * Set time shift.
		 * 
		 * @param shift time shift
		 * @param unit unit of time shift
		 */
		public final synchronized void setTestTimeShift(final long shift, final TimeUnit unit) {
			LOGGER.debug("set {} {} as timeshift", shift, unit);
			timeShiftNanos = unit.toNanos(shift);
		}

		/**
		 * Gets current time shift in nanoseconds.
		 * 
		 * @return time shift in nanoseconds
		 */
		public final synchronized long getTestTimeShiftNanos() {
			return timeShiftNanos;
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

	public static void main(String[] args) {
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
		Time handler = new Time();
		long nanoRealtime = ClockUtil.nanoRealtime();
		long delta = new Random().nextLong();
		if (nanoRealtime + delta < 0) {
//			delta = -nanoRealtime;
		}
		handler.setTestTimeShift(delta, TimeUnit.NANOSECONDS);
		ClockUtil.setRealtimeHandler(handler);
		STATISTIC_LOGGER.error("start!");
		startManagamentStatistic();
		try {
			K8sManagementDiscoverClient k8sGroup = null;
			DtlsClusterConnectorConfig.Builder clusterConfigBuilder = DtlsClusterConnectorConfig.builder();
			NetworkConfig netConfig = NetworkConfig.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
			if (config.cluster != null) {
				int nodeId;
				clusterConfigBuilder.setBackwardMessage(config.cluster.backwardClusterMessages);
				if (config.cluster.clusterType.k8sCluster != null) {
					clusterConfigBuilder.setAddress(config.cluster.clusterType.k8sCluster.cluster);
					clusterConfigBuilder.setClusterMac(config.cluster.dtlsClusterMac);
					K8sManagementDiscoverClient.setConfiguration(clusterConfigBuilder);
					k8sGroup = new K8sManagementDiscoverJdkClient(config.cluster.clusterType.k8sCluster.externalPort);
					nodeId = k8sGroup.getNodeID();
					LOGGER.info("dynamic k8s-cluster!");
				} else {
					nodeId = -1;
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
				netConfig.setInt(Keys.DTLS_CONNECTION_ID_NODE_ID, nodeId);
			} else if (config.plugtest) {
				// start standard plugtest server
				PlugtestServer.init(config);
			}

			NetworkConfig udpConfig = new NetworkConfig(netConfig);
			udpConfig.setInt(Keys.MAX_MESSAGE_SIZE, 64);
			udpConfig.setInt(Keys.PREFERRED_BLOCK_SIZE, 64);
			Map<Select, NetworkConfig> protocolConfig = new HashMap<>();
			protocolConfig.put(new Select(Protocol.UDP, InterfaceType.EXTERNAL), udpConfig);

			// create server
			List<Protocol> protocols = config.getProtocols();

			List<InterfaceType> types = config.getInterfaceTypes();

			ScheduledExecutorService executor = ExecutorsUtil.newScheduledThreadPool(//
					netConfig.getInt(NetworkConfig.Keys.PROTOCOL_STAGE_THREAD_COUNT), //
					new NamedThreadFactory("ExtCoapServer(main)#")); //$NON-NLS-1$
			ScheduledExecutorService secondaryExecutor = ExecutorsUtil
					.newDefaultSecondaryScheduler("ExtCoapServer(secondary)#");

			ExtendedTestServer server = new ExtendedTestServer(netConfig, protocolConfig, !config.benchmark);
			server.setTag("EXTENDED-TEST");
			server.setExecutors(executor, secondaryExecutor, false);
			server.add(new ReverseRequest(netConfig, executor));
			ReverseObserve reverseObserver = new ReverseObserve(netConfig, executor);
			server.add(reverseObserver);

			if (k8sGroup != null) {
				server.addClusterEndpoint(secondaryExecutor, config.cluster.clusterType.k8sCluster.dtls,
						k8sGroup.getNodeID(), clusterConfigBuilder.build(), null, k8sGroup, config);
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
					int interval = ep.getConfig().getInt(NetworkConfig.Keys.HEALTH_STATUS_INTERVAL);
					final HealthStatisticLogger healthLogger = new HealthStatisticLogger(uri.toASCIIString(),
							!CoAP.isTcpScheme(uri.getScheme()), interval, executor);
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
						LOGGER.info("Or consider to reduce the value of " + Keys.EXCHANGE_LIFETIME);
						LOGGER.info("in \"{}\" or set", CONFIG_FILE);
						LOGGER.info("{} to {} or", Keys.DEDUPLICATOR, Keys.NO_DEDUPLICATOR);
						LOGGER.info("{} in that file.", Keys.PEERS_MARK_AND_SWEEP_MESSAGES);
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

	public ExtendedTestServer(NetworkConfig config, Map<Select, NetworkConfig> protocolConfig, boolean noBenchmark)
			throws SocketException {
		super(config, protocolConfig);
		int maxResourceSize = config.getInt(Keys.MAX_RESOURCE_BODY_SIZE);
		// add resources to the server
		add(new RequestStatistic());
		add(new Benchmark(noBenchmark, maxResourceSize));
		add(new MyIp(MyIp.RESOURCE_NAME, true));
		add(new Context(Context.RESOURCE_NAME, true));
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
		double loadAverage = osMxBean.getSystemLoadAverage();
		if (!(loadAverage < 0.0d)) {
			logger.info("average load: {}", String.format("%.2f", loadAverage));
		}
	}

	private void addClusterEndpoint(ScheduledExecutorService secondaryExecutor, InetSocketAddress dtlsInterface,
			int nodeId, DtlsClusterConnectorConfig configuration, ClusterNodesProvider nodesProvider,
			ClusterNodesDiscover nodesDiscoverer, BaseConfig cliConfig) {
		if (nodesDiscoverer == null ^ nodesProvider != null) {
			throw new IllegalArgumentException("either nodes-provider or -dicoverer is required!");
		}
		InterfaceType interfaceType = dtlsInterface.getAddress().isLoopbackAddress() ? InterfaceType.LOCAL
				: InterfaceType.EXTERNAL;
		NetworkConfig netConfig = getConfig(Protocol.DTLS, interfaceType);
		Integer cidLength = netConfig.getOptInteger(Keys.DTLS_CONNECTION_ID_LENGTH);
		if (cidLength == null || cidLength < 6) {
			throw new IllegalArgumentException("cid length must be at least 6 for cluster!");
		}
		initCredentials();
		int retransmissionTimeout = netConfig.getInt(Keys.ACK_TIMEOUT);
		int staleTimeout = netConfig.getInt(Keys.MAX_PEER_INACTIVITY_PERIOD);
		int dtlsThreads = netConfig.getInt(Keys.NETWORK_STAGE_SENDER_THREAD_COUNT);
		int dtlsReceiverThreads = netConfig.getInt(Keys.NETWORK_STAGE_RECEIVER_THREAD_COUNT);
		int maxPeers = netConfig.getInt(Keys.MAX_ACTIVE_PEERS);
		int handshakeResultDelay = netConfig.getInt(KEY_DTLS_HANDSHAKE_RESULT_DELAY, 0);
		Integer healthStatusInterval = netConfig.getOptInteger(Keys.HEALTH_STATUS_INTERVAL); // seconds
		Integer recvBufferSize = netConfig.getOptInteger(Keys.UDP_CONNECTOR_RECEIVE_BUFFER);
		Integer sendBufferSize = netConfig.getOptInteger(Keys.UDP_CONNECTOR_SEND_BUFFER);
		DtlsConnectorConfig.Builder dtlsConfigBuilder = new DtlsConnectorConfig.Builder();
		dtlsConfigBuilder.setConnectionIdGenerator(new MultiNodeConnectionIdGenerator(nodeId, cidLength));
		AsyncAdvancedPskStore asyncPskStore = new AsyncAdvancedPskStore(new PlugPskStore());
		asyncPskStore.setDelay(handshakeResultDelay);
		dtlsConfigBuilder.setAdvancedPskStore(asyncPskStore);
		dtlsConfigBuilder.setAddress(dtlsInterface);
		dtlsConfigBuilder.setSupportedCipherSuites(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
				CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
		dtlsConfigBuilder.setIdentity(serverCredentials.getPrivateKey(), serverCredentials.getCertificateChain(),
				CertificateType.RAW_PUBLIC_KEY, CertificateType.X_509);
		AsyncNewAdvancedCertificateVerifier.Builder verifierBuilder = AsyncNewAdvancedCertificateVerifier.builder();
		if (cliConfig.trustall) {
			verifierBuilder.setTrustAllCertificates();
		} else {
			verifierBuilder.setTrustedCertificates(trustedCertificates);
		}
		verifierBuilder.setTrustAllRPKs();
		AsyncNewAdvancedCertificateVerifier verifier = verifierBuilder.build();
		verifier.setDelay(handshakeResultDelay);
		dtlsConfigBuilder.setAdvancedCertificateVerifier(verifier);
		dtlsConfigBuilder.setMaxConnections(maxPeers);
		dtlsConfigBuilder.setStaleConnectionThreshold(staleTimeout);
		dtlsConfigBuilder.setConnectionThreadCount(dtlsThreads);
		dtlsConfigBuilder.setReceiverThreadCount(dtlsReceiverThreads);
		dtlsConfigBuilder.setHealthStatusInterval(healthStatusInterval);
		dtlsConfigBuilder.setSocketReceiveBufferSize(recvBufferSize);
		dtlsConfigBuilder.setSocketSendBufferSize(sendBufferSize);
		dtlsConfigBuilder.setRetransmissionTimeout(retransmissionTimeout);
		dtlsConfigBuilder.setConnectionListener(new MdcConnectionListener());
		dtlsConfigBuilder.setCidUpdateAddressOnNewerRecordFilter(true);
		dtlsConfigBuilder.setLoggingTag("node-" + nodeId);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		EndpointObserver endpointObserver = null;
		if (nodesDiscoverer != null) {
			DtlsManagedClusterConnector connector = new DtlsManagedClusterConnector(dtlsConfigBuilder.build(),
					configuration);
			DtlsClusterManagerConfig clusterConfig = DtlsClusterManagerConfig.builder().build();
			final DtlsClusterManager manager = new DtlsClusterManager(connector, clusterConfig, nodesDiscoverer,
					secondaryExecutor);
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
		} else if (nodesProvider != null) {
			builder.setConnector(new DtlsClusterConnector(dtlsConfigBuilder.build(), configuration, nodesProvider));
		}
		if (MatcherMode.PRINCIPAL.name().equals(netConfig.getString(Keys.RESPONSE_MATCHING))) {
			builder.setEndpointContextMatcher(new PrincipalEndpointContextMatcher(true));
		}
		builder.setNetworkConfig(netConfig);
		CoapEndpoint endpoint = builder.build();
		if (healthStatusInterval != null) {
			String tag = CoAP.COAP_SECURE_URI_SCHEME;
			tag += "-" + nodeId;
			final HealthStatisticLogger healthLogger = new HealthStatisticLogger(tag, true, healthStatusInterval,
					secondaryExecutor);
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
