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
import java.net.InetAddress;
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
import org.eclipse.californium.cluster.JdkMonitorService;
import org.eclipse.californium.cluster.K8sDiscoverClient;
import org.eclipse.californium.cluster.K8sManagementClient;
import org.eclipse.californium.cluster.K8sManagementJdkClient;
import org.eclipse.californium.cluster.K8sRestoreJdkHttpClient;
import org.eclipse.californium.cluster.Readiness;
import org.eclipse.californium.cluster.config.DtlsClusterManagerConfig;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.config.CoapConfig.MatcherMode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointObserver;
import org.eclipse.californium.core.network.interceptors.HealthStatisticLogger;
import org.eclipse.californium.core.observe.ObserveStatisticLogger;
import org.eclipse.californium.core.server.resources.MyIpResource;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.config.SystemConfig;
import org.eclipse.californium.elements.config.TcpConfig;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.CounterStatisticManager;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.elements.util.SimpleCounterStatistic;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.extplugtests.resources.Benchmark;
import org.eclipse.californium.extplugtests.resources.Diagnose;
import org.eclipse.californium.extplugtests.resources.RequestStatistic;
import org.eclipse.californium.extplugtests.resources.ReverseObserve;
import org.eclipse.californium.extplugtests.resources.ReverseRequest;
import org.eclipse.californium.plugtests.AbstractTestServer;
import org.eclipse.californium.plugtests.EndpointNetSocketObserver;
import org.eclipse.californium.plugtests.PlugtestServer;
import org.eclipse.californium.plugtests.PlugtestServer.BaseConfig;
import org.eclipse.californium.plugtests.resources.Echo;
import org.eclipse.californium.plugtests.resources.Hono;
import org.eclipse.californium.plugtests.resources.MyContext;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.DtlsClusterConnector;
import org.eclipse.californium.scandium.DtlsClusterConnector.ClusterNodesProvider;
import org.eclipse.californium.scandium.DtlsClusterHealthLogger;
import org.eclipse.californium.scandium.DtlsHealthLogger;
import org.eclipse.californium.scandium.DtlsManagedClusterConnector;
import org.eclipse.californium.scandium.MdcConnectionListener;
import org.eclipse.californium.scandium.config.DtlsClusterConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.AsyncAdvancedPskStore;
import org.eclipse.californium.scandium.dtls.x509.AsyncKeyManagerCertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.AsyncNewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.eclipse.californium.unixhealth.NetSocketHealthLogger;
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
	/**
	 * @since 3.10
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(CoapServer.class);

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
			int processors = Runtime.getRuntime().availableProcessors();
			config.set(DTLS_HANDSHAKE_RESULT_DELAY, 0, TimeUnit.MILLISECONDS);
			config.set(CoapConfig.COAP_PORT, CoapConfig.COAP_PORT.getDefaultValue() + 100);
			config.set(CoapConfig.COAP_SECURE_PORT, CoapConfig.COAP_SECURE_PORT.getDefaultValue() + 100);
			config.set(CoapConfig.MAX_RESOURCE_BODY_SIZE, DEFAULT_MAX_RESOURCE_SIZE);
			config.set(CoapConfig.MAX_MESSAGE_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.PREFERRED_BLOCK_SIZE, DEFAULT_BLOCK_SIZE);
			config.set(CoapConfig.PEERS_MARK_AND_SWEEP_MESSAGES, 16);
			config.set(CoapConfig.DEDUPLICATOR, CoapConfig.DEDUPLICATOR_PEERS_MARK_AND_SWEEP);
			config.set(CoapConfig.MAX_ACTIVE_PEERS, 1000000);
			config.set(CoapConfig.MAX_PEER_INACTIVITY_PERIOD, 3, TimeUnit.MINUTES);
			config.set(CoapConfig.RESPONSE_MATCHING, MatcherMode.PRINCIPAL_IDENTITY);
			config.set(DtlsConfig.DTLS_MAX_CONNECTIONS, 1000000);
			config.set(DtlsConfig.DTLS_STALE_CONNECTION_THRESHOLD, 3, TimeUnit.MINUTES);
			config.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false);
			config.set(DtlsConfig.DTLS_AUTO_HANDSHAKE_TIMEOUT, null, TimeUnit.SECONDS);
			config.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 6);
			config.set(DtlsConfig.DTLS_PRESELECTED_CIPHER_SUITES, PlugtestServer.PRESELECTED_CIPHER_SUITES);
			config.set(DtlsConfig.DTLS_RECEIVE_BUFFER_SIZE, 1000000);
			config.set(DtlsConfig.DTLS_RECEIVER_THREAD_COUNT, processors > 3 ? 2 : 1);
			config.set(DtlsConfig.DTLS_REMOVE_STALE_DOUBLE_PRINCIPALS, true);
			config.set(DtlsConfig.DTLS_MAC_ERROR_FILTER_QUIET_TIME, 4, TimeUnit.SECONDS);
			config.set(DtlsConfig.DTLS_MAC_ERROR_FILTER_THRESHOLD, 8);
			config.set(DtlsConfig.DTLS_RETRANSMISSION_TIMEOUT, 3, TimeUnit.SECONDS);
			config.set(DtlsConfig.DTLS_ADDITIONAL_ECC_TIMEOUT, 8, TimeUnit.SECONDS);
			config.set(TcpConfig.TCP_CONNECT_TIMEOUT, 15, TimeUnit.SECONDS);
			config.set(TcpConfig.TCP_CONNECTION_IDLE_TIMEOUT, 60, TimeUnit.MINUTES);
			config.set(TcpConfig.TLS_HANDSHAKE_TIMEOUT, 60, TimeUnit.SECONDS);
			config.set(SystemConfig.HEALTH_STATUS_INTERVAL, 60, TimeUnit.SECONDS);
			config.set(UdpConfig.UDP_RECEIVER_THREAD_COUNT, processors > 3 ? 2 : 1);
			config.set(UdpConfig.UDP_SENDER_THREAD_COUNT, processors > 3 ? processors : 2);
			config.set(EXTERNAL_UDP_MAX_MESSAGE_SIZE, 64);
			config.set(EXTERNAL_UDP_PREFERRED_BLOCK_SIZE, 64);
			config.set(UDP_DROPS_READ_INTERVAL, 2000, TimeUnit.MILLISECONDS);
		}

	};

	@Command(name = "ExtendedTestServer", version = "(c) 2017-2020, Bosch.IO GmbH and others.")
	private static class Config extends PlugtestServer.BaseConfig {

		@Option(names = "--no-plugtest", negatable = true, description = "enable plugtest server.")
		public boolean plugtest = true;

		@Option(names = "--benchmark", negatable = true, description = "enable benchmark resource.")
		public boolean benchmark;

		@Option(names = "--diagnose", negatable = true, description = "enable diagnose resource.")
		public boolean diagnose;

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

		@Option(names = "--k8s-monitor", description = "enable k8s monitor. http interface for k8s monitoring.")
		public InetSocketAddress k8sMonitor;

		public static class RestorePair {

			@Option(names = "--local-restore", required = true, description = "enable restore for graceful restart. Local https interface to load connections from.")
			public InetSocketAddress restoreLocal;

			@Option(names = "--other-restore", required = true, description = "enable restore for graceful restart. Other's https interface to load connections from.")
			public InetSocketAddress restoreOther;
		}

		public static class RestoreSource {

			@Option(names = "--k8s-restore", description = "enable k8s restore for graceful restart. https interface to load connections from.")
			public InetSocketAddress restoreK8s;

			@ArgGroup(exclusive = false)
			public RestorePair restorePair;
		}

		@ArgGroup(exclusive = false)
		public Restore restore;

		public static class Restore {

			@ArgGroup(exclusive = true)
			public RestoreSource restoreSource;

			@Option(names = "--restore-max-age", defaultValue = "12", description = "maximum age of connections in hours. Default ${DEFAULT-VALUE} [h]")
			public long maxAge;
		}

		public void register(CommandLine cmd) {
			cmd.registerConverter(ClusterNode.class, clusterDefinition);
			cmd.registerConverter(InetSocketAddress.class, addressDefinition);
			cmd.registerConverter(K8sCluster.class, k8sClusterDefinition);
		}

		public List<Protocol> getProtocols() {
			List<Protocol> protocols = super.getProtocols();
			if (cluster != null || restore != null) {
				// cluster uses specific dtls connector
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

	public static void main(String[] args) {
		CommandLine cmd = new CommandLine(config);
		config.register(cmd);
		try {
			ParseResult result = cmd.parseArgs(args);
			if (result.isVersionHelpRequested()) {
				System.out.println(
						"\nCalifornium (Cf) " + cmd.getCommandName() + " " + PlugtestServer.CALIFORNIUM_BUILD_VERSION);
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
		ManagementStatistic management = new ManagementStatistic(STATISTIC_LOGGER);
		try {
			K8sManagementClient k8sClient = null;
			K8sDiscoverClient k8sGroup = null;
			DtlsClusterConnectorConfig.Builder clusterConfigBuilder = DtlsClusterConnectorConfig.builder();
			Configuration configuration = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
			if (config.cluster != null) {
				int nodeId = -1;
				clusterConfigBuilder.setBackwardMessage(config.cluster.backwardClusterMessages);
				if (config.cluster.clusterType.k8sCluster != null) {
					clusterConfigBuilder.setAddress(config.cluster.clusterType.k8sCluster.cluster);
					clusterConfigBuilder.setClusterMac(config.cluster.dtlsClusterMac);
					K8sDiscoverClient.setConfiguration(clusterConfigBuilder);
					k8sClient = new K8sManagementJdkClient();
					k8sGroup = new K8sDiscoverClient(k8sClient, config.cluster.clusterType.k8sCluster.externalPort);
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

			ScheduledExecutorService executor = ExecutorsUtil.newScheduledThreadPool(//
					configuration.get(CoapConfig.PROTOCOL_STAGE_THREAD_COUNT), //
					new NamedThreadFactory("ExtCoapServer(main)#")); //$NON-NLS-1$
			ScheduledExecutorService secondaryExecutor = ExecutorsUtil
					.newDefaultSecondaryScheduler("ExtCoapServer(secondary)#");

			long notifyIntervalMillis = config.getNotifyIntervalMillis();

			final ExtendedTestServer server = new ExtendedTestServer(configuration, protocolConfig, config.benchmark,
					notifyIntervalMillis);
			server.setVersion(PlugtestServer.CALIFORNIUM_BUILD_VERSION);
			server.setTag("EXTENDED-TEST");
			server.setExecutors(executor, secondaryExecutor, false);
			server.add(new Echo(configuration, config.echoDelay ? executor : null));
			if (config.diagnose) {
				server.add(new Diagnose(server));
			}
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
			} else if (config.restore != null) {
				// restore the dtls state from an other host with different
				// local network addresses,
				// requires to use the wildcard address for the connector.
				int port = configuration.get(CoapConfig.COAP_SECURE_PORT);
				server.addEndpoint(new InetSocketAddress(port), config);
			}

			// Statistic for dropped udp messages
			final NetSocketHealthLogger socketLogger = new NetSocketHealthLogger("udp");
			EndpointNetSocketObserver socketObserver = null;
			long interval = configuration.get(SystemConfig.HEALTH_STATUS_INTERVAL, TimeUnit.MILLISECONDS);
			if (interval > 0 && socketLogger.isEnabled()) {
				server.add(socketLogger);
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
				server.addDefaultEndpointObserver(socketObserver);
				EndpointNetSocketObserver internalSocketObserver = new EndpointNetSocketObserver(socketLogger) {

					protected SimpleCounterStatistic getExternalStatistic(Endpoint endpoint) {
						CounterStatisticManager dtlsStatisticManager = getDtlsStatisticManager(endpoint);
						return dtlsStatisticManager != null
								? dtlsStatisticManager.getByKey(DtlsClusterHealthLogger.DROPPED_INTERNAL_UDP_MESSAGES)
								: null;
					}

					@Override
					protected InetSocketAddress getAddress(Endpoint endpoint) {
						if (endpoint instanceof CoapEndpoint) {
							Connector connector = ((CoapEndpoint) endpoint).getConnector();
							if (connector instanceof DtlsClusterConnector) {
								return ((DtlsClusterConnector) connector).getClusterInternalAddress();
							}
						}
						return null;
					}
				};
				server.addDefaultEndpointObserver(internalSocketObserver);
			}
			// using cluster removes dtls from protocols
			server.addEndpoints(config);
			if (server.getEndpoints().isEmpty()) {
				System.err.println("no endpoint available!");
				System.exit(PlugtestServer.ERR_INIT_FAILED);
			}

			for (Endpoint ep : server.getEndpoints()) {
				ep.addNotificationListener(reverseObserver);
			}
			InetSocketAddress httpLocal = config.k8sMonitor;
			InetSocketAddress httpsRestoreLocal = null;
			InetSocketAddress httpsRestoreOther = null;
			SSLContext context = null;
			K8sRestoreJdkHttpClient client = null;
			SSLContext clientContext = null;

			if (config.restore != null) {
				if (config.restore.restoreSource.restoreK8s != null) {
					httpsRestoreLocal = config.restore.restoreSource.restoreK8s;
					httpsRestoreOther = new InetSocketAddress(httpsRestoreLocal.getPort());
				} else if (config.restore.restoreSource.restorePair != null) {
					httpsRestoreLocal = config.restore.restoreSource.restorePair.restoreLocal;
					httpsRestoreOther = config.restore.restoreSource.restorePair.restoreOther;
				}
				context = CredentialsUtil.getClusterInternalHttpsServerContext();
			}
			if (httpLocal != null || httpsRestoreLocal != null) {
				long maxAgeSeconds = config.restore != null ? TimeUnit.HOURS.toSeconds(config.restore.maxAge) : 0;
				final JdkMonitorService monitor = new JdkMonitorService(httpLocal, httpsRestoreLocal, maxAgeSeconds,
						context);
				monitor.addServer(server);
				if (context != null) {
					clientContext = CredentialsUtil.getClusterInternalHttpsClientContext();
					if (clientContext != null) {
						client = new K8sRestoreJdkHttpClient();
						monitor.addComponent(client);
					}
				}
				monitor.start();
			}

			PlugtestServer.add(server);
			PlugtestServer.load(config);

			// start standard plugtest server and shutdown
			CoapServer plugtestServer = PlugtestServer.start(executor, secondaryExecutor, config, configuration,
					socketObserver, null);
			server.start();

			server.addLogger(!config.benchmark);

			List<CounterStatisticManager> statistics = new ArrayList<>();
			ObserveStatisticLogger obsStatLogger = new ObserveStatisticLogger(server.getTag());
			if (obsStatLogger.isEnabled()) {
				statistics.add(obsStatLogger);
				server.add(obsStatLogger);
				server.setObserveHealth(obsStatLogger);
			}
			if (plugtestServer != null) {
				obsStatLogger = new ObserveStatisticLogger(plugtestServer.getTag());
				if (obsStatLogger.isEnabled()) {
					statistics.add(obsStatLogger);
					plugtestServer.add(obsStatLogger);
					plugtestServer.setObserveHealth(obsStatLogger);
				}
			}

			Resource child = server.getRoot().getChild(Diagnose.RESOURCE_NAME);
			if (child instanceof Diagnose) {
				Diagnose diagnose = (Diagnose) child;
				diagnose.add(plugtestServer);
				diagnose.update(statistics);
			}

			PlugtestServer.ActiveInputReader reader = new PlugtestServer.ActiveInputReader();
			if (interval > 0) {
				if (config.ipv4) {
					NetStatLogger netStatLogger = new NetStatLogger("udp", false);
					if (netStatLogger.isEnabled()) {
						server.add(netStatLogger);
						LOGGER.info("udp health enabled.");
					} else {
						LOGGER.warn("udp health not enabled!");
					}
				}
				if (config.ipv6) {
					NetStatLogger netStatLogger = new NetStatLogger("udp6", true);
					if (netStatLogger.isEnabled()) {
						server.add(netStatLogger);
						LOGGER.info("udp6 health enabled.");
					} else {
						LOGGER.warn("udp6 health not enabled!");
					}
				}
			} else {
				interval = 30000;
			}

			Runtime runtime = Runtime.getRuntime();
			long max = runtime.maxMemory();
			StringBuilder builder = new StringBuilder(ExtendedTestServer.class.getSimpleName());
			if (!PlugtestServer.CALIFORNIUM_BUILD_VERSION.isEmpty()) {
				builder.append(", version ").append(PlugtestServer.CALIFORNIUM_BUILD_VERSION);
			}
			builder.append(", ").append(max / (1024 * 1024)).append("MB heap, started ...");
			LOGGER.info("{}", builder);
			while (!server.isReady()) {
				Thread.sleep(500);
			}
			if (httpsRestoreOther != null && client != null) {
				if (config.restore.restoreSource.restoreK8s != null) {
					if (k8sClient == null) {
						k8sClient = new K8sManagementJdkClient();
					}
					if (k8sGroup != null) {
						client.restoreCluster(k8sClient, httpsRestoreOther.getPort(), clientContext, server);
					} else {
						client.restoreSingle(k8sClient, httpsRestoreOther.getPort(), clientContext, server);
					}
				} else {
					String host = StringUtil.toHostString(httpsRestoreOther);
					client.restore(InetAddress.getLocalHost().getHostName(), host, httpsRestoreOther.getPort(),
							clientContext, server);
				}
			}
			if (!config.benchmark) {
				LOGGER.info("{} without benchmark started ...", ExtendedTestServer.class.getSimpleName());
				for (;;) {
					if (PlugtestServer.console(reader, interval)) {
						break;
					}
					PlugtestServer.dumpAll();
				}
			} else {
				long inputTimeout = interval < 15000 ? interval : 15000;
				long lastGcCount = 0;
				long lastDumpNanos = ClockUtil.nanoRealtime();
				for (;;) {
					if (PlugtestServer.console(reader, inputTimeout)) {
						break;
					}
					if (management.useWarningMemoryUsage()) {
						long used = runtime.totalMemory() - runtime.freeMemory();
						int fill = (int) ((used * 100L) / max);
						if (fill > 80) {
							LOGGER.info("Maxium heap size: {}M  {}% used.", max / MEGA, fill);
							LOGGER.info("Heap may exceed! Enlarge the maxium heap size.");
							LOGGER.info("Or consider to reduce the value of " + CoapConfig.EXCHANGE_LIFETIME);
							LOGGER.info("in \"{}\" or set", CONFIG_FILE);
							LOGGER.info("{} to {} or", CoapConfig.DEDUPLICATOR, CoapConfig.NO_DEDUPLICATOR);
							LOGGER.info("{} in that file.", CoapConfig.PEERS_MARK_AND_SWEEP_MESSAGES);
						}
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
						PlugtestServer.dumpAll();
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

	public ExtendedTestServer(Configuration config, Map<Select, Configuration> protocolConfig, boolean benchmark,
			long notifyIntervalMillis) throws SocketException {
		super(config, protocolConfig);
		int maxResourceSize = config.get(CoapConfig.MAX_RESOURCE_BODY_SIZE);
		// add resources to the server
		add(new RequestStatistic());
		add(new Benchmark(!benchmark, maxResourceSize, notifyIntervalMillis));
		add(new Hono("telemetry"));
		add(new Hono("event"));
		add(new MyIpResource(MyIpResource.RESOURCE_NAME, true));
		add(new MyContext(MyContext.RESOURCE_NAME, PlugtestServer.CALIFORNIUM_BUILD_VERSION, true));
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
		String tag = "dtls:node-" + nodeId + ":" + StringUtil.toString(dtlsInterface);
		List<CipherSuite> list = configuration.get(DtlsConfig.DTLS_CIPHER_SUITES);
		boolean psk = list == null || CipherSuite.containsPskBasedCipherSuite(list);
		boolean certificate = list == null || CipherSuite.containsCipherSuiteRequiringCertExchange(list);
		int handshakeResultDelayMillis = configuration.getTimeAsInt(DTLS_HANDSHAKE_RESULT_DELAY, TimeUnit.MILLISECONDS);
		long healthStatusIntervalMillis = configuration.get(SystemConfig.HEALTH_STATUS_INTERVAL, TimeUnit.MILLISECONDS);
		Integer cidLength = configuration.get(DtlsConfig.DTLS_CONNECTION_ID_LENGTH);
		if (cidLength == null || cidLength < 6) {
			throw new IllegalArgumentException("cid length must be at least 6 for cluster!");
		}
		initCredentials();
		DtlsConnectorConfig.Builder dtlsConfigBuilder = DtlsConnectorConfig.builder(configuration);
		dtlsConfigBuilder.setAddress(dtlsInterface);
		dtlsConfigBuilder.setLoggingTag(tag);
		dtlsConfigBuilder.setConnectionListener(new MdcConnectionListener());

		// set node-id in dtls-config-builder's Configuration clone
		dtlsConfigBuilder.set(DtlsConfig.DTLS_CONNECTION_ID_NODE_ID, nodeId);
		if (psk || cliConfig.pskFile != null) {
			PlugPskStore pskStore = new PlugPskStore();
			if (cliConfig.pskFile != null) {
				pskStore.loadPskCredentials(cliConfig.pskFile);
			}
			AsyncAdvancedPskStore asyncPskStore = new AsyncAdvancedPskStore(pskStore);
			asyncPskStore.setDelay(handshakeResultDelayMillis);
			dtlsConfigBuilder.setAdvancedPskStore(asyncPskStore);
		}
		if (certificate) {
			if (cliConfig.clientAuth != null) {
				dtlsConfigBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, cliConfig.clientAuth);
			}
			X509KeyManager keyManager = SslContextUtil.getX509KeyManager(serverCredentials);
			AsyncKeyManagerCertificateProvider certificateProvider = new AsyncKeyManagerCertificateProvider(keyManager,
					configuration.get(DtlsConfig.DTLS_CERTIFICATE_TYPES));
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
		}
		if (healthStatusIntervalMillis > 0) {
			DtlsClusterHealthLogger health = new DtlsClusterHealthLogger(tag);
			dtlsConfigBuilder.setHealthHandler(health);
			add(health);
			// reset to prevent active logger
			dtlsConfigBuilder.set(SystemConfig.HEALTH_STATUS_INTERVAL, 0, TimeUnit.MILLISECONDS);
		}
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
			components.add(manager);
		} else if (nodesProvider != null) {
			builder.setConnector(new DtlsClusterConnector(dtlsConnectorConfig, clusterConfiguration, nodesProvider));
		}
		// use dtls-config-builder's Configuration clone with the set node-id
		builder.setConfiguration(dtlsConnectorConfig.getConfiguration());
		CoapEndpoint endpoint = builder.build();
		if (healthStatusIntervalMillis > 0) {
			HealthStatisticLogger healthLogger = new HealthStatisticLogger(CoAP.COAP_SECURE_URI_SCHEME + "-" + nodeId,
					true);
			if (healthLogger.isEnabled()) {
				endpoint.addPostProcessInterceptor(healthLogger);
				add(healthLogger);
			}
		}
		if (endpointObserver != null) {
			endpoint.addObserver(endpointObserver);
		}
		addEndpoint(endpoint);
		print(endpoint, interfaceType);
	}

	private void addEndpoint(InetSocketAddress dtlsInterface, BaseConfig cliConfig) {
		InterfaceType interfaceType = dtlsInterface.getAddress().isLoopbackAddress() ? InterfaceType.LOCAL
				: InterfaceType.EXTERNAL;
		Configuration configuration = getConfig(Protocol.DTLS, interfaceType);
		String tag = "dtls:" + StringUtil.toString(dtlsInterface);
		List<CipherSuite> list = configuration.get(DtlsConfig.DTLS_CIPHER_SUITES);
		boolean psk = list == null || CipherSuite.containsPskBasedCipherSuite(list);
		boolean certificate = list == null || CipherSuite.containsCipherSuiteRequiringCertExchange(list);
		int handshakeResultDelayMillis = configuration.getTimeAsInt(DTLS_HANDSHAKE_RESULT_DELAY, TimeUnit.MILLISECONDS);
		long healthStatusIntervalMillis = configuration.get(SystemConfig.HEALTH_STATUS_INTERVAL, TimeUnit.MILLISECONDS);
		Integer cidLength = configuration.get(DtlsConfig.DTLS_CONNECTION_ID_LENGTH);
		if (cidLength == null || cidLength < 6) {
			throw new IllegalArgumentException("cid length must be at least 6 for cluster!");
		}
		initCredentials();
		DtlsConnectorConfig.Builder dtlsConfigBuilder = DtlsConnectorConfig.builder(configuration);
		dtlsConfigBuilder.setAddress(dtlsInterface);
		dtlsConfigBuilder.setLoggingTag(tag);
		dtlsConfigBuilder.setConnectionListener(new MdcConnectionListener());

		if (psk) {
			PlugPskStore pskStore = new PlugPskStore();
			if (cliConfig.pskFile != null) {
				pskStore.loadPskCredentials(cliConfig.pskFile);
			}
			AsyncAdvancedPskStore asyncPskStore = new AsyncAdvancedPskStore(pskStore);
			asyncPskStore.setDelay(handshakeResultDelayMillis);
			dtlsConfigBuilder.setAdvancedPskStore(asyncPskStore);
		}
		if (certificate) {
			if (cliConfig.clientAuth != null) {
				dtlsConfigBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, cliConfig.clientAuth);
			}
			X509KeyManager keyManager = SslContextUtil.getX509KeyManager(serverCredentials);
			AsyncKeyManagerCertificateProvider certificateProvider = new AsyncKeyManagerCertificateProvider(keyManager,
					configuration.get(DtlsConfig.DTLS_CERTIFICATE_TYPES));
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
		}
		if (healthStatusIntervalMillis > 0) {
			DtlsHealthLogger health = new DtlsHealthLogger(tag);
			dtlsConfigBuilder.setHealthHandler(health);
			add(health);
			// reset to prevent active logger
			dtlsConfigBuilder.set(SystemConfig.HEALTH_STATUS_INTERVAL, 0, TimeUnit.MILLISECONDS);
		}
		DtlsConnectorConfig dtlsConnectorConfig = dtlsConfigBuilder.build();
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConnector(new DTLSConnector(dtlsConnectorConfig));
		builder.setConfiguration(dtlsConnectorConfig.getConfiguration());
		CoapEndpoint endpoint = builder.build();
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
