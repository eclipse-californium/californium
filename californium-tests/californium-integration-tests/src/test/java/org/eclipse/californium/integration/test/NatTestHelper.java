/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.integration.test;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointContextMatcherFactory.MatcherMode;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.network.interceptors.HealthStatisticLogger;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.PrincipalEndpointContextMatcher;
import org.eclipse.californium.elements.util.CounterStatisticManager;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.integration.test.util.CoapsNetworkRule;
import org.eclipse.californium.scandium.AlertHandler;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.DtlsClusterConnector;
import org.eclipse.californium.scandium.DtlsClusterHealthLogger;
import org.eclipse.californium.scandium.DtlsHealthLogger;
import org.eclipse.californium.scandium.DtlsManagedClusterConnector;
import org.eclipse.californium.scandium.config.DtlsClusterConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.ConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.DebugConnectionStore;
import org.eclipse.californium.scandium.dtls.NodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.ResumptionSupportingConnectionStore;
import org.eclipse.californium.scandium.dtls.SingleNodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedSinglePskStore;
import org.eclipse.californium.util.nat.NioNatUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NatTestHelper {
	private static final Logger LOGGER = LoggerFactory.getLogger(NatTestHelper.class);

	static final long RESPONSE_TIMEOUT = 10 * 1000L;
	static final String TARGET = "resource";
	static final String IDENITITY = "client1";
	static final String KEY = "key1";

	static final ConnectionIdGenerator SUPPORT_CID = new SingleNodeConnectionIdGenerator(0);

	static final ConnectionIdGenerator USE_CID_4 = new SingleNodeConnectionIdGenerator(4);

	CoapsNetworkRule network;

	boolean first;
	Random rand;
	NioNatUtil nat;
	MatcherMode mode;
	NetworkConfig config;

	List<DebugConnectionStore> serverConnections = new ArrayList<>();
	List<DebugConnectionStore> clientConnections = new ArrayList<>();
	List<CoapEndpoint> serverEndpoints = new ArrayList<>();;
	List<CoapEndpoint> clientEndpoints = new ArrayList<>();
	List<CounterStatisticManager> serverStatistics = new ArrayList<>();
	List<CounterStatisticManager> serverCoapStatistics = new ArrayList<>();
	List<CounterStatisticManager> clientStatistics = new ArrayList<>();
	List<CounterStatisticManager> clientCoapStatistics = new ArrayList<>();
	List<CoapServer> servers = new ArrayList<>();

	MyResource resource;
	String uri;

	NatTestHelper(CoapsNetworkRule network) {
		this.network = network;
		this.rand = new Random(System.currentTimeMillis());
		this.first = true;
	}

	void shutdown() {
		for (CoapServer server : servers) {
			server.destroy();
		}
		if (nat != null) {
			nat.stop();
			nat = null;
		}
		for (CoapEndpoint endpoint : clientEndpoints) {
			endpoint.destroy();
		}
	}

	void forceResumption(List<Integer> resumeEndpoints, int percent) throws InterruptedException {
		resumeEndpoints.clear();
		int num = clientEndpoints.size();
		for (int i = 0; i < num; ++i) {
			if (rand.nextInt(100) < percent) {
				CoapEndpoint endpoint = clientEndpoints.get(i);
				Connector connector = endpoint.getConnector();
				if (connector instanceof DTLSConnector) {
					((DTLSConnector) connector).forceResumeAllSessions();
					resumeEndpoints.add(i);
				}
			}
		}
	}

	void clearServerStatistic() {
		for (CounterStatisticManager statistic : serverStatistics) {
			statistic.reset();
		}
		for (CounterStatisticManager statistic : serverCoapStatistics) {
			statistic.reset();
		}
	}

	boolean dumpClientConnections(int id) throws InterruptedException {
		DebugConnectionStore connections = clientConnections.get(id);
		connections.dump();
		clientStatistics.get(id).dump();
		clientCoapStatistics.get(id).dump();
		CoapEndpoint endpoint = clientEndpoints.get(id);
		InetSocketAddress address = endpoint.getAddress();
		InetSocketAddress via = nat.getLocalAddressForAddress(address);
		if (via.getAddress().isAnyLocalAddress()) {
			via = new InetSocketAddress(InetAddress.getLoopbackAddress(), via.getPort());
		}
		return dumpServerConnections(via);
	}

	void validateServerConnections() {
		for (DebugConnectionStore store : serverConnections) {
			store.validate();
		}
	}

	void dumpServerConnections() {
		for (DebugConnectionStore store : serverConnections) {
			store.dump();
		}
		for (DebugConnectionStore store : serverConnections) {
			store.dump();
		}
	}

	boolean dumpServerConnections(InetSocketAddress address) {
		int count = 0;
		int index = 0;
		int last = 0;
		for (DebugConnectionStore store : serverConnections) {
			if (store.get(address) != null) {
				last = index;
				++count;
			}
			++index;
		}
		if (count == 1) {
			serverConnections.get(last).dump(address);
			serverStatistics.get(last).dump();
			serverCoapStatistics.get(last).dump();
			serverConnections.get(last).dump();
			return true;
		} else {
			for (DebugConnectionStore store : serverConnections) {
				store.dump(address);
			}
			return false;
		}
	}

	void setupNetworkConfig(MatcherMode mode, int ackTimeout) {
		this.mode = mode;
		config = network.getStandardTestConfig()
				// retransmit starting with 200 milliseconds
				.setInt(Keys.ACK_TIMEOUT, ackTimeout).setFloat(Keys.ACK_RANDOM_FACTOR, 1.5f)
				.setFloat(Keys.ACK_TIMEOUT_SCALE, 1.5f).setLong(Keys.EXCHANGE_LIFETIME, RESPONSE_TIMEOUT)
				.setString(Keys.RESPONSE_MATCHING, mode.name());
	}

	void createSecureServer(ConnectionIdGenerator... cidGenerators) throws IOException {
		MyClusterNodesProvider provider = new MyClusterNodesProvider();
		int timeout = config.getInt(Keys.ACK_TIMEOUT);
		int count = 1;
		for (ConnectionIdGenerator generator : cidGenerators) {
			String tag = "server" + count;
			DtlsClusterHealthLogger health = new DtlsClusterHealthLogger(tag);
			this.serverStatistics.add(health);
			TestUtilPskStore pskStore = new TestUtilPskStore();
			pskStore.set(IDENITITY, KEY.getBytes());
			pskStore.setCatchAll(true);
			DtlsConnectorConfig dtlsConfig = new DtlsConnectorConfig.Builder().setAddress(TestTools.LOCALHOST_EPHEMERAL)
					.setLoggingTag(tag).setHealthHandler(health).setServerOnly(true).setReceiverThreadCount(2)
					.setMaxConnections(10000).setStaleConnectionThreshold(20).setConnectionThreadCount(4)
					.setConnectionIdGenerator(generator).setMaxRetransmissions(4).setRetransmissionTimeout(timeout)
					.setVerifyPeersOnResumptionThreshold(100).setAdvancedPskStore(pskStore).build();

			DebugConnectionStore serverConnectionStore = new DebugConnectionStore(dtlsConfig.getMaxConnections(),
					dtlsConfig.getStaleConnectionThreshold(), null);
			serverConnectionStore.setTag(dtlsConfig.getLoggingTag());
			this.serverConnections.add(serverConnectionStore);

			CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
			if (generator instanceof NodeConnectionIdGenerator) {
				DtlsClusterConnectorConfig.Builder clusterConfigBuilder = DtlsClusterConnectorConfig.builder();
				clusterConfigBuilder.setAddress(TestTools.LOCALHOST_EPHEMERAL);
				DtlsManagedClusterConnector serverConnector = new MyDtlsClusterConnector(dtlsConfig,
						clusterConfigBuilder.build(), serverConnectionStore);
				serverConnector.setClusterNodesProvider(provider);
				provider.add(serverConnector);
				serverConnector.setAlertHandler(new MyAlertHandler(dtlsConfig.getLoggingTag()));
				builder.setConnector(serverConnector);
			} else {
				DTLSConnector serverConnector = new MyDtlsConnector(dtlsConfig, serverConnectionStore);
				serverConnector.setAlertHandler(new MyAlertHandler(dtlsConfig.getLoggingTag()));
				builder.setConnector(serverConnector);
			}
			if (mode == MatcherMode.PRINCIPAL) {
				// requires different client identities!
				builder.setEndpointContextMatcher(new PrincipalEndpointContextMatcher(true));
			}
			builder.setNetworkConfig(config);
			CoapEndpoint serverEndpoint = builder.build();
			HealthStatisticLogger healthLogger = new HealthStatisticLogger(tag, true);
			serverCoapStatistics.add(healthLogger);
			serverEndpoint.addPostProcessInterceptor(healthLogger);
			serverEndpoints.add(serverEndpoint);
			CoapServer server = new CoapServer();
			server.addEndpoint(serverEndpoint);
			resource = new MyResource(TARGET);
			server.add(resource);
			server.start();
			servers.add(server);
			++count;
		}
		createLoadBalancer();
		System.out.println("coap-server " + uri);
	}

	CoapEndpoint createClientEndpoint(ConnectionIdGenerator cidGenerator) throws IOException {

		String tag = "client";
		int size = clientEndpoints.size();
		if (size > 0) {
			tag += "." + size;
		}
		int timeout = config.getInt(Keys.ACK_TIMEOUT);

		DtlsHealthLogger health = new DtlsHealthLogger(tag);
		this.clientStatistics.add(health);

		// prepare secure client endpoint
		DtlsConnectorConfig clientDtlsConfig = new DtlsConnectorConfig.Builder()
				.setAddress(TestTools.LOCALHOST_EPHEMERAL).setLoggingTag(tag).setHealthHandler(health)
				.setReceiverThreadCount(2).setMaxConnections(20).setConnectionThreadCount(2)
				.setConnectionIdGenerator(cidGenerator).setMaxRetransmissions(4).setRetransmissionTimeout(timeout)
				.setSupportedCipherSuites(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8)
				.setAdvancedPskStore(new AdvancedSinglePskStore(IDENITITY + "." + size, KEY.getBytes())).build();

		DebugConnectionStore connections = new DebugConnectionStore(clientDtlsConfig.getMaxConnections(),
				clientDtlsConfig.getStaleConnectionThreshold(), null);
		connections.setTag(clientDtlsConfig.getLoggingTag());

		DTLSConnector clientConnector = new MyDtlsConnector(clientDtlsConfig, connections);
		clientConnector.setAlertHandler(new MyAlertHandler(clientDtlsConfig.getLoggingTag()));
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConnector(clientConnector);
		builder.setNetworkConfig(config);
		CoapEndpoint clientEndpoint = builder.build();
		HealthStatisticLogger healthLogger = new HealthStatisticLogger(tag, true);
		clientCoapStatistics.add(healthLogger);
		clientEndpoint.addPostProcessInterceptor(healthLogger);
		clientEndpoint.start();
		clientConnections.add(connections);
		clientEndpoints.add(clientEndpoint);
		return clientEndpoint;
	}

	void createDefaultClientEndpoint(ConnectionIdGenerator cidGenerator) throws IOException {
		Endpoint clientEndpoint = createClientEndpoint(cidGenerator);
		EndpointManager.getEndpointManager().setDefaultEndpoint(clientEndpoint);
		System.out.println("coap-client " + clientEndpoint.getUri());
	}

	void createLoadBalancer() throws IOException {
		int destinationPort = -1;
		for (CoapEndpoint serverEndpoint : serverEndpoints) {
			InetSocketAddress address = serverEndpoint.getAddress();
			if (nat == null) {
				nat = new NioNatUtil(TestTools.LOCALHOST_EPHEMERAL, address);
				uri = TestTools.getUri(serverEndpoint, TARGET);
				destinationPort = address.getPort();
			} else {
				nat.addDestination(address);
			}
		}
		nat.setNatTimeoutMillis(0);
		nat.setLoadBalancerTimeoutMillis(0);
		int port = nat.getProxySocketAddress().getPort();
		uri = uri.replace(":" + destinationPort + "/", ":" + port + "/");
		System.out.println("URI: LoadBalancer destination " + uri);
	}

	void testMultipleSecureGet(int loop, int overallResumes, List<Integer> resumeEndpoints)
			throws InterruptedException {
		if (first) {
			first = false;
		} else {
			clearServerStatistic();
		}
		int num = clientEndpoints.size();
		List<Request> requests = new ArrayList<>();
		for (int count = 1; count < num; ++count) {
			CoapEndpoint endpoint = clientEndpoints.get(count);
			Request request = Request.newGet();
			request.setURI(uri);
			endpoint.sendRequest(request);
			requests.add(request);
			if (count % 8 == 0) {
				validateServerConnections();
			}
		}
		List<Integer> idOfErrors = new ArrayList<Integer>();
		long responseTimeout = config.getLong(Keys.EXCHANGE_LIFETIME) + 1000;
		for (int count = 0; count < requests.size(); ++count) {
			int id = count + 1;
			Request request = requests.get(count);
			Response response = request.waitForResponse(responseTimeout);
			if (response == null) {
				idOfErrors.add(id);
			}
		}
		if (!idOfErrors.isEmpty()) {
			validateServerConnections();
			LOGGER.warn("{} resumptions, {} at all.", resumeEndpoints.size(), overallResumes);
			for (Integer resume : resumeEndpoints) {
				CoapEndpoint endpoint = clientEndpoints.get(resume);
				InetSocketAddress via = nat.getLocalAddressForAddress(endpoint.getAddress());
				if (idOfErrors.contains(resume)) {
					LOGGER.error("resume client {}, {} via {} has failed!", resume, endpoint.getUri(), via.getPort());
				} else {
					LOGGER.warn("resume client {}, {} via {}", resume, endpoint.getUri(), via.getPort());
				}
			}
			boolean dump = false;
			StringBuilder failure = new StringBuilder();
			for (Integer id : idOfErrors) {
				Request request = requests.get(id - 1);
				CoapEndpoint endpoint = clientEndpoints.get(id);
				InetSocketAddress via = nat.getLocalAddressForAddress(endpoint.getAddress());
				if (!resumeEndpoints.contains(id)) {
					LOGGER.error("client {}, {} via {} has failed!", id, endpoint.getUri(), via.getPort());
				}
				if (!dumpClientConnections(id)) {
					dump = true;
				}
				failure.append("loop ").append(loop).append(" / client ").append(id).append(": ");
				if (request.getSendError() != null) {
					failure.append("received error ").append(request.getSendError());
				} else if (request.isCanceled()) {
					failure.append("request canceled ").append(request);
				} else if (!request.isSent()) {
					failure.append("request not sent ").append(request);
				} else if (request.isRejected()) {
					failure.append("request rejected ").append(request);
				} else if (request.isTimedOut()) {
					failure.append("request timed out ").append(request);
				} else {
					failure.append("request failed ").append(request);
				}
				failure.append(StringUtil.lineSeparator());
			}
			if (dump) {
				dumpServerConnections();
			}
			fail(failure.toString());
		}
		validateServerConnections();
	}

	private static class MyResource extends CoapResource {

		public MyResource(String name) {
			super(name);
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			Response response = new Response(ResponseCode.CONTENT);
			response.setPayload("Hello");
			exchange.respond(response);
		}
	}

	private static class MyDtlsConnector extends DTLSConnector {

		public MyDtlsConnector(DtlsConnectorConfig configuration, ResumptionSupportingConnectionStore connectionStore) {
			super(configuration, connectionStore);

		}
	}

	private static class MyDtlsClusterConnector extends DtlsManagedClusterConnector {

		public MyDtlsClusterConnector(DtlsConnectorConfig configuration,
				DtlsClusterConnectorConfig clusterConfiguration, ResumptionSupportingConnectionStore connectionStore) {
			super(configuration, clusterConfiguration, connectionStore);
		}
	}

	private static class MyClusterNodesProvider implements DtlsClusterConnector.ClusterNodesProvider {

		private final Map<Integer, DtlsManagedClusterConnector> clusterConnectors = new HashMap<>();

		public void add(DtlsManagedClusterConnector connector) {
			int nodeId = connector.getNodeID();
			LOGGER.info("add node {}", nodeId);
			clusterConnectors.put(nodeId, connector);
		}

		@Override
		public InetSocketAddress getClusterNode(int nodeId) {
			DtlsManagedClusterConnector connector = clusterConnectors.get(nodeId);
			if (connector != null) {
				InetSocketAddress address = connector.getClusterManagementConnector().getAddress();
				LOGGER.info("get node {} => {}", nodeId, StringUtil.toDisplayString(address));
				return address;
			} else {
				LOGGER.info("get node {} => null", nodeId);
				return null;
			}
		}

		@Override
		public boolean available(InetSocketAddress destinationConnector) {
			return true;
		}

	}

	private static class MyAlertHandler implements AlertHandler {
		String tag;

		MyAlertHandler(String tag) {
			this.tag = tag;
		}

		@Override
		public void onAlert(InetSocketAddress peer, AlertMessage alert) {
			LOGGER.warn("DTLS {}: peer {} - {}/{} ", tag, StringUtil.toString(peer), alert.getLevel(),
					alert.getDescription());
		}
	}

}
