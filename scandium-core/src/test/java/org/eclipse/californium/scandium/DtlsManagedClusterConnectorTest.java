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
package org.eclipse.californium.scandium;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.rule.ThreadsRule;
import org.eclipse.californium.elements.util.LeastRecentlyUsedCache.Predicate;
import org.eclipse.californium.elements.util.SimpleMessageCallback;
import org.eclipse.californium.elements.util.TestConditionTools;
import org.eclipse.californium.scandium.ConnectorHelper.LatchDecrementingRawDataChannel;
import org.eclipse.californium.scandium.ConnectorHelper.MessageCapturingProcessor;
import org.eclipse.californium.scandium.ConnectorHelper.SimpleRawDataChannel;
import org.eclipse.californium.scandium.config.DtlsClusterConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.eclipse.californium.scandium.dtls.MultiNodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.SingleNodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedSinglePskStore;
import org.eclipse.californium.scandium.rule.DtlsNetworkRule;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/**
 * Simple basic test for forwarding and backwarding of messages.
 */
@RunWith(Parameterized.class)
@Category(Small.class)
public class DtlsManagedClusterConnectorTest {

	@ClassRule
	public static DtlsNetworkRule network = new DtlsNetworkRule(DtlsNetworkRule.Mode.DIRECT,
			DtlsNetworkRule.Mode.NATIVE);

	@ClassRule
	public static ThreadsRule cleanup = new ThreadsRule();

	@Rule
	public TestNameLoggerRule names = new TestNameLoggerRule();

	private static final long DEFAULT_TIMEOUT_MILLIS = 2000;

	private static InetAddress loopback = InetAddress.getLoopbackAddress();
	private static InetSocketAddress dtlsAddress1 = new InetSocketAddress(loopback, 15684);
	private static InetSocketAddress dtlsAddress2 = new InetSocketAddress(loopback, 25684);
	private static InetSocketAddress mgmtAddress1 = new InetSocketAddress(loopback, 15784);
	private static InetSocketAddress mgmtAddress2 = new InetSocketAddress(loopback, 25784);

	@Parameter
	public DtlsClusterConnectorConfig clusterConfig;

	/**
	 * @return List of DTLS Configuration Builder setup.
	 */
	@Parameters(name = "${index}")
	public static Iterable<DtlsClusterConnectorConfig> setups() {
		SecretKey key = SecretUtil.create("secret".getBytes(), "PSK");
		List<DtlsClusterConnectorConfig> parameters = Arrays.asList(
				DtlsClusterConnectorConfig.builder().getIncompleteConfig(),
				DtlsClusterConnectorConfig.builder().setBackwardMessage(false).getIncompleteConfig(),
				DtlsClusterConnectorConfig.builder().setSecure("test", key).setClusterMac(false).getIncompleteConfig(),
				DtlsClusterConnectorConfig.builder().setSecure("test", key).getIncompleteConfig());
		SecretUtil.destroy(key);
		return parameters;
	}

	private DtlsManagedClusterConnector connector1;
	private DtlsManagedClusterConnector connector2;
	private MessageCapturingProcessor messages1;
	private MessageCapturingProcessor messages2;
	private LatchDecrementingRawDataChannel mgmtChannel1;
	private LatchDecrementingRawDataChannel mgmtChannel2;
	private DtlsClusterHealthLogger health1;
	private DtlsClusterHealthLogger health2;

	private DTLSConnector clientConnector;
	private InMemoryConnectionStore clientConnections;
	private LatchDecrementingRawDataChannel clientChannel;
	private DtlsHealthLogger clientHealth;

	private boolean secureInternalCommunication;

	@Before
	public void init() throws IOException {
		final int CID_LENGTH = 6;
		final int NODE_ID_1 = 1;
		final int NODE_ID_2 = 2;
		health1 = new DtlsClusterHealthLogger("server1");
		AdvancedSinglePskStore testPskStore1 = new AdvancedSinglePskStore(ConnectorHelper.CLIENT_IDENTITY,
				ConnectorHelper.CLIENT_IDENTITY_SECRET.getBytes());
		DtlsConnectorConfig config1 = DtlsConnectorConfig.builder().setAddress(dtlsAddress1)
				.setAdvancedPskStore(testPskStore1).setMaxConnections(10).setReceiverThreadCount(2)
				.setConnectionThreadCount(2).setHealthHandler(health1)
				.setConnectionIdGenerator(new MultiNodeConnectionIdGenerator(NODE_ID_1, CID_LENGTH)).build();
		DtlsClusterConnectorConfig clusterConfig1 = DtlsClusterConnectorConfig.builder(clusterConfig)
				.setAddress(mgmtAddress1).build();
		health2 = new DtlsClusterHealthLogger("server2");
		AdvancedSinglePskStore testPskStore2 = new AdvancedSinglePskStore(ConnectorHelper.CLIENT_IDENTITY,
				ConnectorHelper.CLIENT_IDENTITY_SECRET.getBytes());
		DtlsConnectorConfig config2 = DtlsConnectorConfig.builder().setAddress(dtlsAddress2)
				.setAdvancedPskStore(testPskStore2).setMaxConnections(10).setReceiverThreadCount(2)
				.setConnectionThreadCount(2).setHealthHandler(health2)
				.setConnectionIdGenerator(new MultiNodeConnectionIdGenerator(NODE_ID_2, CID_LENGTH)).build();
		DtlsClusterConnectorConfig clusterConfig2 = DtlsClusterConnectorConfig.builder(clusterConfig)
				.setAddress(mgmtAddress2).build();
		DtlsClusterConnector.ClusterNodesProvider nodesProvider = new DtlsClusterConnector.ClusterNodesProvider() {

			@Override
			public InetSocketAddress getClusterNode(int nodeId) {
				switch (nodeId) {
				case NODE_ID_1:
					return mgmtAddress1;
				case NODE_ID_2:
					return mgmtAddress2;
				}
				return null;
			}

			@Override
			public boolean available(InetSocketAddress destinationConnector) {
				return true;
			}

		};

		connector1 = new DtlsManagedClusterConnector(config1, clusterConfig1);
		connector2 = new DtlsManagedClusterConnector(config2, clusterConfig2);

		connector1.setClusterNodesProvider(nodesProvider);
		connector2.setClusterNodesProvider(nodesProvider);

		messages1 = new MessageCapturingProcessor();
		connector1.setRawDataReceiver(new SimpleRawDataChannel(connector1, messages1));

		messages2 = new MessageCapturingProcessor();
		connector2.setRawDataReceiver(new SimpleRawDataChannel(connector2, messages2));

		mgmtChannel1 = new LatchDecrementingRawDataChannel();
		connector1.getClusterManagementConnector().setRawDataReceiver(mgmtChannel1);

		mgmtChannel2 = new LatchDecrementingRawDataChannel();
		connector2.getClusterManagementConnector().setRawDataReceiver(mgmtChannel2);

		connector1.start();
		connector2.start();

		clusterConfig = clusterConfig1;

		clientHealth = new DtlsClusterHealthLogger("client");
		AdvancedSinglePskStore testPskStore = new AdvancedSinglePskStore(ConnectorHelper.CLIENT_IDENTITY,
				ConnectorHelper.CLIENT_IDENTITY_SECRET.getBytes());
		DtlsConnectorConfig config = DtlsConnectorConfig.builder().setAdvancedPskStore(testPskStore)
				.setMaxConnections(10).setReceiverThreadCount(2).setConnectionThreadCount(2)
				.setHealthHandler(clientHealth).setConnectionIdGenerator(new SingleNodeConnectionIdGenerator(4))
				.build();
		clientConnections = new InMemoryConnectionStore(10, 6000);
		clientConnector = new DTLSConnector(config, clientConnections);

		clientChannel = new LatchDecrementingRawDataChannel();
		clientConnector.setRawDataReceiver(clientChannel);

		clientConnector.start();

		String protocol1 = connector1.getManagementProtocol();
		String protocol2 = connector1.getManagementProtocol();
		assertEquals("protocol mismatch", protocol1, protocol2);
		secureInternalCommunication = protocol1.startsWith(DtlsManagedClusterConnector.PROTOCOL_MANAGEMENT_DTLS);
	}

	@After
	public void shutdownclient() {
		if (connector1 != null) {
			connector1.destroy();
			connector1 = null;
		}
		if (connector2 != null) {
			connector2.destroy();
			connector2 = null;
		}
		if (clientConnector != null) {
			clientConnector.destroy();
			clientConnector = null;
		}
	}

	private void initClusterManagementCommunication() throws InterruptedException {
		if (secureInternalCommunication) {
			// initialize encryption
			mgmtChannel1.setLatchCount(1);
			RawData message = RawData.outbound("ping".getBytes(), new AddressEndpointContext(mgmtAddress1), null,
					false);
			connector2.getClusterManagementConnector().send(message);

			assertTrue(mgmtChannel1.await(DEFAULT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));
			TestConditionTools.assertStatisticCounter(health1, "recv cluster mgmt", is(1L), DEFAULT_TIMEOUT_MILLIS,
					TimeUnit.MILLISECONDS);
			TestConditionTools.assertStatisticCounter(health2, "sent cluster mgmt", is(1L), DEFAULT_TIMEOUT_MILLIS,
					TimeUnit.MILLISECONDS);
			health1.reset();
			health2.reset();
		}
	}

	/**
	 * Send first a message to connector 1, Then a message to connector 2, and
	 * compare the used CIDs.
	 * 
	 * @throws Exception if an error occurred
	 */
	@Test
	public void testCidLoadBalancer() throws Exception {
		initClusterManagementCommunication();

		// send message to connector 1
		clientChannel.setLatchCount(1);

		SimpleMessageCallback callback = new SimpleMessageCallback();
		RawData message = RawData.outbound("hello!".getBytes(), new AddressEndpointContext(dtlsAddress1), callback,
				false);
		clientConnector.send(message);
		assertTrue(callback.isSent(DEFAULT_TIMEOUT_MILLIS));
		assertTrue(clientChannel.await(DEFAULT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));

		// check number of connections

		assertEquals(9, clientConnections.remainingCapacity());
		TestConditionTools.assertStatisticCounter(health1, "handshakes succeeded", is(1L), DEFAULT_TIMEOUT_MILLIS,
				TimeUnit.MILLISECONDS);
		health1.reset();
		clientHealth.reset();

		// adapt the destination address to connector 2
		Future<Void> result = clientConnector.startForEach(new Predicate<Connection>() {

			@Override
			public boolean accept(Connection value) {
				if (value.equalsPeerAddress(dtlsAddress1)) {
					clientConnections.update(value, dtlsAddress2);
					return true;
				} else {
					return false;
				}
			}
		});

		result.get(DEFAULT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
		assertTrue(result.isDone());

		// send message to connector 2
		clientChannel.setLatchCount(1);

		SimpleMessageCallback callback2 = new SimpleMessageCallback();
		RawData message2 = RawData.outbound("hello 2!".getBytes(), new AddressEndpointContext(dtlsAddress2), callback2,
				false);
		clientConnector.send(message2);
		assertTrue(callback2.isSent(DEFAULT_TIMEOUT_MILLIS));
		assertTrue(clientChannel.await(DEFAULT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));

		// compare connection id

		EndpointContext endpointContext = callback.getEndpointContext();
		EndpointContext endpointContext2 = callback2.getEndpointContext();
		String cid1 = endpointContext.getString(DtlsEndpointContext.KEY_WRITE_CONNECTION_ID);
		String cid2 = endpointContext2.getString(DtlsEndpointContext.KEY_WRITE_CONNECTION_ID);
		assertNotNull(cid1);
		assertNotNull(cid2);
		assertEquals(cid1, cid2);

		// check number of connections

		assertEquals(9, clientConnections.remainingCapacity());

		TestConditionTools.assertStatisticCounter(health1, "received records", is(1L), DEFAULT_TIMEOUT_MILLIS,
				TimeUnit.MILLISECONDS);
		TestConditionTools.assertStatisticCounter(health1, "sending records", is(1L), DEFAULT_TIMEOUT_MILLIS,
				TimeUnit.MILLISECONDS);
		TestConditionTools.assertStatisticCounter(health1, "process forwarded", is(1L), DEFAULT_TIMEOUT_MILLIS,
				TimeUnit.MILLISECONDS);
		if (clusterConfig.useBackwardMessages()) {
			TestConditionTools.assertStatisticCounter(health1, "backwarded", is(1L), DEFAULT_TIMEOUT_MILLIS,
					TimeUnit.MILLISECONDS);
			TestConditionTools.assertStatisticCounter(health2, "send backwarded", is(1L), DEFAULT_TIMEOUT_MILLIS,
					TimeUnit.MILLISECONDS);
		} else {
			TestConditionTools.assertStatisticCounter(health1, "backwarded", is(0L));

			TestConditionTools.assertStatisticCounter(health2, "send backwarded", is(0L));
		}
		TestConditionTools.assertStatisticCounter(health2, "forwarded", is(1L), DEFAULT_TIMEOUT_MILLIS,
				TimeUnit.MILLISECONDS);

		TestConditionTools.assertStatisticCounter(health1, "handshakes succeeded", is(0L));
		TestConditionTools.assertStatisticCounter(health2, "handshakes succeeded", is(0L));

		TestConditionTools.assertStatisticCounter(clientHealth, "received records", is(1L), DEFAULT_TIMEOUT_MILLIS,
				TimeUnit.MILLISECONDS);
		TestConditionTools.assertStatisticCounter(clientHealth, "sending records", is(1L), DEFAULT_TIMEOUT_MILLIS,
				TimeUnit.MILLISECONDS);
	}

	@Test
	public void testClusterMgmtCommunication() throws Exception {
		mgmtChannel1.setLatchCount(1);

		RawData message = RawData.outbound("ping".getBytes(), new AddressEndpointContext(mgmtAddress1), null, false);
		connector2.getClusterManagementConnector().send(message);

		assertTrue(mgmtChannel1.await(DEFAULT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));

		TestConditionTools.assertStatisticCounter("ping", health2, "sent cluster mgmt", is(1L), DEFAULT_TIMEOUT_MILLIS,
				TimeUnit.MILLISECONDS);
		TestConditionTools.assertStatisticCounter("ping", health1, "recv cluster mgmt", is(1L), DEFAULT_TIMEOUT_MILLIS,
				TimeUnit.MILLISECONDS);
		TestConditionTools.assertStatisticCounter("ping", health2, "forwarded", is(0L));
		TestConditionTools.assertStatisticCounter("ping", health1, "backwarded", is(0L));

		mgmtChannel2.setLatchCount(1);

		message = RawData.outbound("pong".getBytes(), new AddressEndpointContext(mgmtAddress2), null, false);
		connector1.getClusterManagementConnector().send(message);

		assertTrue(mgmtChannel2.await(DEFAULT_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));

		TestConditionTools.assertStatisticCounter("pong", health1, "sent cluster mgmt", is(1L), DEFAULT_TIMEOUT_MILLIS,
				TimeUnit.MILLISECONDS);
		TestConditionTools.assertStatisticCounter("pong", health2, "recv cluster mgmt", is(1L), DEFAULT_TIMEOUT_MILLIS,
				TimeUnit.MILLISECONDS);
		TestConditionTools.assertStatisticCounter("pong", health1, "forwarded", is(0L));
		TestConditionTools.assertStatisticCounter("pong", health2, "backwarded", is(0L));

	}

	@Test
	public void testClusterInternalCommunication() throws Exception {
		initClusterManagementCommunication();

		mgmtChannel1.setLatchCount(1);
		int len = DtlsClusterConnector.CLUSTER_ADDRESS_OFFSET + 4 + connector1.getClusterMacLength() + 2;
		byte[] data = new byte[len];
		// cause drop mgmt message
		data[DtlsClusterConnector.CLUSTER_RECORD_TYPE_OFFSET] = DtlsClusterConnector.RECORD_TYPE_INCOMING;
		data[DtlsClusterConnector.CLUSTER_ADDRESS_LENGTH_OFFSET] = 4;
		DatagramPacket packet = new DatagramPacket(data, data.length, mgmtAddress1);
		try {
			connector2.sendDatagramToClusterNetwork(packet);
		} catch (IOException ex) {
			ex.printStackTrace();
		}
		Thread.sleep(200);
		TestConditionTools.assertStatisticCounter(health1, "drop forward", is(1L), DEFAULT_TIMEOUT_MILLIS,
				TimeUnit.MILLISECONDS);
		TestConditionTools.assertStatisticCounter(health1, "recv cluster mgmt", is(0L));
		TestConditionTools.assertStatisticCounter(health1, "backwarded", is(0L));
		TestConditionTools.assertStatisticCounter(health2, "forwarded", is(0L));
		TestConditionTools.assertStatisticCounter(health2, "sent cluster mgmt", is(0L));
	}
}
