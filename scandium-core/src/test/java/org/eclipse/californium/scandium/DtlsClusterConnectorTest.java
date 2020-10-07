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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.rule.ThreadsRule;
import org.eclipse.californium.elements.util.LeastRecentlyUsedCache.Predicate;
import org.eclipse.californium.elements.util.SimpleMessageCallback;
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
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Simple basic test for forwarding and backwarding of messages.
 */
@Category(Small.class)
public class DtlsClusterConnectorTest {

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

	private static DtlsClusterConnector connector1;
	private static DtlsClusterConnector connector2;
	private static MessageCapturingProcessor messages1;
	private static MessageCapturingProcessor messages2;

	private DTLSConnector clientConnector;
	private InMemoryConnectionStore clientConnections;
	private LatchDecrementingRawDataChannel clientChannel;

	@BeforeClass
	public static void initServer() throws IOException {
		final int CID_LENGTH = 6;
		final int NODE_ID_1 = 1;
		final int NODE_ID_2 = 2;
		AdvancedSinglePskStore testPskStore1 = new AdvancedSinglePskStore(ConnectorHelper.CLIENT_IDENTITY,
				ConnectorHelper.CLIENT_IDENTITY_SECRET.getBytes());
		DtlsConnectorConfig config1 = DtlsConnectorConfig.builder().setAddress(dtlsAddress1)
				.setAdvancedPskStore(testPskStore1).setMaxConnections(10).setReceiverThreadCount(2)
				.setConnectionThreadCount(2)
				.setConnectionIdGenerator(new MultiNodeConnectionIdGenerator(NODE_ID_1, CID_LENGTH)).build();
		DtlsClusterConnectorConfig clusterConfig1 = DtlsClusterConnectorConfig.builder().setAddress(mgmtAddress1)
				.build();
		AdvancedSinglePskStore testPskStore2 = new AdvancedSinglePskStore(ConnectorHelper.CLIENT_IDENTITY,
				ConnectorHelper.CLIENT_IDENTITY_SECRET.getBytes());
		DtlsConnectorConfig config2 = DtlsConnectorConfig.builder().setAddress(dtlsAddress2)
				.setAdvancedPskStore(testPskStore2).setMaxConnections(10).setReceiverThreadCount(2)
				.setConnectionThreadCount(2)
				.setConnectionIdGenerator(new MultiNodeConnectionIdGenerator(NODE_ID_2, CID_LENGTH)).build();
		DtlsClusterConnectorConfig clusterConfig2 = DtlsClusterConnectorConfig.builder().setAddress(mgmtAddress2)
				.build();
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

		connector1 = new DtlsClusterConnector(config1, clusterConfig1, nodesProvider);
		connector2 = new DtlsClusterConnector(config2, clusterConfig2, nodesProvider);

		messages1 = new MessageCapturingProcessor();
		connector1.setRawDataReceiver(new SimpleRawDataChannel(connector1, messages1));

		messages2 = new MessageCapturingProcessor();
		connector2.setRawDataReceiver(new SimpleRawDataChannel(connector2, messages2));

		connector1.start();
		connector2.start();
	}

	@AfterClass
	public static void shutdownServer() {
		if (connector1 != null) {
			connector1.destroy();
			connector1 = null;
		}
		if (connector2 != null) {
			connector2.destroy();
			connector2 = null;
		}
	}

	@Before
	public void initClient() throws IOException {
		AdvancedSinglePskStore testPskStore = new AdvancedSinglePskStore(ConnectorHelper.CLIENT_IDENTITY,
				ConnectorHelper.CLIENT_IDENTITY_SECRET.getBytes());
		DtlsConnectorConfig config = DtlsConnectorConfig.builder().setAdvancedPskStore(testPskStore)
				.setMaxConnections(10).setReceiverThreadCount(2).setConnectionThreadCount(2)
				.setConnectionIdGenerator(new SingleNodeConnectionIdGenerator(4)).build();
		clientConnections = new InMemoryConnectionStore(10, 6000);
		clientConnector = new DTLSConnector(config, clientConnections);

		clientChannel = new LatchDecrementingRawDataChannel();
		clientConnector.setRawDataReceiver(clientChannel);

		clientConnector.start();
	}

	@After
	public void shutdownclient() {
		if (clientConnector != null) {
			clientConnector.destroy();
			clientConnector = null;
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
		String cid1 = endpointContext.get(DtlsEndpointContext.KEY_WRITE_CONNECTION_ID);
		String cid2 = endpointContext2.get(DtlsEndpointContext.KEY_WRITE_CONNECTION_ID);
		assertNotNull(cid1);
		assertNotNull(cid2);
		assertEquals(cid1, cid2);

		// check number of connections

		assertEquals(9, clientConnections.remainingCapacity());
	}
}
