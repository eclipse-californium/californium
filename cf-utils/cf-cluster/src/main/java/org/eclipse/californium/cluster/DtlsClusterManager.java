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
package org.eclipse.californium.cluster;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.ExtendedConnector;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.MessageCallback;
import org.eclipse.californium.elements.PrincipalEndpointContextMatcher;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.elements.UdpEndpointContextMatcher;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.scandium.DtlsClusterConnector.ClusterNodesProvider;
import org.eclipse.californium.scandium.DtlsManagedClusterConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * DTLS cluster manager.
 * 
 * Discover and update cluster cid nodes associations dynamically. The manager
 * requires the cluster management connector
 * {@link DtlsManagedClusterConnector#getClusterManagementConnector()} in order
 * to exchange cluster management messages with other nodes.
 * 
 * The manager refreshes all other available nodes using a short interval.
 * Discovering new nodes by sending a message probe to such potential nodes is
 * done less frequently. If a node receives a ping, that node gets also
 * refreshed and the receiving node will not send a ping message to refresh that
 * node until the refresh interval expires.
 * 
 * @since 2.5
 */
public class DtlsClusterManager {

	private static final Logger LOGGER = LoggerFactory.getLogger(DtlsClusterManager.class);

	/**
	 * Type of cluster management node-id request.
	 */
	private static final byte MAGIC_ID_PING = (byte) 61;
	/**
	 * Type of cluster management node-id response.
	 */
	private static final byte MAGIC_ID_PONG = (byte) 60;
	/**
	 * Protocol for cluster management.
	 */
	private final String tag;
	/**
	 * {@code true}, for secure DTLS cluster management connector,
	 * {@code false}, for plain UDP.
	 */
	private final boolean secure;
	/**
	 * Timer to handle cluster-nodes refresh and discover.
	 */
	private final ScheduledExecutorService timer;
	/**
	 * Cluster nodes discover callback.
	 */
	private final ClusterNodesDiscover discoverScope;
	/**
	 * Discover and provide nodes for cluster.
	 */
	private final NodesDiscoverer nodesDiscoverer;
	/**
	 * Managed internal connector for cluster.
	 */
	private final DtlsManagedClusterConnector clusterConnector;
	/**
	 * Node id of this cluster node.
	 */
	private final int nodeId;
	/**
	 * Cluster manager configuration.
	 */
	private final DtlsClusterManagerConfig configuration;

	/**
	 * Logging callback for sending cluster management messages.
	 */
	private final MessageCallback messageLoggingCallback = new MessageCallback() {

		@Override
		public void onSent() {
			LOGGER.trace("cluster-node {}: sent", tag);
		}

		@Override
		public void onError(Throwable error) {
			LOGGER.info("cluster-node {}: error", tag, error);
		}

		@Override
		public void onDtlsRetransmission(int flight) {
			LOGGER.trace("cluster-node {}: retransmission flight {}", tag, flight);
		}

		@Override
		public void onContextEstablished(EndpointContext context) {
			LOGGER.trace("cluster-node {}: context established", tag);
		}

		@Override
		public void onConnecting() {
			LOGGER.trace("cluster-node {}: connecting ...", tag);
		}
	};

	private final EndpointContextMatcher matcher;

	/**
	 * Schedule for cluster management timer.
	 */
	private ScheduledFuture<?> schedule;

	/**
	 * Create dtls cluster manager.
	 * 
	 * @param clusterConnector dtls cluster connector
	 * @param configuration cluster manager configuration
	 * @param nodes cluster nodes discoverer
	 * @param timer timer executor service
	 */
	public DtlsClusterManager(DtlsManagedClusterConnector clusterConnector, DtlsClusterManagerConfig configuration,
			ClusterNodesDiscover nodes, ScheduledExecutorService timer) {
		this.clusterConnector = clusterConnector;
		this.nodeId = clusterConnector.getNodeID();
		this.discoverScope = nodes;
		this.timer = timer;
		this.nodesDiscoverer = new NodesDiscoverer();
		this.clusterConnector.setClusterNodesProvider(this.nodesDiscoverer);
		this.configuration = configuration;
		String protocol = clusterConnector.getManagementProtocol();
		this.tag = clusterConnector.getNodeID() + " (" + protocol + ")";
		this.secure = DtlsManagedClusterConnector.PROTOCOL_MANAGEMENT_DTLS.equals(protocol)
				|| DtlsManagedClusterConnector.PROTOCOL_MANAGEMENT_DTLS_MAC.equals(protocol);
		clusterConnector.getClusterManagementConnector().setRawDataReceiver(new RawDataChannel() {

			@Override
			public void receiveData(RawData clusterData) {
				processMessageFromClusterManagement(clusterData);
			}
		});
		if (this.secure) {
			this.matcher = new PrincipalEndpointContextMatcher();
		} else {
			this.matcher = new UdpEndpointContextMatcher(true);
		}
		clusterConnector.setEndpointContextMatcher(this.matcher);
	}

	/**
	 * Start cluster manager.
	 * 
	 * Schedule timer with
	 * {@link DtlsClusterManagerConfig#getTimerIntervalMillis()}.
	 */
	public synchronized void start() {
		if (schedule != null) {
			return;
		}
		long intervalMillis = configuration.getTimerIntervalMillis();
		schedule = timer.scheduleWithFixedDelay(new Runnable() {

			@Override
			public void run() {
				try {
					nodesDiscoverer.process(clusterConnector.getClusterManagementConnector());
				} catch (Throwable t) {
					LOGGER.warn("cluster-node {}: discover", tag, t);
				}
			}
		}, intervalMillis / 2, intervalMillis, TimeUnit.MILLISECONDS);
	}

	/**
	 * Stop cluster manager.
	 * 
	 * Cancel scheduled timer.
	 */
	public synchronized void stop() {
		if (schedule != null) {
			schedule.cancel(false);
			schedule = null;
		}
	}

	/**
	 * Process cluster management data.
	 * 
	 * @param clusterData cluster management data
	 */
	protected void processMessageFromClusterManagement(RawData clusterData) {
		final byte[] data = clusterData.getBytes();

		final byte type = data[0];
		if (clusterData.getSize() < 5) {
			// nothing to do
			return;
		}
		InetSocketAddress router = (InetSocketAddress) clusterData.getInetSocketAddress();
		if (type == MAGIC_ID_PING) {
			int foreignNodeId = decodePingPong(data);
			if (nodeId != foreignNodeId) {
				nodesDiscoverer.update(foreignNodeId, router, clusterData.getEndpointContext(), matcher);
				LOGGER.info("cluster-node {}: >update node {} to {}", tag, foreignNodeId, router);
				// reset packet size
				encodePingPong(data, MAGIC_ID_PONG, nodeId);
				RawData outbound = RawData.outbound(data, clusterData.getEndpointContext(), null, false);
				clusterConnector.getClusterManagementConnector().send(outbound);
			} else {
				LOGGER.info("cluster-node {}: >update self {}, ignored!", tag, router);
			}
		} else if (type == MAGIC_ID_PONG) {
			int foreignNodeId = decodePingPong(data);
			nodesDiscoverer.update(foreignNodeId, router, clusterData.getEndpointContext(), matcher);
			LOGGER.info("cluster-node {}: <update node {} to {}", tag, foreignNodeId, router);
		}
	}

	/**
	 * Decode node-id from {@link #MAGIC_ID_PING} or {@link #MAGIC_ID_PING}
	 * messages.
	 * 
	 * @param data received cluster management data
	 * @return node-id
	 */
	private static int decodePingPong(byte[] data) {
		int nodeId = data[1] & 0xff;
		nodeId |= (data[2] & 0xff) << 8;
		nodeId |= (data[3] & 0xff) << 16;
		nodeId |= (data[4] & 0xff) << 24;
		return nodeId;
	}

	/**
	 * Encode type and node-id.
	 * 
	 * @param data cluster management data to send
	 * @param type {@link #MAGIC_ID_PING} or {@link #MAGIC_ID_PING}
	 * @param nodeId node-id
	 */
	private static void encodePingPong(byte[] data, byte type, int nodeId) {
		data[0] = type;
		data[1] = (byte) (nodeId);
		data[2] = (byte) (nodeId >> 8);
		data[3] = (byte) (nodeId >> 16);
		data[4] = (byte) (nodeId >> 24);
	}

	/**
	 * Interface to get cluster nodes scope.
	 */
	public static interface ClusterNodesDiscover {

		/**
		 * List of addresses of other nodes in the cluster.
		 * 
		 * This is called less frequently, short delay may be accepted, e.g. 1s
		 * for a k8s API http-request.
		 * 
		 * @return list of other nodes.
		 */
		List<InetSocketAddress> getClusterNodesDiscoverScope();

	}

	/**
	 * Discover manager and provide nodes for cluster.
	 */
	private class NodesDiscoverer implements ClusterNodesProvider {

		/**
		 * Buffer for cluster management message.
		 */
		private final byte[] discoverBuffer = new byte[5];
		/**
		 * Map of node-ids to nodes.
		 */
		private final ConcurrentMap<Integer, Node> nodesById = new ConcurrentHashMap<>();
		/**
		 * Map of management interface addresses to nodes.
		 */
		private final ConcurrentMap<InetSocketAddress, Node> nodesByAddress = new ConcurrentHashMap<>();
		/**
		 * Random for order of messages.
		 */
		private final Random rand = new Random(ClockUtil.nanoRealtime());
		/**
		 * Nanos of next discover operation.
		 */
		private volatile long nextDiscover;

		/**
		 * Create discover manager.
		 */
		private NodesDiscoverer() {
		}

		@Override
		public InetSocketAddress getClusterNode(int nodeId) {
			Node node = nodesById.get(nodeId);
			if (node != null) {
				return node.address;
			} else {
				return null;
			}
		}

		@Override
		public boolean available(InetSocketAddress destinationConnector) {
			return nodesByAddress.containsKey(destinationConnector);
		}

		/**
		 * Update address of node for node-id
		 * 
		 * @param nodeId node-id
		 * @param address cluster management interface address
		 */
		public synchronized void update(int nodeId, InetSocketAddress address, EndpointContext context,
				EndpointContextMatcher matcher) {
			if (DtlsClusterManager.this.nodeId == nodeId) {
				throw new IllegalArgumentException("Own node ID not supported!");
			}
			Node iNode = nodesById.get(nodeId);
			if (iNode == null) {
				iNode = new Node(nodeId);
				nodesById.put(nodeId, iNode);
			}
			iNode.update(address, context, matcher);
			Node aNode = nodesByAddress.put(address, iNode);
			if (aNode != null && aNode != iNode) {
				nodesById.remove(nodeId, aNode);
			}
		}

		/**
		 * Remove cluster node.
		 * 
		 * @param node remove cluster node.
		 */
		private synchronized void remove(Node node) {
			nodesById.remove(node.nodeId, node);
			nodesByAddress.remove(node.address, node);
		}

		/**
		 * Process node refreshing and discovering.
		 * 
		 * @param clusterManagementConnector connector for cluster management
		 */
		public void process(ExtendedConnector clusterManagementConnector) {
			synchronized (rand) {
				if (clusterManagementConnector != null && clusterManagementConnector.isRunning()) {
					long now = ClockUtil.nanoRealtime();
					encodePingPong(discoverBuffer, MAGIC_ID_PING, nodeId);
					boolean discover = refresh(now, clusterManagementConnector) || nodesById.isEmpty()
							|| nextDiscover - now <= 0;
					if (discover && clusterManagementConnector.isRunning()) {
						discover(clusterManagementConnector);
						nextDiscover = ClockUtil.nanoRealtime()
								+ TimeUnit.MILLISECONDS.toNanos(configuration.getDiscoverIntervalMillis());
					}
				}
			}
		}

		/**
		 * Refresh cluster nodes.
		 * 
		 * @param now real time in nanoseconds
		 * @param clusterManagementConnector connector for cluster management
		 * @return {@code true}, if nodes are expired, {@code false}, otherwise.
		 */
		private boolean refresh(long now, ExtendedConnector clusterManagementConnector) {
			boolean expired = false;
			long freshTimeNanos = now - TimeUnit.MILLISECONDS.toNanos(configuration.getRefreshIntervalMillis());
			long expireTimeNanos = freshTimeNanos
					- TimeUnit.MILLISECONDS.toNanos(configuration.getExpirationTimeMillis());
			List<Node> nodes = new ArrayList<>();
			for (Node node : nodesById.values()) {
				if (node.nodeId == nodeId) {
					// self, not intended to be included
				} else if (node.isBefore(expireTimeNanos)) {
					remove(node);
					expired = true;
				} else if (node.isBefore(freshTimeNanos)) {
					nodes.add(node);
				} else {
					LOGGER.debug("cluster-node {}: keep node {} at {}", tag, node.nodeId, node.address);
				}
			}
			while (!nodes.isEmpty()) {
				int pos = rand.nextInt(nodes.size());
				Node node = nodes.remove(pos);
				if (clusterManagementConnector.isRunning()) {
					RawData outbound = RawData.outbound(discoverBuffer, node.context, messageLoggingCallback, false);
					clusterManagementConnector.send(outbound);
					LOGGER.info("cluster-node {}: refresh node {} at {}", tag, node.nodeId, node.address);
				}
			}
			return expired;
		}

		/**
		 * Discover new nodes.
		 * 
		 * @param clusterManagementConnector connector for cluster management
		 */
		private void discover(ExtendedConnector clusterManagementConnector) {
			List<InetSocketAddress> scope = discoverScope.getClusterNodesDiscoverScope();
			List<InetSocketAddress> nodes = new ArrayList<>();
			for (InetSocketAddress node : scope) {
				LOGGER.debug("cluster-node {}: discover scope {}", tag, node);
				if (!nodesByAddress.containsKey(node)) {
					nodes.add(node);
				}
			}
			while (!nodes.isEmpty()) {
				int pos = rand.nextInt(nodes.size());
				InetSocketAddress node = nodes.remove(pos);
				if (clusterManagementConnector.isRunning()) {
					EndpointContext context;
					if (secure) {
						context = new MapBasedEndpointContext(node, null, DtlsEndpointContext.KEY_HANDSHAKE_MODE,
								DtlsEndpointContext.HANDSHAKE_MODE_FORCE);
					} else {
						context = new AddressEndpointContext(node);
					}
					RawData outbound = RawData.outbound(discoverBuffer, context, messageLoggingCallback, false);
					clusterManagementConnector.send(outbound);
					LOGGER.info("cluster-node {}:  discover {}", tag, node);
				}
			}
		}
	}

	/**
	 * Cluster node.
	 */
	private static class Node {

		/**
		 * Node-id.
		 */
		private final int nodeId;
		/**
		 * Cluster management interface address of node.
		 */
		private InetSocketAddress address;
		/**
		 * Realtime in nanoseconds of last address update.
		 */
		private long time;
		/**
		 * EndpointContext for internal management messages.
		 */
		private EndpointContext context;

		/**
		 * Create node.
		 * 
		 * @param nodeId node-id.
		 * @param address cluster management interface address
		 */
		private Node(int nodeId) {
			this.nodeId = nodeId;
		}

		/**
		 * Update address and usage time.
		 * 
		 * @param address cluster management interface address
		 */
		private synchronized void update(InetSocketAddress address, EndpointContext context,
				EndpointContextMatcher matcher) {
			this.address = address;
			if (this.context == null) {
				this.context = context;
			} else {
				matcher.isResponseRelatedToRequest(this.context, context);
			}
			this.time = ClockUtil.nanoRealtime();
		}

		/**
		 * Test, if provided nano time is before the last usage.
		 * 
		 * @param timeNanos realtime in nanoseconds
		 * @return {@code true}, if provided nano time is before last usage,
		 *         {@code false}, otherwise.
		 */
		private synchronized boolean isBefore(long timeNanos) {
			return timeNanos - time > 0;
		}
	}

}
