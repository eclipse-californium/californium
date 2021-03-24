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

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.config.DtlsClusterConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.ContentType;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.NodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.ResumptionSupportingConnectionStore;
import org.eclipse.californium.scandium.dtls.SessionCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * DTLS cluster connector.
 * <p>
 * Forwards foreign cid records (tls_cid) to other connectors based on the
 * passed in {@link ClusterNodesProvider}. Requires a
 * {@link NodeConnectionIdGenerator} in {@link DtlsConnectorConfig} in order to
 * extract the node-id from the record's CID and to retrieve the own node-id.
 * </p>
 * <p>
 * In order to preserve the original source address, the forwarded records are
 * prepended by a header, which contains that original address. The forwarded
 * records are exchange using a separate endpoint (port) to easier separate the
 * cluster internal traffic from external record traffic. That additional
 * endpoint is configured using {@link DtlsClusterConnectorConfig}.
 * </p>
 * <p>
 * Generally, if a forwarded tls_cid record is processed and a message is sent
 * back by that final destination connector, that sent message is backwarded to
 * the original receiving connector. That is required for the most network setup
 * in order to keep all NATs and load-balancers working. If your network permits
 * to send outgoing messages also from other endpoints,
 * {@link DtlsClusterConnectorConfig} can be used to configure that.
 * </p>
 * 
 * @since 2.5
 */
public class DtlsClusterConnector extends DTLSConnector {

	private static final Logger LOGGER = LoggerFactory.getLogger(DtlsClusterConnector.class);
	/**
	 * Offset of cluster record type.
	 */
	protected static final int CLUSTER_RECORD_TYPE_OFFSET = 0;
	/**
	 * Offset for port of cluster records.
	 */
	protected static final int CLUSTER_PORT_OFFSET = 1;
	/**
	 * Offset for address length of cluster records.
	 */
	protected static final int CLUSTER_ADDRESS_LENGTH_OFFSET = 3;
	/**
	 * Offset for address of cluster records.
	 */
	protected static final int CLUSTER_ADDRESS_OFFSET = 4;
	/**
	 * Maximum address length for cluster records.
	 */
	protected static final int MIN_ADDRESS_LENGTH = 4;
	/**
	 * Maximum address length for cluster records.
	 */
	protected static final int MAX_ADDRESS_LENGTH = 16;
	/**
	 * Length of cluster Mac, if used.
	 * 
	 * @see #getClusterMacLength()
	 */
	protected static final int CLUSTER_MAC_LENGTH = 8;
	/**
	 * Maximum datagram offset for cluster records.
	 */
	protected static final int MAX_DATAGRAM_OFFSET = CLUSTER_ADDRESS_OFFSET + MAX_ADDRESS_LENGTH + CLUSTER_MAC_LENGTH;
	/**
	 * Type of incoming forwarded messages.
	 * 
	 * Unassigned according <a href=
	 * "https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5">IANA,
	 * TLS ContentType</a>, and no collision with CoAP messages
	 * <a href= "https://tools.ietf.org/html/rfc7252#section-3">RFC 7252,
	 * Message Format</a> (1. byte, version 0b01, others xx xxxx).
	 */
	public static final Byte RECORD_TYPE_INCOMING = (byte) 63;
	/**
	 * Type of outgoing forwarded messages.
	 * 
	 * Unassigned according <a href=
	 * "https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5">IANA,
	 * TLS ContentType</a>, and no collision with CoAP messages
	 * <a href= "https://tools.ietf.org/html/rfc7252#section-3">RFC 7252,
	 * Message Format</a> (1. byte, version 0b01, others xx xxxx).
	 */
	public static final Byte RECORD_TYPE_OUTGOING = (byte) 62;
	/**
	 * Node CID generator to extract node-id from CID and retrieve own node-id.
	 */
	private final NodeConnectionIdGenerator nodeCidGenerator;
	/**
	 * List of threads for cluster receiver.
	 */
	private final List<Thread> clusterReceiverThreads = new LinkedList<Thread>();
	/**
	 * Start receiver for cluster internal communication on
	 * {@link #init(InetSocketAddress, DatagramSocket, Integer)}.
	 */
	private final boolean startReceiver;
	/**
	 * Send messages back to original receiving dtls connector.
	 */
	private final boolean backwardMessages;
	/**
	 * DTLS cluster health statistic.
	 */
	protected final DtlsClusterHealth clusterHealth;
	/**
	 * Socket address for cluster internal communication.
	 */
	private final InetSocketAddress clusterInternalSocketAddress;
	/**
	 * Datagram socket for cluster internal communication.
	 */
	protected volatile DatagramSocket clusterInternalSocket;
	/**
	 * Nodes provider for cluster.
	 */
	private volatile ClusterNodesProvider nodesProvider;

	/**
	 * Create dtls connector with cluster support.
	 * 
	 * @param configuration dtls configuration
	 * @param clusterConfiguration cluster internal connector configuration
	 * @param nodes nodes provider
	 * @throws IllegalArgumentException if the configuration doesn't provide a
	 *             cid generator, or the cid generator only supports, but
	 *             doesn't use cids, or the cid generator is no
	 *             {@link NodeConnectionIdGenerator}.
	 */
	public DtlsClusterConnector(DtlsConnectorConfig configuration, DtlsClusterConnectorConfig clusterConfiguration,
			ClusterNodesProvider nodes) {
		this(configuration, clusterConfiguration, nodes, null);
	}

	/**
	 * Create dtls connector with cluster support and session cache.
	 * 
	 * @param configuration dtls configuration
	 * @param clusterConfiguration cluster internal connector configuration
	 * @param nodes nodes provider
	 * @param sessionCache session cache. May be {@code null}.
	 * @throws IllegalArgumentException if the configuration doesn't provide a
	 *             cid generator, or the cid generator only supports, but
	 *             doesn't use cids, or the cid generator is no
	 *             {@link NodeConnectionIdGenerator}.
	 */
	public DtlsClusterConnector(DtlsConnectorConfig configuration, DtlsClusterConnectorConfig clusterConfiguration,
			ClusterNodesProvider nodes, SessionCache sessionCache) {
		this(configuration, clusterConfiguration, createConnectionStore(configuration, sessionCache), true);
		setClusterNodesProvider(nodes);
	}

	/**
	 * Create dtls connector with cluster support and connection store.
	 * 
	 * @param configuration dtls configuration
	 * @param clusterConfiguration cluster internal connector configuration
	 * @param connectionStore connection store
	 * @param startReceiver {@code true}, start receiver threads for cluster
	 *            internal communication on
	 *            {@link #init(InetSocketAddress, DatagramSocket, Integer)},
	 *            {@code false}, otherwise.
	 * @throws IllegalArgumentException if the configuration doesn't provide a
	 *             cid generator, or the cid generator only supports, but
	 *             doesn't use cids, or the cid generator is no
	 *             {@link NodeConnectionIdGenerator}.
	 */
	protected DtlsClusterConnector(DtlsConnectorConfig configuration, DtlsClusterConnectorConfig clusterConfiguration,
			ResumptionSupportingConnectionStore connectionStore, boolean startReceiver) {
		super(configuration, connectionStore);
		this.nodeCidGenerator = getNodeConnectionIdGenerator();
		this.clusterInternalSocketAddress = clusterConfiguration.getAddress();
		this.backwardMessages = clusterConfiguration.useBackwardMessages();
		this.clusterHealth = (health instanceof DtlsClusterHealth) ? (DtlsClusterHealth) health : null;
		this.startReceiver = startReceiver;
		LOGGER.info("cluster-node {}: on internal {}, backwards {}", getNodeID(),
				StringUtil.toDisplayString(clusterInternalSocketAddress), backwardMessages);
	}

	/**
	 * Get node's cid generator.
	 * 
	 * @return node's cid generator.
	 * @throws IllegalArgumentException if cid generator is not provided, or the
	 *             cid generator only supports, but doesn't use cids, or the cid
	 *             generator is no {@link NodeConnectionIdGenerator}.
	 */
	private NodeConnectionIdGenerator getNodeConnectionIdGenerator() {
		if (connectionIdGenerator == null) {
			throw new IllegalArgumentException("CID generator missing!");
		} else if (!connectionIdGenerator.useConnectionId()) {
			throw new IllegalArgumentException("CID not used!");
		} else if (!(connectionIdGenerator instanceof NodeConnectionIdGenerator)) {
			throw new IllegalArgumentException("CID generator not supports nodes!");
		}
		return (NodeConnectionIdGenerator) connectionIdGenerator;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Creates a {@link DtlsClusterHealthLogger}.
	 */
	@Override
	protected DtlsHealth createDefaultHealthHandler(DtlsConnectorConfig configuration) {
		return new DtlsClusterHealthLogger(configuration.getLoggingTag());
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Creates also socket and threads for cluster internal communication. The
	 * threads are only create, if {@link #startReceiver} is {@code true}.
	 */
	@Override
	protected void init(InetSocketAddress bindAddress, DatagramSocket socket, Integer mtu) throws IOException {
		try {
			clusterInternalSocket = new DatagramSocket(clusterInternalSocketAddress);
		} catch (IOException ex) {
			LOGGER.error("cluster-node {}: management-interface {} failed!", getNodeID(),
					StringUtil.toDisplayString(clusterInternalSocketAddress));
			throw ex;
		}
		super.init(bindAddress, socket, mtu);
		if (startReceiver) {
			startReceiver();
		}
	}

	/**
	 * Start receiver threads for cluster internal communication.
	 * 
	 * After starting the threads, the {@link #clusterInternalSocket} may be
	 * locked by these threads calling
	 * {@link DatagramSocket#receive(DatagramPacket)}.
	 */
	protected void startReceiver() {
		int receiverThreadCount = config.getReceiverThreadCount();
		for (int i = 0; i < receiverThreadCount; i++) {
			Worker receiver = new Worker(
					"DTLS-Cluster-" + getNodeID() + "-Receiver-" + i + "-" + clusterInternalSocketAddress) {

				private final byte[] receiverBuffer = new byte[inboundDatagramBufferSize + MAX_DATAGRAM_OFFSET];
				private final DatagramPacket clusterPacket = new DatagramPacket(receiverBuffer, receiverBuffer.length);

				@Override
				public void doWork() throws Exception {
					clusterPacket.setData(receiverBuffer);
					clusterInternalSocket.receive(clusterPacket);
					Byte type = getClusterRecordType(clusterPacket);
					if (type != null) {
						if (ensureLength(type, clusterPacket)) {
							processDatagramFromClusterNetwork(type, clusterPacket);
						} else if (clusterHealth != null) {
							clusterHealth.dropForwardMessage();
						}
					} else {
						processManagementDatagramFromClusterNetwork(clusterPacket);
					}
				}
			};
			receiver.setDaemon(true);
			receiver.start();
			clusterReceiverThreads.add(receiver);
		}
		LOGGER.info("cluster-node {}: started {}", getNodeID(), clusterInternalSocket.getLocalSocketAddress());
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Stop also socket and threads for cluster internal communication.
	 */
	@Override
	public void stop() {
		super.stop();
		synchronized (this) {
			clusterInternalSocket.close();
			for (Thread t : clusterReceiverThreads) {
				t.interrupt();
				try {
					t.join(500);
				} catch (InterruptedException e) {
				}
			}
			clusterReceiverThreads.clear();
		}
	}

	/**
	 * Get cluster MAC length.
	 * 
	 * @return cluster MAC length. {@code 0}, if cluster MAC is not used.
	 */
	protected int getClusterMacLength() {
		return 0;
	}

	/**
	 * Set cluster nodes provider.
	 * 
	 * @param nodes cluster nodes provider
	 */
	public void setClusterNodesProvider(ClusterNodesProvider nodes) {
		this.nodesProvider = nodes;
	}

	/**
	 * Get connector's node-id.
	 * 
	 * @return node-id.
	 */
	public int getNodeID() {
		return nodeCidGenerator.getNodeId();
	}

	/**
	 * Check, if internal message is forwarded or backwarded record.
	 * 
	 * @param clusterPacket cluster internal message
	 * @return {@link #RECORD_TYPE_INCOMING}, if message is forwarded,
	 *         {@link #RECORD_TYPE_OUTGOING}, if message is backwarded,
	 *         {@code null}, otherwise.
	 */
	protected Byte getClusterRecordType(DatagramPacket clusterPacket) {
		final byte type = clusterPacket.getData()[clusterPacket.getOffset() + CLUSTER_RECORD_TYPE_OFFSET];
		if (type == RECORD_TYPE_INCOMING.byteValue()) {
			return RECORD_TYPE_INCOMING;
		} else if (type == RECORD_TYPE_OUTGOING.byteValue()) {
			return RECORD_TYPE_OUTGOING;
		}
		return null;
	}

	/**
	 * Ensure, that the packet is large enough for a valid cluster internal
	 * message.
	 * 
	 * @param type {@link #RECORD_TYPE_INCOMING} or
	 *            {@link #RECORD_TYPE_OUTGOING}.
	 * @param clusterPacket the cluster internal message.
	 * @return {@code true}, if the cluster internal message is large enough,
	 *         {@code false}, if it is too short.
	 */
	protected boolean ensureLength(Byte type, DatagramPacket clusterPacket) {
		int length = clusterPacket.getLength();
		if (length < (CLUSTER_ADDRESS_OFFSET + MIN_ADDRESS_LENGTH + DTLSSession.DTLS_HEADER_LENGTH)) {
			return false;
		}
		byte[] data = clusterPacket.getData();
		int offset = clusterPacket.getOffset();
		int addressLength = data[offset + CLUSTER_ADDRESS_LENGTH_OFFSET] & 0xff;
		int macLength = getClusterMacLength();

		return length > CLUSTER_ADDRESS_OFFSET + addressLength + macLength + DTLSSession.DTLS_HEADER_LENGTH;
	}

	/**
	 * Process received cluster internal message.
	 * 
	 * @param type cluster record type. {@link #RECORD_TYPE_INCOMING} or
	 *            {@link #RECORD_TYPE_OUTGOING}.
	 * @param clusterPacket cluster internal message
	 * @throws IOException if an io-error occurred.
	 */
	protected void processDatagramFromClusterNetwork(Byte type, DatagramPacket clusterPacket) throws IOException {
		InetSocketAddress router = (InetSocketAddress) clusterPacket.getSocketAddress();
		DatagramPacket packet = decode(clusterPacket);
		if (packet == null) {
			// nothing to do
			if (clusterHealth != null) {
				clusterHealth.dropForwardMessage();
			}
			return;
		}
		if (RECORD_TYPE_INCOMING.equals(type)) {
			LOGGER.trace("cluster-node {}: received forwarded message", getNodeID());
			super.processDatagram(packet, router);
			if (clusterHealth != null) {
				clusterHealth.processForwardedMessage();
			}
		} else if (RECORD_TYPE_OUTGOING.equals(type)) {
			LOGGER.trace("cluster-node {}: received backwarded outgoing message", getNodeID());
			super.sendNextDatagramOverNetwork(packet);
			if (clusterHealth != null) {
				clusterHealth.sendBackwardedMessage();
			}
		}
	}

	/**
	 * Process cluster internal management message.
	 * 
	 * Not used for forwarded or backwarded tls_cid records.
	 * 
	 * @param clusterPacket cluster internal management message.
	 * @throws IOException if an i/o-error occurred
	 */
	protected void processManagementDatagramFromClusterNetwork(DatagramPacket clusterPacket) throws IOException {
		// empty default implementation
	}

	/**
	 * Send cluster internal message.
	 * 
	 * Used for forwarded or backwarded tls_cid records.
	 * 
	 * @param clusterPacket cluster internal message
	 * @throws IOException if an i/o-error occurred.
	 */
	protected void sendDatagramToClusterNetwork(DatagramPacket clusterPacket) throws IOException {
		clusterInternalSocket.send(clusterPacket);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Test for CID records and forward foreign records to other nodes, based on
	 * the returned node-id of the {@link NodeConnectionIdGenerator}.
	 */
	@Override
	protected void processDatagram(DatagramPacket packet, InetSocketAddress router) {
		int offset = packet.getOffset();
		int length = packet.getLength();
		byte[] data = packet.getData();
		InetSocketAddress source = (InetSocketAddress) packet.getSocketAddress();
		if (data[offset] == ContentType.TLS12_CID.getCode()) {
			if (length > Record.RECORD_HEADER_BYTES) {
				DatagramReader reader = new DatagramReader(data, offset, length);
				ConnectionId cid = Record.readConnectionIdFromReader(reader, connectionIdGenerator);
				if (cid != null) {
					int incomingNodeId = nodeCidGenerator.getNodeId(cid);
					if (getNodeID() != incomingNodeId) {
						LOGGER.trace("cluster-node {}: received foreign message for {} from {}", getNodeID(),
								incomingNodeId, source);
						InetSocketAddress clusterNode = nodesProvider.getClusterNode(incomingNodeId);
						if (clusterNode != null) {
							DatagramPacket clusterPacket = encode(RECORD_TYPE_INCOMING, packet, null);
							clusterPacket.setSocketAddress(clusterNode);
							try {
								LOGGER.trace("cluster-node {}: forwards received message from {} to {}, {} bytes",
										getNodeID(), source, clusterNode, length);
								sendDatagramToClusterNetwork(clusterPacket);
								if (clusterHealth != null) {
									clusterHealth.forwardMessage();
								}
								return;
							} catch (IOException e) {
								LOGGER.info("cluster-node {}: forward error:", getNodeID(), e);
								if (clusterHealth != null) {
									clusterHealth.dropForwardMessage();
								} else {
									health.receivingRecord(true);
								}
							}
						} else {
							LOGGER.debug(
									"cluster-node {}: received foreign message from {} for unknown node {}, {} bytes, dropping.",
									getNodeID(), source, incomingNodeId, length);
							if (clusterHealth != null) {
								clusterHealth.dropForwardMessage();
							} else {
								health.receivingRecord(true);
							}
						}
					} else {
						LOGGER.trace("cluster-node {}: received own message from {}, {} bytes", getNodeID(), source,
								length);
					}
				} else {
					LOGGER.debug("cluster-node {}: received broken CID message from {}", getNodeID(), source);
				}
			} else {
				LOGGER.debug("cluster-node {}: received too short CID message from {}", getNodeID(), source);
			}
		} else {
			LOGGER.trace("cluster-node {}: received no CID message from {}, {} bytes.", getNodeID(), source, length);
		}
		super.processDatagram(packet, null);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * For {@link Record#getRouter()} destinations, backwards massage to
	 * original receiving connector (router).
	 */
	@Override
	protected void sendRecord(Record record) throws IOException {
		InetSocketAddress destination = record.getPeerAddress();
		InetSocketAddress router = record.getRouter();
		if (router != null && backwardMessages) {
			if (nodesProvider.available(router)) {
				byte[] recordBytes = record.toByteArray();
				int length = recordBytes.length;
				byte[] datagramBytes = new byte[length + MAX_DATAGRAM_OFFSET];
				LOGGER.trace("cluster-node {}: backwards send message for {} to {}, {} bytes", getNodeID(), destination,
						router, length);
				DatagramPacket datagram = new DatagramPacket(datagramBytes, datagramBytes.length, destination);
				DatagramPacket clusterPacket = encode(RECORD_TYPE_OUTGOING, datagram, recordBytes);
				clusterPacket.setSocketAddress(router);
				try {
					sendDatagramToClusterNetwork(clusterPacket);
					if (clusterHealth != null) {
						clusterHealth.backwardMessage();
					}
				} catch (IOException ex) {
					LOGGER.debug("cluster-node {}: sending internal message failed!", getNodeID(), ex);
					if (clusterHealth != null) {
						clusterHealth.dropBackwardMessage();
					}
					throw ex;
				}
			} else {
				if (clusterHealth != null) {
					clusterHealth.dropBackwardMessage();
				}
				throw new IOException(
						"Cluster internal destination " + StringUtil.toString(router) + " not longer available!");
			}
		} else {
			LOGGER.trace("cluster-node {}: sends message to {}, {} bytes", getNodeID(), destination, record.size());
			super.sendRecord(record);
		}
	}

	/**
	 * Encode message for cluster internal communication.
	 * 
	 * Add original source address at message head.
	 * 
	 * @param direction direction of message. Values are
	 *            {@link #RECORD_TYPE_INCOMING} or {@link #RECORD_TYPE_OUTGOING}
	 * @param packet packet to prepare. contains the original record, if
	 *            recordBytes is {@code null}.
	 * @param recordBytes message to send
	 * @return encoded message with original source address
	 * @see #decode(DatagramPacket)
	 */
	private DatagramPacket encode(byte direction, DatagramPacket packet, byte[] recordBytes) {
		InetAddress source = packet.getAddress();
		byte[] address = source.getAddress();
		int headerLength = CLUSTER_ADDRESS_OFFSET + address.length + getClusterMacLength();
		byte[] data = packet.getData();
		int offset;
		int length;
		if (recordBytes == null) {
			offset = packet.getOffset();
			length = packet.getLength();
			if (offset != headerLength) {
				System.arraycopy(data, offset, data, headerLength, length);
			}
		} else {
			offset = 0;
			length = recordBytes.length;
			System.arraycopy(recordBytes, 0, data, headerLength, length);
		}
		data[CLUSTER_RECORD_TYPE_OFFSET] = direction;
		data[CLUSTER_PORT_OFFSET] = (byte) packet.getPort();
		data[CLUSTER_PORT_OFFSET + 1] = (byte) (packet.getPort() >> 8);
		data[CLUSTER_ADDRESS_LENGTH_OFFSET] = (byte) address.length;
		System.arraycopy(address, 0, data, CLUSTER_ADDRESS_OFFSET, address.length);
		packet.setData(data, 0, length + headerLength);
		return packet;
	}

	/**
	 * Decode message from cluster internal communication.
	 * 
	 * @param packet message with original source address encoded at head.
	 * @return message with decoded original source address
	 * @see #encode(DatagramPacket, byte)
	 */
	private DatagramPacket decode(DatagramPacket packet) {
		try {
			byte[] data = packet.getData();
			int offset = packet.getOffset();
			int length = packet.getLength();
			int addressLength = data[offset + CLUSTER_ADDRESS_LENGTH_OFFSET] & 0xff;
			int port = (data[offset + CLUSTER_PORT_OFFSET] & 0xff)
					| ((data[offset + CLUSTER_PORT_OFFSET + 1] & 0xff) << 8);
			byte[] address = Arrays.copyOfRange(data, offset + CLUSTER_ADDRESS_OFFSET,
					offset + CLUSTER_ADDRESS_OFFSET + addressLength);
			int headerLength = CLUSTER_ADDRESS_OFFSET + addressLength + getClusterMacLength();
			InetAddress iaddr = InetAddress.getByAddress(address);
			packet.setAddress(iaddr);
			packet.setPort(port);
			packet.setData(data, offset + headerLength, length - headerLength);
			return packet;
		} catch (UnknownHostException e) {
			return null;
		} catch (RuntimeException e) {
			return null;
		}
	}

	/**
	 * Cluster nodes provider. Maintaining internal addresses of nodes.
	 * 
	 * It extremely performance critical to immediately return results!
	 */
	public static interface ClusterNodesProvider {

		/**
		 * Get address for node.
		 * 
		 * @param nodeId node id of node
		 * @return internal address of node. {@code null}, if not available.
		 */
		InetSocketAddress getClusterNode(int nodeId);

		/**
		 * Check, if address to backward message is still available.
		 * 
		 * @param destinationConnector address of destination connector.
		 * @return {@code true}, if destination is still available,
		 *         {@code false}, if not.
		 */
		boolean available(InetSocketAddress destinationConnector);
	}
}
