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
import java.net.InetSocketAddress;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.eclipse.californium.elements.ExtendedConnector;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.config.DtlsClusterConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.Handshaker;
import org.eclipse.californium.scandium.dtls.SessionCache;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedSinglePskStore;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * DTLS dynamic cluster connector.
 * 
 * Discover and update cluster cid nodes associations dynamically.
 * 
 * @since 2.5
 */
public class DtlsManagedClusterConnector extends DtlsClusterConnector {

	private static final Logger LOGGER = LoggerFactory.getLogger(DtlsManagedClusterConnector.class);

	public static final String PROTOCOL_MANAGEMENT_UDP = "mgmt-udp";
	public static final String PROTOCOL_MANAGEMENT_DTLS = "mgmt-dtls";
	public static final String PROTOCOL_MANAGEMENT_DTLS_MAC = "mgmt-dtls-mac";

	/**
	 * Protocol for cluster management.
	 */
	private final String protocol;
	/**
	 * Send messages back to original receiving dtls connector.
	 */
	private final boolean useClusterMac;
	/**
	 * Connector for cluster management.
	 */
	private volatile ExtendedConnector clusterManagementConnector;

	/**
	 * Create dtls connector with dynamic cluster support.
	 * 
	 * @param configuration dtls configuration
	 * @param clusterConfiguration cluster internal connector configuration
	 */
	public DtlsManagedClusterConnector(DtlsConnectorConfig configuration,
			DtlsClusterConnectorConfig clusterConfiguration) {
		this(configuration, clusterConfiguration, null);
	}

	/**
	 * Create dtls connector with dynamic cluster support.
	 * 
	 * @param configuration dtls configuration
	 * @param clusterConfiguration cluster internal connector configuration
	 * @param sessionCache session cache
	 */
	public DtlsManagedClusterConnector(DtlsConnectorConfig configuration,
			DtlsClusterConnectorConfig clusterConfiguration, SessionCache sessionCache) {
		super(configuration, clusterConfiguration, sessionCache);
		String identity = clusterConfiguration.getSecureIdentity();
		Integer mgmtReceiveBuffer = add(config.getSocketReceiveBufferSize(), MAX_DATAGRAM_OFFSET);
		Integer mgmtSendBuffer = add(config.getSocketSendBufferSize(), MAX_DATAGRAM_OFFSET);
		if (identity != null) {
			SecretKey secretkey = clusterConfiguration.getSecretKey();
			DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder()
					.setAddress(clusterConfiguration.getAddress()).setReceiverThreadCount(0).setMaxConnections(1024)
					.setSocketReceiveBufferSize(mgmtReceiveBuffer).setSocketSendBufferSize(mgmtSendBuffer)
					.setAdvancedPskStore(new AdvancedSinglePskStore(identity, secretkey));
			SecretUtil.destroy(secretkey);
			this.clusterManagementConnector = new ClusterManagementDtlsConnector(builder.build());
			this.useClusterMac = clusterConfiguration.useClusterMac();
			this.protocol = this.useClusterMac ? PROTOCOL_MANAGEMENT_DTLS_MAC : PROTOCOL_MANAGEMENT_DTLS;
		} else {
			ClusterManagementUdpConnector connector = new ClusterManagementUdpConnector(
					clusterConfiguration.getAddress());
			connector.setReceiverThreadCount(0);
			connector.setSenderThreadCount(2);
			if (mgmtReceiveBuffer != null) {
				connector.setReceiveBufferSize(mgmtReceiveBuffer);
			}
			if (mgmtSendBuffer != null) {
				connector.setSendBufferSize(mgmtSendBuffer);
			}
			this.clusterManagementConnector = connector;
			this.useClusterMac = false;
			this.protocol = PROTOCOL_MANAGEMENT_UDP;
		}
		LOGGER.info("cluster-node {} ({}): recv. buffer {}, send buffer {}", getNodeID(), protocol, mgmtReceiveBuffer,
				mgmtSendBuffer);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Creates socket and threads for cluster internal communication.
	 */
	@Override
	protected void init(InetSocketAddress bindAddress, DatagramSocket socket, Integer mtu) throws IOException {
		super.init(bindAddress, socket, mtu);
		clusterManagementConnector.start();
		startReceiver();
	}

	@Override
	public void stop() {
		clusterManagementConnector.stop();
		super.stop();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Returns {@link #CLUSTER_MAC_LENGTH}, if {@link #useClusterMac} is
	 * {@code true}, {@code 0}, otherwise.
	 */
	@Override
	protected int getClusterMacLength() {
		return useClusterMac ? CLUSTER_MAC_LENGTH : 0;
	}

	/**
	 * Get protocol for management connector.
	 * 
	 * @return {@link #PROTOCOL_MANAGEMENT_UDP},
	 *         {@link #PROTOCOL_MANAGEMENT_DTLS}, or
	 *         {@link #PROTOCOL_MANAGEMENT_DTLS_MAC}.
	 */
	public String getManagementProtocol() {
		return protocol;
	}

	/**
	 * Get cluster management connector.
	 * 
	 * @return cluster management connector
	 */
	public ExtendedConnector getClusterManagementConnector() {
		return clusterManagementConnector;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Check cluster MAC, if {@link #useClusterMac}.
	 */
	@Override
	protected void processDatagramFromClusterNetwork(Byte type, DatagramPacket clusterPacket) throws IOException {
		if (useClusterMac) {
			DTLSSession session = ((DTLSConnector) clusterManagementConnector)
					.getSessionByAddress((InetSocketAddress) clusterPacket.getSocketAddress());
			Mac mac = session.getThreadLocalClusterReadMac();
			if (mac != null && !validateClusterMac(mac, clusterPacket)) {
				if (LOGGER.isInfoEnabled()) {
					byte[] mac2 = Arrays.copyOf(calculateClusterMac(mac, clusterPacket), CLUSTER_MAC_LENGTH);
					byte[] data = clusterPacket.getData();
					int offset = clusterPacket.getOffset();
					int macOffset = CLUSTER_ADDRESS_OFFSET + (data[offset + CLUSTER_ADDRESS_LENGTH_OFFSET] & 0xff);
					byte[] mac3 = Arrays.copyOfRange(data, offset + macOffset, CLUSTER_MAC_LENGTH);
					LOGGER.info("drop internal record, cluster MAC failure! {} != {}", StringUtil.byteArray2Hex(mac2),
							StringUtil.byteArray2Hex(mac3));
				}
				if (clusterHealth != null) {
					if (type == RECORD_TYPE_INCOMING) {
						clusterHealth.badForwardMessage();
					} else if (type == RECORD_TYPE_OUTGOING) {
						clusterHealth.badBackwardMessage();
					}
				}
				return;
			}
		}
		super.processDatagramFromClusterNetwork(type, clusterPacket);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Fill in cluster MAC, if {@link #useClusterMac}.
	 */
	@Override
	protected void sendDatagramToClusterNetwork(DatagramPacket clusterPacket) throws IOException {
		if (useClusterMac) {
			DTLSSession session = ((DTLSConnector) clusterManagementConnector)
					.getSessionByAddress((InetSocketAddress) clusterPacket.getSocketAddress());
			if (session != null) {
				Mac mac = session.getThreadLocalClusterWriteMac();
				if (mac != null) {
					setClusterMac(mac, clusterPacket);
				}
			}
		}
		super.sendDatagramToClusterNetwork(clusterPacket);
	}

	/**
	 * Validate cluster MAC in packet.
	 * 
	 * @param mac initialized Mac
	 * @param clusterPacket packet
	 * @return {@code true}, if MAC is valid, {@code false}, otherwise.
	 */
	public static boolean validateClusterMac(Mac mac, DatagramPacket clusterPacket) {
		byte[] macBytes = calculateClusterMac(mac, clusterPacket);
		byte[] data = clusterPacket.getData();
		int offset = clusterPacket.getOffset();
		int macOffset = offset + CLUSTER_ADDRESS_OFFSET + (data[offset + CLUSTER_ADDRESS_LENGTH_OFFSET] & 0xff);
		int diffs = 0;
		for (int index = 0; index < CLUSTER_MAC_LENGTH; ++index) {
			if (macBytes[index] != data[macOffset + index]) {
				++diffs;
			}
		}
		return diffs == 0;
	}

	/**
	 * Set cluster MAC in packet.
	 * 
	 * @param mac initialized Mac
	 * @param clusterPacket packet
	 */
	public static void setClusterMac(Mac mac, DatagramPacket clusterPacket) {
		byte[] macBytes = calculateClusterMac(mac, clusterPacket);
		byte[] data = clusterPacket.getData();
		int offset = clusterPacket.getOffset();
		int macOffset = CLUSTER_ADDRESS_OFFSET + (data[offset + CLUSTER_ADDRESS_LENGTH_OFFSET] & 0xff);
		System.arraycopy(macBytes, 0, data, offset + macOffset, CLUSTER_MAC_LENGTH);
	}

	/**
	 * Calculates MAC for forwarded and backwarded messages.
	 * 
	 * Used to protect the original address from modifications.
	 * 
	 * @param mac initialized MAC.
	 * @param clusterPacket forwarded and backwarded messages
	 * @return calculated MAC
	 */
	public static byte[] calculateClusterMac(Mac mac, DatagramPacket clusterPacket) {
		byte[] data = clusterPacket.getData();
		int offset = clusterPacket.getOffset();
		int length = clusterPacket.getLength();
		int macOffset = CLUSTER_ADDRESS_OFFSET + (data[offset + CLUSTER_ADDRESS_LENGTH_OFFSET] & 0xff);
		int originalHeaderOffset = macOffset + CLUSTER_MAC_LENGTH;
		mac.update(data, offset, macOffset);
		if (length < 32 + CLUSTER_MAC_LENGTH) {
			// all bytes, except the cluster MAC
			mac.update(data, offset + macOffset + CLUSTER_MAC_LENGTH, length - originalHeaderOffset);
		} else {
			// 32 first bytes, includes epoch + rec. seqn. of tls_cid record.
			// except the cluster MAC
			mac.update(data, offset + macOffset + CLUSTER_MAC_LENGTH, 32 - originalHeaderOffset);
			// 32 last bytes, includes MAC of tls_cid record
			mac.update(data, offset + length - 32, 32);
		}
		return mac.doFinal();
	}

	@Override
	protected void processManagementDatagramFromClusterNetwork(DatagramPacket clusterPacket) throws IOException {
		LOGGER.trace("cluster-node {} ({}): process datagram from {}, {} bytes", getNodeID(), protocol,
				clusterPacket.getAddress(), clusterPacket.getLength());
		clusterManagementConnector.processDatagram(clusterPacket);
	}

	/**
	 * Add two values.
	 * 
	 * @param value value, if {@code null} or {@code 0}, don't add the second
	 *            value.
	 * @param add additional value.
	 * @return added value
	 */
	private static Integer add(Integer value, int add) {
		if (value != null && value != 0) {
			return value + add;
		} else {
			return value;
		}
	}

	/**
	 * Cluster management connector using UDP.
	 */
	private class ClusterManagementUdpConnector extends UDPConnector implements ExtendedConnector {

		public ClusterManagementUdpConnector(InetSocketAddress bindAddress) {
			super(bindAddress);
		}

		@Override
		public synchronized void start() throws IOException {
			if (isRunning())
				return;
			init(clusterInternalSocket);
		}

		@Override
		public boolean isRunning() {
			return running;
		}

		@Override
		public void processDatagram(DatagramPacket datagram) {
			super.processDatagram(datagram);
			if (clusterHealth != null) {
				clusterHealth.receivingClusterManagementMessage();
			}
		}

		@Override
		public void send(RawData msg) {
			super.send(msg);
			if (clusterHealth != null) {
				clusterHealth.sendingClusterManagementMessage();
			}
		}

	}

	/**
	 * Cluster management connector using DTLS.
	 */
	private class ClusterManagementDtlsConnector extends DTLSConnector implements ExtendedConnector {

		public ClusterManagementDtlsConnector(DtlsConnectorConfig configuration) {
			super(configuration);
		}

		@Override
		protected void onInitializeHandshaker(final Handshaker handshaker) {
			if (useClusterMac) {
				handshaker.setGenerateClusterMacKeys(useClusterMac);
			}
		}

		@Override
		protected void start(InetSocketAddress bindAddress) throws IOException {
			if (isRunning()) {
				return;
			}
			init(bindAddress, clusterInternalSocket, config.getMaxTransmissionUnit());
		}

		@Override
		public void processDatagram(DatagramPacket datagram) {
			super.processDatagram(datagram, null);
			if (clusterHealth != null) {
				clusterHealth.receivingClusterManagementMessage();
			}
		}

		@Override
		public void send(RawData msg) {
			super.send(msg);
			if (clusterHealth != null) {
				clusterHealth.sendingClusterManagementMessage();
			}
		}

	}

}
