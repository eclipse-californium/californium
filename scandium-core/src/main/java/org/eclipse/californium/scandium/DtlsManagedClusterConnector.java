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
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.config.DtlsClusterConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConfig.DtlsRole;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.DTLSContext;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.Handshaker;
import org.eclipse.californium.scandium.dtls.NodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.ConnectionStore;
import org.eclipse.californium.scandium.dtls.SessionAdapter;
import org.eclipse.californium.scandium.dtls.pskstore.SinglePskStore;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * DTLS managed cluster connector.
 * 
 * Enables access to the cluster internal communication to exchange additional
 * management messages and enable encryption for that internal communication.
 * 
 * If encryption is enabled, that header for the forwarded tls-cid records maybe
 * protected by a MAC, see {@link DtlsClusterConnectorConfig}.
 * 
 * @since 2.5
 */
public class DtlsManagedClusterConnector extends DtlsClusterConnector {

	private static final Logger LOGGER = LoggerFactory.getLogger(DtlsManagedClusterConnector.class);

	/**
	 * Protocol identifier for plain UDP management communication.
	 * 
	 * @see #protocol
	 * @see #getManagementProtocol()
	 */
	public static final String PROTOCOL_MANAGEMENT_UDP = "mgmt-udp";
	/**
	 * Protocol identifier for DTLS management communication. The additional
	 * source header for forwarded tls_cid records is not protected by a MAC.
	 * 
	 * @see #protocol
	 * @see #getManagementProtocol()
	 */
	public static final String PROTOCOL_MANAGEMENT_DTLS = "mgmt-dtls";
	/**
	 * Protocol identifier for DTLS management communication. The additional
	 * source header for forwarded tls_cid records is protected by a MAC.
	 * 
	 * @see #protocol
	 * @see #getManagementProtocol()
	 */
	public static final String PROTOCOL_MANAGEMENT_DTLS_MAC = "mgmt-dtls-mac";

	/**
	 * Protocol for cluster management. {@link #PROTOCOL_MANAGEMENT_UDP},
	 * {@link #PROTOCOL_MANAGEMENT_DTLS}, or
	 * {@link #PROTOCOL_MANAGEMENT_DTLS_MAC}.
	 * 
	 * @see #getManagementProtocol()
	 */
	private final String protocol;
	/**
	 * Use MAC to protect source header for forwarded tls_cid records.
	 */
	private final boolean useClusterMac;
	/**
	 * Connector for cluster management. Also used to forward and backward
	 * tls_cid records.
	 */
	private final Connector clusterManagementConnector;

	/**
	 * Create dtls connector with cluster management communication.
	 * 
	 * @param configuration dtls configuration
	 * @param clusterConfiguration cluster internal connector configuration
	 * @throws IllegalArgumentException if the configuration doesn't provide a
	 *             cid generator, or the cid generator only supports, but
	 *             doesn't use cids, or the cid generator is no
	 *             {@link NodeConnectionIdGenerator}.
	 */
	public DtlsManagedClusterConnector(DtlsConnectorConfig configuration,
			DtlsClusterConnectorConfig clusterConfiguration) {
		this(configuration, clusterConfiguration, createConnectionStore(configuration));
	}

	/**
	 * Create dtls connector with dynamic cluster support.
	 * 
	 * @param configuration dtls configuration
	 * @param clusterConfiguration cluster internal connector configuration
	 * @param connectionStore connection store
	 * @throws IllegalArgumentException if the configuration doesn't provide a
	 *             cid generator, or the cid generator only supports, but
	 *             doesn't use cids, or the cid generator is no
	 *             {@link NodeConnectionIdGenerator}.
	 */
	protected DtlsManagedClusterConnector(DtlsConnectorConfig configuration,
			DtlsClusterConnectorConfig clusterConfiguration, ConnectionStore connectionStore) {
		super(configuration, clusterConfiguration, connectionStore, false);
		String identity = clusterConfiguration.getSecureIdentity();
		Integer mgmtReceiveBuffer = addConditionally(config.get(DtlsConfig.DTLS_RECEIVE_BUFFER_SIZE), MAX_DATAGRAM_OFFSET);
		Integer mgmtSendBuffer = addConditionally(config.get(DtlsConfig.DTLS_SEND_BUFFER_SIZE), MAX_DATAGRAM_OFFSET);
		if (identity != null) {
			SecretKey secretkey = clusterConfiguration.getSecretKey();
			String tag = configuration.getLoggingTag();
			if (tag == null || tag.isEmpty()) {
				tag = "dtls-cluster-mgmt";
			} else {
				tag = StringUtil.normalizeLoggingTag(tag);
				tag += "dtls-cluster-mgmt";
			}
			DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder(configuration.getConfiguration())
					.setLoggingTag(tag)
					.set(DtlsConfig.DTLS_RETRANSMISSION_TIMEOUT, 500, TimeUnit.MILLISECONDS)
					.set(DtlsConfig.DTLS_MAX_RETRANSMISSIONS, 3)
					.set(DtlsConfig.DTLS_RETRANSMISSION_BACKOFF, 0)
					.set(DtlsConfig.DTLS_MAX_CONNECTIONS, 1024)
					.set(DtlsConfig.DTLS_RECEIVER_THREAD_COUNT, 0)
					.set(DtlsConfig.DTLS_RECEIVE_BUFFER_SIZE, mgmtReceiveBuffer)
					.set(DtlsConfig.DTLS_SEND_BUFFER_SIZE, mgmtSendBuffer)
					.set(DtlsConfig.DTLS_ROLE, DtlsRole.BOTH)
					.setAddress(clusterConfiguration.getAddress())
					.setPskStore(new SinglePskStore(identity, secretkey))
					.setConnectionListener(new ConnectionListener() {

						@Override
						public void updateExecution(Connection connection) {
						}

						@Override
						public boolean onConnectionUpdatesSequenceNumbers(Connection connection,
								boolean writeSequenceNumber) {
							return false;
						}

						@Override
						public void onConnectionRemoved(Connection connection) {
							LOGGER.info("cluster-node {}: lost connection {}!", getNodeID(),
									connection.getPeerAddress());
						}

						@Override
						public boolean onConnectionMacError(Connection connection) {
							return false;
						}

						@Override
						public void onConnectionEstablished(Connection connection) {
						}

						@Override
						public void beforeExecution(Connection connection) {
						}

						@Override
						public void afterExecution(Connection connection) {
						}
					});
			SecretUtil.destroy(secretkey);
			this.clusterManagementConnector = new ClusterManagementDtlsConnector(builder.build());

			this.useClusterMac = clusterConfiguration.useClusterMac();
			this.protocol = this.useClusterMac ? PROTOCOL_MANAGEMENT_DTLS_MAC : PROTOCOL_MANAGEMENT_DTLS;
		} else {
			Configuration config = new Configuration();
			config.set(UdpConfig.UDP_RECEIVER_THREAD_COUNT, 0);
			config.set(UdpConfig.UDP_SENDER_THREAD_COUNT, 2);
			config.set(UdpConfig.UDP_RECEIVE_BUFFER_SIZE, mgmtReceiveBuffer);
			config.set(UdpConfig.UDP_SEND_BUFFER_SIZE, mgmtSendBuffer);
			ClusterManagementUdpConnector udpConnector = new ClusterManagementUdpConnector(
					clusterConfiguration.getAddress(), config);
			this.clusterManagementConnector = udpConnector;
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
		super.stop();
		clusterManagementConnector.stop();
	}

	@Override
	public void destroy() {
		super.destroy();
		clusterManagementConnector.destroy();
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
	 * @see #protocol
	 */
	public String getManagementProtocol() {
		return protocol;
	}

	/**
	 * Get cluster management connector.
	 * 
	 * @return cluster management connector
	 */
	public Connector getClusterManagementConnector() {
		return clusterManagementConnector;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Check cluster MAC for source header of forwarded or backwarded tls_cid
	 * records, if {@link #useClusterMac} is enabled.
	 */
	@Override
	protected void processDatagramFromClusterNetwork(Byte type, DatagramPacket clusterPacket) throws IOException {
		if (useClusterMac) {
			try {
				DTLSContext context = ((DTLSConnector) clusterManagementConnector)
						.getDtlsContextByAddress((InetSocketAddress) clusterPacket.getSocketAddress());
				if (context == null) {
					throw new IOException("Cluster MAC could not be validated! Missing DTLS context.");
				}
				Mac mac = context.getThreadLocalClusterReadMac();
				if (mac == null) {
					throw new IOException("Cluster MAC could not be validated! Missing keys.");
				}
				if (!validateClusterMac(mac, clusterPacket)) {
					if (LOGGER.isInfoEnabled()) {
						byte[] mac2 = Arrays.copyOf(calculateClusterMac(mac, clusterPacket), CLUSTER_MAC_LENGTH);
						byte[] data = clusterPacket.getData();
						int offset = clusterPacket.getOffset();
						int macOffset = CLUSTER_ADDRESS_OFFSET + (data[offset + CLUSTER_ADDRESS_LENGTH_OFFSET] & 0xff);
						byte[] mac3 = Arrays.copyOfRange(data, offset + macOffset,
								offset + macOffset + CLUSTER_MAC_LENGTH);
						LOGGER.info("cluster-node {} ({}): drop internal record, cluster MAC failure! {} != {}",
								getNodeID(), protocol, StringUtil.byteArray2Hex(mac2), StringUtil.byteArray2Hex(mac3));
					}
					if (clusterHealth != null) {
						if (RECORD_TYPE_INCOMING.equals(type)) {
							clusterHealth.badForwardMessage();
						} else if (RECORD_TYPE_OUTGOING.equals(type)) {
							clusterHealth.badBackwardMessage();
						}
					}
					return;
				}
			} catch (RuntimeException ex) {
				LOGGER.debug("cluster-node {} ({}): receiving failed!", getNodeID(), protocol, ex);
				throw new IOException("Cluster MAC could not be validated!", ex);
			}
		}
		super.processDatagramFromClusterNetwork(type, clusterPacket);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Fill in cluster MAC for source header of forwarded or backwarded tls_cid
	 * records, if {@link #useClusterMac} is enabled.
	 */
	@Override
	protected void sendDatagramToClusterNetwork(DatagramPacket clusterPacket) throws IOException {
		if (useClusterMac) {
			try {
				DTLSContext context = ((DTLSConnector) clusterManagementConnector)
						.getDtlsContextByAddress((InetSocketAddress) clusterPacket.getSocketAddress());
				if (context == null) {
					throw new IOException("Cluster MAC could not be generated! Missing dtls context.");
				}
				Mac mac = context.getThreadLocalClusterWriteMac();
				if (mac == null) {
					throw new IOException("Cluster MAC could not be generated! Missing keys.");
				}
				setClusterMac(mac, clusterPacket);
			} catch (RuntimeException ex) {
				LOGGER.debug("cluster-node {} ({}): sending failed!", getNodeID(), protocol, ex);
				throw new IOException("Cluster MAC could not be generated!", ex);
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
	 * @throws IllegalArgumentException if message is too small
	 */
	public static byte[] calculateClusterMac(Mac mac, DatagramPacket clusterPacket) {
		byte[] data = clusterPacket.getData();
		int offset = clusterPacket.getOffset();
		int length = clusterPacket.getLength();
		int macOffset = CLUSTER_ADDRESS_OFFSET + (data[offset + CLUSTER_ADDRESS_LENGTH_OFFSET] & 0xff);
		int headerOffset = macOffset + CLUSTER_MAC_LENGTH;
		if (headerOffset < length) {
			mac.update(data, offset, macOffset);
			length -= headerOffset;
			if (length > 0) {
				offset += headerOffset;
				if (length > (64 - macOffset)) {
					mac.update(data, offset, 32);
					offset += (length - 32);
					length = 32;
				}
				mac.update(data, offset, length);
			}
			return mac.doFinal();
		} else {
			throw new IllegalArgumentException(length + " bytes is too small for cluster MAC message!");
		}
	}

	@Override
	protected void processManagementDatagramFromClusterNetwork(DatagramPacket clusterPacket) throws IOException {
		LOGGER.trace("cluster-node {} ({}): process datagram from {}, {} bytes", getNodeID(), protocol,
				clusterPacket.getAddress(), clusterPacket.getLength());
		clusterManagementConnector.processDatagram(clusterPacket);
	}

	/**
	 * Add two values conditionally.
	 * 
	 * @param value value, if {@code null} or {@code 0}, don't add the second
	 *            value.
	 * @param add additional value.
	 * @return added value
	 */
	private static Integer addConditionally(Integer value, int add) {
		if (value != null && value != 0) {
			return value + add;
		} else {
			return value;
		}
	}

	/**
	 * Cluster management connector using UDP.
	 */
	private class ClusterManagementUdpConnector extends UDPConnector {

		public ClusterManagementUdpConnector(InetSocketAddress bindAddress, Configuration configuration) {
			super(bindAddress, configuration);
		}

		@Override
		public synchronized void start() throws IOException {
			if (isRunning())
				return;
			init(clusterInternalSocket);
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
	private class ClusterManagementDtlsConnector extends DTLSConnector {

		public ClusterManagementDtlsConnector(DtlsConnectorConfig configuration) {
			super(configuration);
			addSessionListener(new SessionAdapter() {

				@Override
				public void handshakeStarted(Handshaker handshaker) throws HandshakeException {
					if (useClusterMac) {
						handshaker.setGenerateClusterMacKeys(useClusterMac);
					}
				}
			});
		}

		@Override
		protected void start(InetSocketAddress bindAddress) throws IOException {
			if (isRunning()) {
				return;
			}
			super.init(bindAddress, clusterInternalSocket, null);
		}

		@Override
		public void setRawDataReceiver(final RawDataChannel messageHandler) {
			super.setRawDataReceiver(new RawDataChannel() {

				@Override
				public void receiveData(RawData raw) {
					messageHandler.receiveData(raw);
					if (clusterHealth != null) {
						clusterHealth.receivingClusterManagementMessage();
					}
				}
			});
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
