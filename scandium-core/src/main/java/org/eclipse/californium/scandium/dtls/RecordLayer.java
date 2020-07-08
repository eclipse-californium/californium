/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove unused sendRecord
 *    Achim Kraus (Bosch Software Innovations GmbH) - redesign RecordLayer
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.io.IOException;
import java.net.DatagramPacket;
import java.util.List;

import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.NoPublicAPI;

/**
 * An abstraction of the DTLS record layer's capabilities for sending records to
 * peers. MTU values according
 * <a href="https://en.wikipedia.org/wiki/Maximum_transmission_unit">MTU - Wikipedia</a>.
 */
@NoPublicAPI
public interface RecordLayer {

	/**
	 * Maximum MTU.
	 * 
	 * @since 2.4
	 */
	public final int MAX_MTU = NetworkInterfacesUtil.MAX_MTU;
	/**
	 * Default IPv6 MTU.
	 * 
	 * @since 2.4
	 */
	public final int DEFAULT_IPV6_MTU = NetworkInterfacesUtil.DEFAULT_IPV6_MTU;
	/**
	 * Default IPv4 MTU.
	 * 
	 * @since 2.4
	 */
	public final int DEFAULT_IPV4_MTU = NetworkInterfacesUtil.DEFAULT_IPV4_MTU;
	/**
	 * Default Ethernet MTU.
	 * 
	 * @since 2.4
	 */
	public final int DEFAULT_ETH_MTU = 1500;
	/**
	 * IPv4 header size.
	 * 
	 * @since 2.4
	 */
	public final int IPV4_HEADER_LENGTH = + 8 // bytes UDP headers
			+ 20 // bytes IP headers
			+ 36; // bytes optional IP options

	/**
	 * IPv6 header size.
	 * 
	 * @since 2.4
	 */
	public final int IPV6_HEADER_LENGTH = 128; // 1280 - 1152 bytes, assumption
												// of RFC 7252, Section 4.6.,
												// Message Size

	/**
	 * Returns execution state of record layer.
	 * 
	 * @return {@code true} if execution is running, {@code false}, otherwise.
	 * 
	 * @since 2.4
	 */
	boolean isRunning();

	/**
	 * Gets the maximum size of a UDP datagram that can be sent to this
	 * session's peer without IP fragmentation.
	 * 
	 * @param ipv6 {@code true}, IPv6 destination, {@code false}, IPv4
	 *            destination
	 * @return the maximum datagram size in bytes
	 * @since 2.4
	 */
	int getMaxDatagramSize(boolean ipv6);

	/**
	 * Sends a set of UDP datagrams containing DTLS records with handshake
	 * messages to a peer.
	 * <p>
	 * The set is sent <em>as a whole</em>. In particular this means that all
	 * datagrams will be re-transmitted in case of a missing acknowledgement
	 * from the peer.
	 * </p>
	 * 
	 * @param datagrams list of UDP datagrams containing DTLS records to send.
	 * @throws IOException if an io error occurs
	 * @since 2.4
	 */
	void sendFlight(List<DatagramPacket> datagrams) throws IOException;

	/**
	 * Process received record.
	 * 
	 * @param record received record.
	 * @param connection connection to process record.
	 */
	void processRecord(Record record, Connection connection);

	/**
	 * Report dropped record
	 * 
	 * @param record dropped record
	 * @since 2.4
	 */
	void dropReceivedRecord(Record record);
}
