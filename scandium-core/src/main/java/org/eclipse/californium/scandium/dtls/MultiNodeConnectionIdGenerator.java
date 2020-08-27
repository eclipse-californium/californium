/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *     Achim Kraus (Bosch Software Innovations GmbH) - initial API and implementation
 *******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.scandium.dtls.cipher.RandomManager;

/**
 * Connection id generator for multiple nodes systems (cluster).
 * 
 * Encodes node id into first byte of generated connection id. The node id must
 * be unique in the cluster, to ensure, that other nodes of the cluster don't
 * generate the same connection id.
 */
public class MultiNodeConnectionIdGenerator implements NodeConnectionIdGenerator {

	/**
	 * Node id. Must be unique in cluster.
	 */
	private final int nodeId;
	/**
	 * Length of connection id.
	 */
	private final int connectionIdLength;

	/**
	 * Create new connection id generator for multiple nodes.
	 * 
	 * @param nodeId node id of this node. The lowest byte must be unique in the
	 *            cluster, to ensure, that other nodes of the cluster don't
	 *            generate the same connection id.
	 * @param connectionIdLength length of connection id
	 * @throws IllegalArgumentException if length is less than 2 bytes
	 */
	public MultiNodeConnectionIdGenerator(int nodeId, int connectionIdLength) {
		if (connectionIdLength < 2) {
			throw new IllegalArgumentException("cid length must be at least 2 bytes!");
		}
		this.nodeId = nodeId;
		this.connectionIdLength = connectionIdLength;
	}

	@Override
	public boolean useConnectionId() {
		return true;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Places the {@link #nodeId} into the first byte of the connection id.
	 */
	@Override
	public ConnectionId createConnectionId() {
		byte[] cidBytes = new byte[connectionIdLength];
		RandomManager.currentRandom().nextBytes(cidBytes);
		cidBytes[0] = (byte) nodeId;
		return new ConnectionId(cidBytes);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Returns {@code null}, if {@link #nodeId} doesn't match the first byte of
	 * the connection id.
	 */
	@Override
	public ConnectionId read(DatagramReader reader) {
		byte[] cidBytes = reader.readBytes(connectionIdLength);
		if ((cidBytes[0] & 0xff) != nodeId) {
//			return null;
		}
		return new ConnectionId(cidBytes);
	}

	@Override
	public int getNodeId() {
		return nodeId;
	}

	@Override
	public int getNodeId(ConnectionId cid) {
		return cid.getBytes()[0] & 0xff;
	}
}
