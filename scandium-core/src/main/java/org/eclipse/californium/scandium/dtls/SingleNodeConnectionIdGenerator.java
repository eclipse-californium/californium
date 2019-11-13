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
 * Connection id generator for single node systems (no cluster).
 */
public class SingleNodeConnectionIdGenerator implements ConnectionIdGenerator {

	/**
	 * Length of connection id.
	 */
	private final int connectionIdLength;

	/**
	 * Create new connection id generator.
	 * 
	 * @param connectionIdLength length of connection id. {@code 0} to support
	 *            connection id of the other peer, but not using it for this
	 *            peer.
	 * @throws IllegalArgumentException if length is less than 0 bytes
	 */
	public SingleNodeConnectionIdGenerator(int connectionIdLength) {
		if (connectionIdLength < 0) {
			throw new IllegalArgumentException("cid length must not be less than 0 bytes!");
		}
		this.connectionIdLength = connectionIdLength;
	}

	@Override
	public boolean useConnectionId() {
		return connectionIdLength > 0;
	}

	@Override
	public ConnectionId createConnectionId() {
		if (useConnectionId()) {
			byte[] cidBytes = new byte[connectionIdLength];
			RandomManager.currentRandom().nextBytes(cidBytes);
			return new ConnectionId(cidBytes);
		} else {
			return null;
		}
	}

	@Override
	public ConnectionId read(DatagramReader reader) {
		if (useConnectionId()) {
			return new ConnectionId(reader.readBytes(connectionIdLength));
		} else {
			return null;
		}
	}
}
