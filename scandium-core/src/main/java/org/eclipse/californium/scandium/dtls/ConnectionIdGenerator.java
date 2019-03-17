/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 *
 * Contributors:
 *     Achim Kraus (Bosch Software Innovations GmbH) - initial API and implementation
 *******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.elements.util.DatagramReader;

/**
 * Connection id generator.
 * 
 * Responsible for generating ID which identifies scandium connections in store.
 * 
 * By default, DTLS defined that IP address and port of the peer are used to
 * identify the DTLS Connection. The DTLS connection ID draft defines a way to
 * identify connection using Connection ID and so supports environments where IP
 * address/port changes.
 * {@link https://tools.ietf.org/html/draft-ietf-tls-dtls-connection-id-03}
 * 
 * This class can be used to activate support of this draft and configure if the
 * current peer want foreign peers use connection ID when sending message or
 * signaling, that this peer is willing to accept a connection ID from the other
 * peer.
 */
public interface ConnectionIdGenerator {

	/**
	 * Indicates, if connection ids are used or just supported.
	 * 
	 * @return {@code true}, if a connection is used, {@code false}, if only a
	 *         connection id from the other peer is supported.
	 */
	boolean useConnectionId();

	/**
	 * Creates a connection id.
	 * 
	 * The caller must take care to use only unique connection ids. In cases
	 * where the generated connection id is already in use, it's intended to
	 * create a next connection id calling this method again.
	 * 
	 * @return created connection id or {@code null}, if this generator only
	 *         supports connection ids from the other peer.
	 */
	ConnectionId createConnectionId();

	/**
	 * Read connection id from record header bytes.
	 * 
	 * @param reader reader with header bytes at the position of the connection
	 *            id.
	 * @return read connection id or {@code null}, if this generator only
	 *         supports connection ids from the other peer.
	 */
	ConnectionId read(DatagramReader reader);
}
