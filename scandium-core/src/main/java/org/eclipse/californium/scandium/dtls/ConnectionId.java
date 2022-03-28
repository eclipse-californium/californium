/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial API and implementation
 *******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.elements.util.Bytes;

/**
 * Implementation of DTLS connection id.
 * 
 * @see <a href= "https://www.rfc-editor.org/rfc/rfc9146.html" target
 *      ="_blank">RFC 9146, Connection Identifier for DTLS 1.2</a>
 */
public class ConnectionId extends Bytes {

	public static final ConnectionId EMPTY = new ConnectionId(Bytes.EMPTY);

	/**
	 * Create connection id from bytes.
	 * 
	 * @param connectionId connectionId bytes
	 * @throws NullPointerException if connectionId is {@code null}
	 * @throws IllegalArgumentException if connectionId length is larger than
	 *             255
	 */
	public ConnectionId(byte[] connectionId) {
		super(connectionId);
	}

	@Override
	public String toString() {
		return new StringBuilder("CID=").append(getAsString()).toString();
	}

	/**
	 * Check, if provided generator supports cid.
	 * 
	 * Any none {@code null} generator supports cid. This check is therefore
	 * equivalent to {@code generator != null}.
	 * 
	 * @param generator cid generator.
	 * @return {@code true}, if the provided generator supports cid,
	 *         {@code false}, if not.
	 * @since 3.0
	 */
	public static boolean supportsConnectionId(ConnectionIdGenerator generator) {
		return generator != null;
	}

	/**
	 * Check, if provided generator use cid.
	 * 
	 * @param generator cid generator.
	 * @return {@code true}, if the provided generator use cid, {@code false},
	 *         if not.
	 * @see ConnectionIdGenerator#useConnectionId()
	 * @since 3.0
	 */
	public static boolean useConnectionId(ConnectionIdGenerator generator) {
		return generator != null && generator.useConnectionId();
	}

	/**
	 * Check, if provided cid is used for records.
	 * 
	 * Only none {@link ConnectionId#isEmpty()} cids are used for records.
	 * 
	 * @param cid cid
	 * @return {@code true}, if the provided cid is used for records,
	 *         {@code false}, if not.
	 * @since 3.0
	 */
	public static boolean useConnectionId(ConnectionId cid) {
		return cid != null && !cid.isEmpty();
	}
}
