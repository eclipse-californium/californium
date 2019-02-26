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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

/**
 * Pair of connections.
 * 
 * Helper to prevent duplicated calls to
 * {@link ResumptionSupportingConnectionStore#find(SessionId)}.
 * 
 * <ul>
 * <li>connection associated with the peer's address or cid</li>
 * <li>connection associated with the session id</li>
 * </ul>
 */
public class AvailableConnections {

	/**
	 * Connection associated with the peer's address. May be {@code null}, if no
	 * connection is associated with the peer's address.
	 */
	private Connection byAddress;
	/**
	 * Connection associated with the session id. May be {@code null}, if no
	 * connection is associated with the session id.
	 */
	private Connection bySessionId;
	/**
	 * Indicates, that {@link #setConnectionBySessionId(Connection)} has been
	 * called.
	 */
	private boolean setBySessionId;

	/**
	 * Creates a new connection pair.
	 * 
	 * @param byAddress connection associated with the peer's address. May be
	 *            {@code null}, if no connection is associated with the peer's
	 *            address.
	 */
	public AvailableConnections(Connection byAddress) {
		this.byAddress = byAddress;
	}

	/**
	 * Set connection associated with the peer's address.
	 * 
	 * @param connection connection associated with the peer's address. May be
	 *            {@code null}, if no connection is associated with the peer's
	 *            address.
	 */
	public void setConnectionByAddress(Connection connection) {
		byAddress = connection;
	}

	/**
	 * Get connection associated with the peer's address.
	 * 
	 * @return connection associated with the peer's address. May be
	 *         {@code null}, if no connection is associated with the peer's
	 *         address.
	 */
	public Connection getConnectionByAddress() {
		return byAddress;
	}

	/**
	 * Set connection associated with the session id.
	 * 
	 * @param connection connection associated with the session id. May be
	 *            {@code null}, if no connection is associated with the session
	 *            id.
	 */
	public void setConnectionBySessionId(Connection connection) {
		bySessionId = connection;
		setBySessionId = true;
	}

	/**
	 * Get connection associated with the session id.
	 * 
	 * @return connection associated with the session id. May be {@code null},
	 *         if no connection is associated with the session id.
	 */
	public Connection getConnectionBySessionId() {
		return bySessionId;
	}

	/**
	 * Check, if it's known to have a connection for the provided session id.
	 * 
	 * @return {@code true}, if {@link #setConnectionBySessionId(Connection)}
	 *         was called. Used to recognize already unsuccessful tries to find
	 *         a connection associated with the session id.
	 */
	public boolean isConnectionBySessionIdKnown() {
		return setBySessionId;
	}
}
