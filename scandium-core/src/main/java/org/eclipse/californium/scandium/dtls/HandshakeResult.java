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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.scandium.auth.AdvancedApplicationLevelInfoSupplier;

/**
 * Handshake result for optionally asynchronous functions.
 * 
 * @since 2.5
 */
public class HandshakeResult {

	/**
	 * Connection id of the connection.
	 */
	private final ConnectionId cid;
	/**
	 * Custom argument.
	 * 
	 * Passed to {@link AdvancedApplicationLevelInfoSupplier} by the
	 * {@link Handshaker}, if a {@link AdvancedApplicationLevelInfoSupplier} is
	 * available.
	 */
	private final Object customArgument;

	/**
	 * Create handshake result with custom argument for
	 * {@link AdvancedApplicationLevelInfoSupplier}.
	 * 
	 * @param cid connection id
	 * @param customArgument custom argument. May be {@code null}. Passed to
	 *            {@link AdvancedApplicationLevelInfoSupplier} by the
	 *            {@link Handshaker}, if a
	 *            {@link AdvancedApplicationLevelInfoSupplier} is available.
	 * @throws NullPointerException if cid  is {@code null}
	 */
	public HandshakeResult(ConnectionId cid, Object customArgument) {
		if (cid == null) {
			throw new NullPointerException("cid must not be null!");
		}
		this.cid = cid;
		this.customArgument = customArgument;
	}

	/**
	 * Get connection id.
	 * 
	 * @return connection id
	 */
	public ConnectionId getConnectionId() {
		return cid;
	}

	/**
	 * Get custom argument.
	 * 
	 * Passed to {@link AdvancedApplicationLevelInfoSupplier} by the
	 * {@link Handshaker}, if a {@link AdvancedApplicationLevelInfoSupplier} is
	 * available.
	 * 
	 * @return custom argument.
	 */
	public Object getCustomArgument() {
		return customArgument;
	}

}
