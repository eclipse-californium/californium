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
 *    Bosch Software Innovations GmbH - Initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium;

import org.eclipse.californium.scandium.dtls.Connection;

/**
 * Listener for Connections life cycle.
 */
public interface ConnectionListener {

	/**
	 * Callback, when DTLS session is established by a successful handshake.
	 * 
	 * @param connection connection, which's session gets established
	 */
	void onConnectionEstablished(Connection connection);

	/**
	 * Callback, when connection gets removed from the connection store.
	 * 
	 * @param connection connection, which gets removed from the connection
	 *            store
	 */
	void onConnectionRemoved(Connection connection);
}
