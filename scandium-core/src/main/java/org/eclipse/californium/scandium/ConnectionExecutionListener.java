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

import org.eclipse.californium.elements.util.PublicAPIExtension;
import org.eclipse.californium.scandium.dtls.Connection;

/**
 * Listener for Connections execution cycle.
 * 
 * Please note: Though Scandium isn't designed to have a separated public API,
 * using the {@link Connection} and the reachable data comes with the risk, that
 * your custom implementation will face changes.
 * 
 * @since 2.4
 */
@PublicAPIExtension(type = ConnectionListener.class)
public interface ConnectionExecutionListener {

	/**
	 * Callback, when a executor begin processing a connection.
	 * 
	 * @param connection connection
	 */
	void beforeExecution(Connection connection);

	/**
	 * Callback, when a connection changed its state.
	 * 
	 * @param connection connection
	 */
	void updateExecution(Connection connection);

	/**
	 * Callback, after a executor processed a connection.
	 * 
	 * @param connection connection
	 */
	void afterExecution(Connection connection);
}
