/*******************************************************************************
 * Copyright (c) 2020 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.eclipse.californium.elements.util.WipAPI;

/**
 * Interface for connector supporting persistent connections.
 * 
 * Note: this is "Work In Progress"; the stream will contain not encrypted
 * critical credentials. It is required to protect this data before exporting
 * it. The encoding of the content may also change in the future.
 * 
 * @since 3.0
 */
@WipAPI
public interface PersistentConnector {

	/**
	 * Save connections.
	 * 
	 * Connector must be stopped before saving connections. The connections are
	 * removed after saving.
	 * 
	 * Note: this is "Work In Progress"; the stream will contain not encrypted
	 * critical credentials. It is required to protect this data before
	 * exporting it. The encoding of the content may also change in the future.
	 * 
	 * @param out output stream to save connections
	 * @param maxQuietPeriodInSeconds maximum quiet period of the connections in
	 *            seconds. Connections without traffic for that time are skipped
	 *            during serialization.
	 * @return number of save connections.
	 * @throws IOException if an io-error occurred
	 * @throws IllegalStateException if connector is running
	 */
	@WipAPI
	int saveConnections(OutputStream out, long maxQuietPeriodInSeconds) throws IOException;

	/**
	 * Load connections.
	 * 
	 * Note: this is "Work In Progress"; the stream will contain not encrypted
	 * critical credentials. The encoding of the content may also change in the
	 * future.
	 * 
	 * @param in input stream to load connections
	 * @param delta adjust-delta for nano-uptime. In nanoseconds. The stream
	 *            contains timestamps based on nano-uptime. On loading, this
	 *            requires to adjust these timestamps according the current nano
	 *            uptime and the passed real time.
	 * @return number of loaded connections.
	 * @throws IOException if an io-error occurred. Indicates, that further
	 *             loading should be aborted.
	 * @throws IllegalArgumentException if an reading error occurred. Continue
	 *             to load other connection-stores may work, that may be not
	 *             affected by this error.
	 */
	@WipAPI
	int loadConnections(InputStream in, long delta) throws IOException;

}
