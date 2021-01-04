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
import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

import org.eclipse.californium.elements.util.WipAPI;

/**
 * Interface for connector supporting persistent connections.
 * 
 * @since 3.0
 */
public interface PersistentConnector {

	/**
	 * Save connections.
	 * 
	 * Connector must be stopped before saving connections. The connections are
	 * removed after saving.
	 * 
	 * Note: this "Work In Progress"; the encryption, the states and the format may change!
	 * 
	 * @param out output stream to save connections
	 * @param password password for encryption
	 * @param maxAgeInSeconds maximum age in seconds
	 * @return number of save connections, {@code -1}, if not supported.
	 * @throws IOException if an io-error occurred
	 * @throws GeneralSecurityException if an crypto error occurred
	 * @throws IllegalStateException if connector is running
	 */
	@WipAPI
	int saveConnections(OutputStream out, SecretKey password, long maxAgeInSeconds) throws IOException, GeneralSecurityException;

	/**
	 * Load connections.
	 * 
	 * Note: this "Work In Progress"; the encryption, the states and the format
	 * may change!
	 * 
	 * @param in input stream to load connections
	 * @param password password for encryption
	 * @return number of save connections, {@code -1}, if not supported.
	 * @throws IOException if an io-error occurred. Indicates, that further
	 *             loading should be aborted.
	 * @throws IllegalStateException if an reading error occurred. Continue to
	 *             load other connection-stores may work, that may be not
	 *             affected by this error.
	 * @throws GeneralSecurityException if an crypto error occurred. Continue to
	 *             load other connection-stores may work, that may be not
	 *             affected by this error.
	 */
	@WipAPI
	int loadConnections(InputStream in, SecretKey password) throws IOException, GeneralSecurityException;

}
