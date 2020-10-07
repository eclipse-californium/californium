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
package org.eclipse.californium.elements;

import java.net.DatagramPacket;

import org.eclipse.californium.elements.util.PublicAPIExtension;

/**
 * Extension interface for {@link Connector}.
 * 
 * @since 2.5
 */
@PublicAPIExtension(type = Connector.class)
public interface ExtendedConnector extends Connector {

	/**
	 * Connector is running.
	 * 
	 * @return {@code true}, if running, {@code false}, otherwise.
	 */
	boolean isRunning();

	/**
	 * Process datagram.
	 * 
	 * @param datagram datagram to process
	 */
	void processDatagram(DatagramPacket datagram);

}
