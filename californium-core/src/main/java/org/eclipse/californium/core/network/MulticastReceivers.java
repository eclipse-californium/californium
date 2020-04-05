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
package org.eclipse.californium.core.network;

import java.io.IOException;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.UdpMulticastConnector;
import org.eclipse.californium.elements.util.PublicAPIExtension;

/**
 * Extend {@link Endpoint} using multicast receivers.
 * 
 * Responses for multicast requests maybe sent using a different endpoint also
 * on server side.
 * 
 * @since 2.3
 */
@PublicAPIExtension(type = Endpoint.class)
public interface MulticastReceivers {

	/**
	 * Add connector as multicast receiver.
	 * 
	 * A multicast receiver must return a multicast address on
	 * {@link Connector#getAddress()}. A {@link UdpMulticastConnector} maybe
	 * used as multicast receiver, if it joins only one multicast group.
	 * 
	 * @param receiver multicast receiver to add
	 * @throws NullPointerException if receiver is {@code null}
	 * @throws IllegalArgumentException if receiver doesn't return a multicast
	 *             address on {@link Connector#getAddress()}
	 */
	void addMulticastReceiver(Connector receiver);

	/**
	 * Remove connector from multicast receivers.
	 * 
	 * @param receiver multicast receiver to remove
	 */
	void removeMulticastReceiver(Connector receiver);

	/**
	 * Start multicast receivers to ensure, that all unicast connectors are
	 * started afterwards.
	 * 
	 * @throws IOException if an i/o error occurred.
	 */
	void startMulticastReceivers() throws IOException;
}
