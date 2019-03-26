/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove unused sendRecord
 *    Achim Kraus (Bosch Software Innovations GmbH) - redesign RecordLayer
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.io.IOException;

/**
 * An abstraction of the DTLS record layer's capabilities for sending records to peers.
 */
public interface RecordLayer {

	/**
	 * Sends a set of records containing DTLS handshake messages to a peer.
	 * <p>
	 * The records are sent <em>as a whole</em>. In particular this means that all
	 * records will be re-transmitted in case of a missing acknowledgement from the peer.
	 * </p>
	 * 
	 * @param flight the records to send. The properties of the flight are used to control the
	 *                  timespan to wait between re-transmissions. 
	 * @param connection to send the flight
	 * @throws IOException if an io error occurs
	 */
	void sendFlight(DTLSFlight flight, Connection connection) throws IOException;
}
