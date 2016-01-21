/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium;

import java.net.InetSocketAddress;

import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;

/**
 * A call back to be invoked when an <em>ALERT</em> message is received from a peer.
 * 
 * Applications can register such a call back in order to be able to react to e.g. aborted
 * handshakes etc.
 */
public interface ErrorHandler {

	/**
	 * Indicates that an <em>ALERT</em> message has been received from a peer.
	 * 
	 * @param peerAddress the IP address and port of the peer the alert has been received from 
	 * @param level the severity level of the alert
	 * @param description the reason of the alert
	 */
	void onError(InetSocketAddress peerAddress, AlertLevel level, AlertDescription description);
}
