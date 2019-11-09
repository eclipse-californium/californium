/*******************************************************************************
 * Copyright (c) 2015, 2018 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Initial creation
 *    Bosch Software Innovations GmbH - Rename and move to scandium.dtls package
 ******************************************************************************/
package org.eclipse.californium.scandium;

import java.net.InetSocketAddress;

import org.eclipse.californium.scandium.dtls.AlertMessage;

/**
 * A call back to be invoked when an <em>ALERT</em> message is received from a peer.
 * 
 * Applications can register such a call back in order to be able to react to e.g. aborted
 * handshakes etc.
 */
public interface AlertHandler {

	/**
	 * Indicates that an <em>ALERT</em> message has been received from a peer.
	 * 
	 * @param peer The peer that the alert has been received from.
	 * @param alert The alert.
	 */
	void onAlert(InetSocketAddress peer, AlertMessage alert);
}
