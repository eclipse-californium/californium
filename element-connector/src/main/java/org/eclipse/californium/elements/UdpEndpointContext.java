/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.net.InetSocketAddress;

/**
 * A endpoint context for plain UDP.
 */
public class UdpEndpointContext extends MapBasedEndpointContext {

	public static final String KEY_PLAIN = "PLAIN";

	/**
	 * Creates a new context for a socket address.
	 * 
	 * @param peerAddress The peer's address.
	 */
	public UdpEndpointContext(InetSocketAddress peerAddress) {
		super(peerAddress, null, KEY_PLAIN, "");
	}

	@Override
	public String toString() {
		return String.format("UDP(%s)", getPeerAddressAsString());
	}
}
