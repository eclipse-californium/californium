/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others
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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;

/**
 * An abstract base class for DTLS messages providing support for the peer address.
 */
public abstract class AbstractMessage implements DTLSMessage {

	private final InetSocketAddress peerAddress;
	
	protected AbstractMessage(InetSocketAddress peerAddress) {
		if (peerAddress == null) {
			throw new NullPointerException("Peer address must not be null");
		}
		this.peerAddress = peerAddress;
	}

	@Override
	public final InetSocketAddress getPeer() {
		return peerAddress;
	}

}
