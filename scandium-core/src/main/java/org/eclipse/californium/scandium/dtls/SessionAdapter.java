/*******************************************************************************
 * Copyright (c) 2015 Sierra Wireless
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
 *    Simon Bernard (Sierra Wireless) - Initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;

/**
 * An abstract adapter class for listening handshake. The methods in this
 * class are empty. This class exists as convenience for creating SessionListener objects.
 */
public class SessionAdapter implements SessionListener{

	@Override
	public void handshakeStarted(Handshaker handshaker) throws HandshakeException {
	}

	@Override
	public void sessionEstablished(Handshaker handshaker, DTLSSession establishedSession) throws HandshakeException {
	}

	@Override
	public void handshakeCompleted(InetSocketAddress peer) {
	}
}
