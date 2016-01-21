/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for peer address
 *****************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;


/**
 * The ServerHelloDone message is sent by the server to indicate the end of the
 * {@link ServerHello} and associated messages. After sending this message, the
 * server will wait for a client response. See <a
 * href="http://tools.ietf.org/html/rfc5246#section-7.4.5">RFC 5246</a> for
 * details.
 */
public final class ServerHelloDone extends HandshakeMessage {

	public ServerHelloDone(InetSocketAddress peerAddress) {
		super(peerAddress);
	}

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.SERVER_HELLO_DONE;
	}

	@Override
	public int getMessageLength() {
		return 0;
	}

	@Override
	public byte[] fragmentToByteArray() {
		return new byte[] {};
	}

}
