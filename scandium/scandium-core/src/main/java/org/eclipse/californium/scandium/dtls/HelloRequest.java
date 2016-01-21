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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;


/**
 * HelloRequest is a simple notification that the client should begin the
 * negotiation process anew. In response, the client should send a
 * {@link ClientHello} message when convenient. This message is not intended to
 * establish which side is the client or server but merely to initiate a new
 * negotiation. See <a
 * href="http://tools.ietf.org/html/rfc5246#section-7.4.1.1">RFC 5246</a> for
 * details.
 */
public final class HelloRequest extends HandshakeMessage {

	public HelloRequest(InetSocketAddress peerAddress) {
		super(peerAddress);
	}

	@Override
	public HandshakeType getMessageType() {
		return HandshakeType.HELLO_REQUEST;
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
