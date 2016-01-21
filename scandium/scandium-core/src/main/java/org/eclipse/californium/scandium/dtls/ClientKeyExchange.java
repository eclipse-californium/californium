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
 * This message is always sent by the client. It MUST immediately follow the
 * client certificate message, if it is sent. Otherwise, it MUST be the first
 * message sent by the client after it receives the {@link ServerHelloDone}
 * message. This is a super class for the different key exchange methods (i.e.
 * Diffie-Hellman, RSA, Elliptic Curve Diffie-Hellman). See <a
 * href="http://tools.ietf.org/html/rfc5246#section-7.4.7">RFC 5246</a>.
 */
public abstract class ClientKeyExchange extends HandshakeMessage {

	protected ClientKeyExchange(InetSocketAddress peerAddress) {
		super(peerAddress);
	}
	
	@Override
	public final HandshakeType getMessageType() {
		return HandshakeType.CLIENT_KEY_EXCHANGE;
	}

}
