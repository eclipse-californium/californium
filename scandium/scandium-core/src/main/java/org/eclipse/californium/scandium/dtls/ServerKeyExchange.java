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
 * This message will be sent immediately after the server
 * {@link CertificateMessage} (or the {@link ServerHello} message, if this is an
 * anonymous negotiation). See <a
 * href="http://tools.ietf.org/html/rfc5246#section-7.4.3">RFC 5246</a> for
 * details.
 */
public abstract class ServerKeyExchange extends HandshakeMessage {

	protected ServerKeyExchange(InetSocketAddress peerAddress) {
		super(peerAddress);
	}

	@Override
	public final HandshakeType getMessageType() {
		return HandshakeType.SERVER_KEY_EXCHANGE;
	}
}
