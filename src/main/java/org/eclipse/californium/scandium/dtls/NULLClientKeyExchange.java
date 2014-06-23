/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;



/**
 * According to <a href="http://tools.ietf.org/html/rfc5246#section-7.3">RFC
 * 5246</a>, the ClientKeyExchange is never optional. Therefore, to support the
 * NULL key exchange, this empty message is sent.
 */
public class NULLClientKeyExchange extends ClientKeyExchange {
	
	// Methods ////////////////////////////////////////////////////////

	@Override
	public int getMessageLength() {
		return 0;
	}

	// Serialization //////////////////////////////////////////////////

	public static HandshakeMessage fromByteArray(byte[] byteArray) {
		return new NULLClientKeyExchange();
	}

	@Override
	public byte[] fragmentToByteArray() {
		return new byte[] {};
	}

}
