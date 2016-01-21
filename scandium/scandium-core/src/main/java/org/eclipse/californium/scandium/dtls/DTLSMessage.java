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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for message type
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for peer address
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;


/**
 * The message contract as defined by the DTLS specification.
 */
public interface DTLSMessage {

	/**
	 * Gets the byte array representation of this message as defined
	 * by <a href="http://tools.ietf.org/html/rfc5246#appendix-A">TLS 1.2, Appendix A</a>.
	 * 
	 * @return the byte array
	 */
	byte[] toByteArray();
	
	/**
	 * Gets the message's content type.
	 * 
	 * @return the type
	 */
	ContentType getContentType();
	
	/**
	 * Gets the IP address and port of the peer this message
	 * has been received from or is to be sent to.
	 * 
	 * @return the address
	 */
	InetSocketAddress getPeer();
}
