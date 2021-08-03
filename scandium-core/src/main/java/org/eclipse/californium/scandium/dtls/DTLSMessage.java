/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for message type
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add accessor for peer address
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.elements.util.NoPublicAPI;

/**
 * The message contract as defined by the DTLS specification.
 */
@NoPublicAPI
public interface DTLSMessage {

	/**
	 * Gets the number of bytes representing this message as defined by
	 * <a href="https://tools.ietf.org/html/rfc5246#appendix-A" target=
	 * "_blank">TLS 1.2, Appendix A</a>.
	 * 
	 * @return number of bytes
	 * @since 2.4
	 */
	int size();

	/**
	 * Gets the byte array representation of this message as defined by
	 * <a href="https://tools.ietf.org/html/rfc5246#appendix-A" target=
	 * "_blank">TLS 1.2, Appendix A</a>.
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
	 * Gets the textual presentation of this message.
	 * 
	 * @param indent line indentation
	 * @return textual presentation
	 * @since 3.0
	 */
	String toString(int indent);
}
