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
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove cloning of byte array
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;

import org.eclipse.californium.elements.util.StringUtil;

/**
 * Application data messages are carried by the record layer and are fragmented,
 * compressed, and encrypted based on the current connection state. The messages
 * are treated as transparent data to the record layer.
 */
public final class ApplicationMessage extends AbstractMessage {

	// Members ////////////////////////////////////////////////////////

	/** The (to the record layer) transparent data. */
	private final byte[] data;

	// Constructor ////////////////////////////////////////////////////

	/**
	 * Creates a new <em>APPLICATION_DATA</em> message containing specific data.
	 * <p>
	 * The given byte array will not be cloned/copied, i.e. any changes made to
	 * the byte array after this method has been invoked will be exposed in the
	 * message's payload.
	 * 
	 * @param data byte array with the application data.
	 * @param peerAddress the IP address and port the message is to be sent to
	 *            or has been received from
	 */
	public ApplicationMessage(byte[] data, InetSocketAddress peerAddress) {
		super(peerAddress);
		this.data = data;
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public ContentType getContentType() {
		return ContentType.APPLICATION_DATA;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("\tApplication Data: ").append(StringUtil.byteArray2Hex(data)).append(StringUtil.lineSeparator());
		return sb.toString();
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	public byte[] toByteArray() {
		return data;
	}

	/**
	 * Create message from byte array.
	 * <p>
	 * The given byte array will not be cloned/copied, i.e. any changes made to
	 * the byte array after this method has been invoked will be exposed in the
	 * message's payload.
	 * 
	 * @param byteArray byte array with the application data.
	 * @param peerAddress peer's address
	 * @return created message
	 * @see #ApplicationMessage(byte[], InetSocketAddress)
	 */
	public static DTLSMessage fromByteArray(byte[] byteArray, InetSocketAddress peerAddress) {
		return new ApplicationMessage(byteArray, peerAddress);
	}

	// Getters and Setters ////////////////////////////////////////////

	public byte[] getData() {
		return data;
	}
}
