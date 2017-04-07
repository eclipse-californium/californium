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
import java.util.Arrays;

import org.eclipse.californium.scandium.util.ByteArrayUtils;


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
	 * 
	 * @param data
	 *            the application data.
	 * @param peerAddress
	 *            the IP address and port the message is to be sent to or has been
	 *            received from
	 */
	public ApplicationMessage(byte[] data, InetSocketAddress peerAddress) {
		super(peerAddress);
		this.data = Arrays.copyOf(data, data.length);
	}

	// Methods ////////////////////////////////////////////////////////

	@Override
	public ContentType getContentType() {
		return ContentType.APPLICATION_DATA;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("\tApplication Data: ").append(ByteArrayUtils.toHexString(data)).append(System.lineSeparator());
		return sb.toString();
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	public byte[] toByteArray() {
		return data;
	}

	public static DTLSMessage fromByteArray(byte[] byteArray, InetSocketAddress peerAddress) {
		return new ApplicationMessage(byteArray, peerAddress);
	}

	// Getters and Setters ////////////////////////////////////////////

	public byte[] getData() {
		return data;
	}
}
