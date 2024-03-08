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
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove cloning of byte array
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import org.eclipse.californium.elements.util.StringUtil;

/**
 * Application data messages are carried by the record layer and are fragmented,
 * compressed, and encrypted based on the current connection state.
 * 
 * The messages are treated as transparent data to the record layer.
 */
public final class ApplicationMessage implements DTLSMessage {

	/** The (to the record layer) transparent data. */
	private final byte[] data;

	/**
	 * Creates a new <em>APPLICATION_DATA</em> message containing specific data.
	 * <p>
	 * The given byte array will not be cloned/copied, i.e. any changes made to
	 * the byte array after this method has been invoked will be exposed in the
	 * message's payload.
	 * 
	 * @param data byte array with the application data.
	 * @throws NullPointerException if data is {@code null}
	 */
	public ApplicationMessage(byte[] data) {
		if (data == null) {
			throw new NullPointerException("data must not be null!");
		}
		this.data = data;
	}

	@Override
	public ContentType getContentType() {
		return ContentType.APPLICATION_DATA;
	}

	@Override
	public String toString(int indent) {
		StringBuilder sb = new StringBuilder();
		if (indent > 0) {
			sb.append(StringUtil.indentation(indent));
		}
		sb.append("Application Data: ").append(StringUtil.byteArray2HexString(data, StringUtil.NO_SEPARATOR, 32));
		if (indent > 0) {
			sb.append(StringUtil.lineSeparator());
		}
		return sb.toString();
	}

	@Override
	public String toString() {
		return toString(0);
	}

	@Override
	public int size() {
		return data.length;
	}

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
	 * @return created message
	 * @see #ApplicationMessage(byte[])
	 */
	public static DTLSMessage fromByteArray(byte[] byteArray) {
		return new ApplicationMessage(byteArray);
	}

	public byte[] getData() {
		return data;
	}
}
