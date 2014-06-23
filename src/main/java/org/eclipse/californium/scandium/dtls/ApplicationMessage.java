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

import org.eclipse.californium.scandium.util.ByteArrayUtils;


/**
 * Application data messages are carried by the record layer and are fragmented,
 * compressed, and encrypted based on the current connection state. The messages
 * are treated as transparent data to the record layer.
 */
public class ApplicationMessage implements DTLSMessage {

	// Members ////////////////////////////////////////////////////////

	/** The (to the record layer) transparent data. */
	private byte[] data;

	// Constructor ////////////////////////////////////////////////////

	/**
	 * 
	 * @param data
	 *            the application data.
	 */
	public ApplicationMessage(byte[] data) {
		this.data = data;
	}
	
	// Methods ////////////////////////////////////////////////////////

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();

		sb.append("\tApplication Data: " + ByteArrayUtils.toHexString(data) + "\n");

		return sb.toString();
	}
	
	// Serialization //////////////////////////////////////////////////

	// @Override
	public byte[] toByteArray() {
		return data;
	}

	public static DTLSMessage fromByteArray(byte[] byteArray) {
		return new ApplicationMessage(byteArray);
	}

	// Getters and Setters ////////////////////////////////////////////

	public byte[] getData() {
		return data;
	}

	public void setData(byte[] data) {
		this.data = data;
	}

}
