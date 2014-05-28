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
 *    Martin Lanter - architect and initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.net.InetAddress;
import java.net.InetSocketAddress;

/**
 * Serves as container for the primitive bytes we retrieve or send over a
 * connector. The RawData consists of the serialized message and the source or
 * destination address and port.
 */
public class RawData {

	/** The serialized message. */
	public final byte[] bytes;
	
	/** The address. */
	private InetAddress address;
	
	/** The port. */
	private int port;
	
	/** Indicates if this message was a multicast message */
	private boolean multicast;
	
	/**
	 * Instantiates a new raw data.
	 *
	 * @param bytes the bytes
	 */
	public RawData(byte[] bytes) {
		this(bytes, null, 0);
	}
	
	/**
	 * Instantiates a new raw data.
	 *
	 * @param bytes the bytes
	 * @param address the address
	 * @param port the port
	 */
	public RawData(byte[] bytes, InetAddress address, int port) {
		if (bytes == null)
			throw new NullPointerException();
		this.bytes = bytes;
		this.address = address;
		this.port = port;
	}
	
	/**
	 * Gets the serialized message.
	 *
	 * @return the bytes
	 */
	public byte[] getBytes() {
		return bytes;
	}
	
	/**
	 * Gets the length of the serialized message
	 *
	 * @return the size
	 */
	public int getSize() {
		return bytes.length;
	}

	/**
	 * Gets the address.
	 *
	 * @return the address
	 */
	public InetAddress getAddress() {
		return address;
	}

	/**
	 * Sets the address.
	 *
	 * @param address the new address
	 */
	public void setAddress(InetAddress address) {
		this.address = address;
	}

	/**
	 * Gets the port.
	 *
	 * @return the port
	 */
	public int getPort() {
		return port;
	}

	/**
	 * Sets the port.
	 *
	 * @param port the new port
	 */
	public void setPort(int port) {
		this.port = port;
	}

	/**
	 * Checks if this is a multicast message
	 *
	 * @return true, if this is a multicast message
	 */
	public boolean isMulticast() {
		return multicast;
	}

	/**
	 * Marks this message as a multicast message.
	 *
	 * @param multicast whether this message is a multicast message
	 */
	public void setMulticast(boolean multicast) {
		this.multicast = multicast;
	}
	
	/**
	 * Gets the address as {@link InetSocketAddress}.
	 *
	 * @return the endpoint address
	 */
	public InetSocketAddress getInetSocketAddress() {
		return new InetSocketAddress(address, port);
	}
}
