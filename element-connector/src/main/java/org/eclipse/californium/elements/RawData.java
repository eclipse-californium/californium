/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - several additions and improvements
 *    Bosch Software Innovations GmbH - add support for correlation context to provide
 *                                      additional information to application layer for
 *                                      matching messages (fix GitHub issue #1)
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.Arrays;

/**
 * A container object for the data received or sent via a <code>Connector</code>.
 * 
 * The following meta-data is included:
 * <ul>
 * <li>the source/destination IP address</li>
 * <li>the source/destination port</li>
 * <li>a flag indicating whether the message is a multicast message (default is
 * <code>false</code>)</li>
 * </ul>
 * 
 * A message received from a client via the network may also optionally contain the
 * authenticated sender's identity as a <code>java.security.Principal</code> object.
 */
public final class RawData {

	/** The raw message. */
	public final byte[] bytes;

	/** The source/destination address. */
	private InetSocketAddress address;

	/** Indicates if this message is a multicast message */
	private boolean multicast;

	private Principal senderIdentity;

	private CorrelationContext correlationContext;

	private MessageCallback callback;

	/**
	 * Instantiates a new raw data.
	 *
	 * @param data the data that is to be sent or has been received
	 * @param address the IP address and port the data is to be sent to or has been received from
	 * @throws NullPointerException if any of the given parameters is <code>null</code>
	 */
	public RawData(byte[] data, InetSocketAddress address) {
		this(data, address, null, false);
	}

	/**
	 * Instantiates a new raw data.
	 *
	 * @param data the data that is to be sent or has been received
	 * @param address the IP address and port the data is to be sent to or has been received from
	 * @param clientIdentity the identity of the authenticated sender of the message
	 *     (or <code>null</code> if sender is not authenticated)
	 * @throws NullPointerException if any of the given parameters is <code>null</code>
	 */
	public RawData(byte[] data, InetSocketAddress address, Principal clientIdentity) {
		this(data, address, clientIdentity, false);
	}

	/**
	 * Instantiates a new raw data.
	 *
	 * @param data the data that is to be sent or has been received
	 * @param address the IP address the data is to be sent to or has been received from
	 * @param port the port the data is to be sent to or has been received from
	 * @throws NullPointerException if data is <code>null</code>
	 */
	public RawData(byte[] data, InetAddress address, int port) {
		this(data, address, port, null, false);
	}

	/**
	 * Instantiates a new raw data.
	 *
	 * @param data the data that is to be sent or has been received
	 * @param address the IP address the data is to be sent to or has been received from
	 * @param port the port the data is to be sent to or has been received from
	 * @param clientIdentity the identity of the authenticated sender of the message
	 *     (or <code>null</code> if sender is not authenticated)
	 * @throws NullPointerException if data is <code>null</code>
	 */
	public RawData(byte[] data, InetAddress address, int port, Principal clientIdentity) {
		this(data, address, port, clientIdentity, false);
	}

	/**
	 * Instantiates a new raw data.
	 *
	 * @param data the data that is to be sent or has been received
	 * @param address the IP address and port the data is to be sent to or has been received from
	 * @param multicast indicates whether the data represents a multicast message
	 * @throws NullPointerException if data or address is <code>null</code>
	 */
	public RawData(byte[] data, InetSocketAddress address, boolean multicast) {
		this(data, address, null, multicast);
	}

	/**
	 * Instantiates a new raw data.
	 *
	 * @param data the data that is to be sent or has been received
	 * @param address the IP address and port the data is to be sent to or has been received from
	 * @param clientIdentity the identity of the authenticated sender of the message
	 *     (or <code>null</code> if sender is not authenticated)
	 * @param multicast indicates whether the data represents a multicast message
	 * @throws NullPointerException if data or address is <code>null</code>
	 */
	public RawData(byte[] data, InetSocketAddress address, Principal clientIdentity, boolean multicast) {
		this(data, address, clientIdentity, null, multicast);
	}

	/**
	 * Instantiates a new raw data.
	 *
	 * @param data the data that is to be sent or has been received
	 * @param address the IP address and port the data is to be sent to or has been received from
	 * @param clientIdentity the identity of the authenticated sender of the message
	 *     (or <code>null</code> if sender is not authenticated)
	 * @param correlationContext additional information regarding the context the message has been
	 *      received in. The information contained will usually come from the transport layer, e.g.
	 *      the ID of the DTLS session the message has been received in, and can be used to correlate
	 *      this message with another (previously send) message.
	 * @param multicast indicates whether the data represents a multicast message
	 * @throws NullPointerException if data or address is <code>null</code>
	 */
	private RawData(byte[] data, InetSocketAddress address, Principal clientIdentity, CorrelationContext correlationContext, boolean multicast) {
		if (data == null) {
			throw new NullPointerException("Data must not be null");
		} else if (address == null) {
			throw new NullPointerException("Address must not be null");
		} else {
			this.bytes = data;
			this.address = address;
			this.senderIdentity = clientIdentity;
			this.correlationContext = correlationContext;
			this.multicast = multicast;
		}
	}

	/**
	 * Instantiates a new raw data.
	 *
	 * @param data the data that is to be sent or has been received
	 * @param address the IP address the data is to be sent to or has been received from
	 * @param port the port the data is to be sent to or has been received from
	 * @param multicast indicates whether the data represents a multicast message
	 * @throws NullPointerException if data is <code>null</code>
	 */
	public RawData(byte[] data, InetAddress address, int port, boolean multicast) {
		this(data, address, port, null, multicast);
	}

	/**
	 * Instantiates a new raw data.
	 *
	 * @param data the data that is to be sent or has been received
	 * @param address the IP address the data is to be sent to or has been received from
	 * @param port the port the data is to be sent to or has been received from
	 * @param clientIdentity the identity of the authenticated sender of the message
	 *     (or <code>null</code> if sender is not authenticated)
	 * @param multicast indicates whether the data represents a multicast message
	 * @throws NullPointerException if data is <code>null</code>
	 */
	public RawData(byte[] data, InetAddress address, int port, Principal clientIdentity, boolean multicast) {
		this(data, new InetSocketAddress(address, port), clientIdentity, multicast);
	}

	/**
	 * Instantiates a new raw data for a message received from a peer.
	 *
	 * @param data the data that is to be sent or has been received.
	 * @param address the IP address and port the data has been received from.
	 * @param clientIdentity the identity of the authenticated sender of the message
	 *     (or <code>null</code> if sender is not authenticated).
	 * @param correlationContext additional information regarding the context the message has been
	 *      received in. The information contained will usually come from the transport layer, e.g.
	 *      the ID of the DTLS session the message has been received in, and can be used to correlate
	 *      this message with another (previously sent) message.
	 * @param isMulticast indicates whether the data has been received as a multicast message.
	 * @return the raw data object containing the inbound message.
	 * @throws NullPointerException if data or address is <code>null</code>.
	 */
	public static RawData inbound(byte[] data, InetSocketAddress address, Principal clientIdentity,
			CorrelationContext correlationContext, boolean isMulticast) {
		return new RawData(data, address, clientIdentity, correlationContext, isMulticast);
	}

	/**
	 * Instantiates a new raw data for a message to be sent to a peer.
	 * <p>
	 * The given callback handler is notified when the message has been sent by a <code>Connector</code>.
	 * The information contained in the <code>MessageContext</code> object that is passed in to the
	 * handler may be relevant for matching a response received via a <code>RawDataChannel</code> to a request
	 * sent using this method, e.g. when using a DTLS based connector the context may contain the DTLS session
	 * ID and epoch number which is required to match a response to a request as defined in the CoAP specification.
	 * </p>
	 * <p>
	 * The message context is set via a callback in order to allow <code>Connector</code> implementations to
	 * process (send) messages asynchronously.
	 * </p>
	 * 
	 * @param data the data to send.
	 * @param address the IP address and port the data is to be sent to.
	 * @param callback the handler to call when this message has been sent (may be <code>null</code>).
	 * @param useMulticast indicates whether the data should be sent using a multicast message.
	 * @return the raw data object containing the outbound message.
	 * @throws NullPointerException if data or address is <code>null</code>.
	 */
	public static RawData outbound(byte[] data, InetSocketAddress address, MessageCallback callback, boolean useMulticast) {
		RawData result = new RawData(data, address);
		result.callback = callback;
		result.multicast = useMulticast;
		return result;
	}

	/**
	 * Gets the raw message.
	 *
	 * @return a copy of the raw message bytes
	 */
	public byte[] getBytes() {
		return Arrays.copyOf(bytes, bytes.length);
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
		return address.getAddress();
	}

	/**
	 * Gets the port.
	 *
	 * @return the port
	 */
	public int getPort() {
		return address.getPort();
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
	 * Gets the source/destination IP address and port.
	 *
	 * @return the address
	 */
	public InetSocketAddress getInetSocketAddress() {
		return address;
	}

	/**
	 * Gets the identity of the sender of the message.
	 * 
	 * This property is only meaningful for messages
	 * received from a client.
	 * 
	 * @return the identity or <code>null</code> if the
	 *      sender has not been authenticated
	 */
	public Principal getSenderIdentity() {
		return senderIdentity;
	}

	/**
	 * Gets additional information regarding the context this message has been 
	 * received in.
	 * 
	 * @return the messageContext the correlation information or <code>null</code> if
	 *           no additional correlation information is available
	 */
	public CorrelationContext getCorrelationContext() {
		return correlationContext;
	}

	/**
	 * @return the callback
	 */
	public MessageCallback getMessageCallback() {
		return callback;
	}

	/**
	 * Determines if the correlation context of this object is secure.
	 *
	 * @return <code>true</code> if context is secure, <code>false</code> otherwise
	 */
	public boolean isSecure() {
		return (correlationContext != null &&
				correlationContext.get(DtlsCorrelationContext.KEY_SESSION_ID) != null);
	}
}
