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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add onContextEstablished.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add CorrelationContext to outbound
 *                                                    (fix GitHub issue #104)
 *    Achim Kraus (Bosch Software Innovations GmbH) - add onSent and onError.
 *                                                    issue #305
 *    Achim Kraus (Bosch Software Innovations GmbH) - move address and principal to
 *                                                    EndpointContext and cleanup
 *                                                    constructors.
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace isSecure by 
 *                                                    connector's protocol
 *    Achim Kraus (Bosch Software Innovations GmbH) - add onConnect
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.Arrays;

/**
 * A container object for the data received or sent via a {@link Connector}.
 * 
 * The following meta-data is included:
 * <ul>
 * <li>the peer's endpoint context, containing it's address, optional principal,
 * and optional correlation information</li>
 * <li>a flag indicating whether the message is a multicast message (default is
 * {@code false})</li>
 * </ul>
 * 
 * A message received from a client via the network may also optionally contain
 * the authenticated sender's identity as a {@link java.security.Principal}
 * object.
 */
public final class RawData {

	/** The raw message. */
	public final byte[] bytes;

	/** Indicates if this message is a multicast message */
	private final boolean multicast;

	/**
	 * Endpoint context of the remote peer.
	 */
	private final EndpointContext peerEndpointContext;

	/**
	 * Message callback to receive the actual endpoint context the message is
	 * sent in.
	 */
	private final MessageCallback callback;

	/**
	 * Instantiates a new raw data.
	 * 
	 * Use {@link #inbound(byte[], EndpointContext, boolean)} or
	 * {@link #outbound(byte[], EndpointContext, MessageCallback, boolean)}.
	 *
	 * @param data the data that is to be sent or has been received
	 * @param endpointContext remote peers endpoint context.
	 * @param multicast indicates whether the data represents a multicast
	 *            message
	 * @throws NullPointerException if data or address is {@code null}
	 */
	private RawData(byte[] data, EndpointContext peerEndpointContext, MessageCallback callback, boolean multicast) {
		if (data == null) {
			throw new NullPointerException("Data must not be null");
		} else if (peerEndpointContext == null) {
			throw new NullPointerException("Peer's EndpointContext must not be null");
		} else {
			this.bytes = data;
			this.peerEndpointContext = peerEndpointContext;
			this.callback = callback;
			this.multicast = multicast;
		}
	}

	/**
	 * Instantiates a new raw data for a message received from a peer.
	 *
	 * @param data the data that is to be sent or has been received.
	 * @param peerEndpointContext information regarding the context the message
	 *            has been received in. The information contained will usually
	 *            come from the transport layer, e.g. the ID of the DTLS session
	 *            the message has been received in, and can be used to correlate
	 *            this message with another (previously sent) message.
	 * @param isMulticast indicates whether the data has been received as a
	 *            multicast message.
	 * @return the raw data object containing the inbound message.
	 * @throws NullPointerException if data or address is {@code null}.
	 */
	public static RawData inbound(byte[] data, EndpointContext peerEndpointContext, boolean isMulticast) {
		return new RawData(data, peerEndpointContext, null, isMulticast);
	}

	/**
	 * Instantiates a new raw data for a message to be sent to a peer.
	 * <p>
	 * The given callback handler is notified when the message has been sent by
	 * a <code>Connector</code>. The information contained in the
	 * <code>MessageContext</code> object that is passed in to the handler may
	 * be relevant for matching a response received via a
	 * <code>RawDataChannel</code> to a request sent using this method, e.g.
	 * when using a DTLS based connector the context may contain the DTLS
	 * session ID and epoch number which is required to match a response to a
	 * request as defined in the CoAP specification.
	 * </p>
	 * <p>
	 * The message context is set via a callback in order to allow
	 * <code>Connector</code> implementations to process (send) messages
	 * asynchronously.
	 * </p>
	 * 
	 * @param data the data to send.
	 * @param peerEndpointContext remote peer's endpoint context to send data.
	 * @param callback the handler to call when this message has been sent (may
	 *            be {@code null}).
	 * @param useMulticast indicates whether the data should be sent using a
	 *            multicast message.
	 * @return the raw data object containing the outbound message.
	 * @throws NullPointerException if data or peerContext is {@code null}.
	 */
	public static RawData outbound(byte[] data, EndpointContext peerEndpointContext, MessageCallback callback,
			boolean useMulticast) {
		return new RawData(data, peerEndpointContext, callback, useMulticast);
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
		return peerEndpointContext.getPeerAddress().getAddress();
	}

	/**
	 * Gets the port.
	 *
	 * @return the port
	 */
	public int getPort() {
		return peerEndpointContext.getPeerAddress().getPort();
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
		return peerEndpointContext.getPeerAddress();
	}

	/**
	 * Gets the identity of the sender of the message.
	 * 
	 * This property is only meaningful for messages received from a client.
	 * 
	 * @return the identity or <code>null</code> if the sender has not been
	 *         authenticated
	 */
	public Principal getSenderIdentity() {
		return peerEndpointContext.getPeerIdentity();
	}

	/**
	 * Gets additional information regarding the context this message has been
	 * received in or should be sent in.
	 * 
	 * @return the message context including the endpoint information
	 */
	public EndpointContext getEndpointContext() {
		return peerEndpointContext;
	}

	/**
	 * Callback, when connector requires to establish a connection. Not called,
	 * if the connection is already established or the connector doesn't require
	 * to establish a connection.
	 */
	public void onConnecting() {
		if (null != callback) {
			callback.onConnecting();
		}
	}

	/**
	 * Callback, when the dtls connector retransmits a handshake flight.
	 * 
	 * @param flight {@code 1 ... 6}, number of retransmitted flight.
	 */
	public void onDtlsRetransmission(int flight) {
		if (null != callback) {
			callback.onDtlsRetransmission(flight);
		}
	}

	/**
	 * Callback, when context gets available. Used on sending an message.
	 * 
	 * @param context established context to be forwarded to the callback.
	 */
	public void onContextEstablished(EndpointContext context) {
		if (null != callback) {
			callback.onContextEstablished(context);
		}
	}

	/**
	 * Callback after message was sent by the connector.
	 */
	public void onSent() {
		if (null != callback) {
			callback.onSent();
		}
	}

	/**
	 * Called, when message was not sent by the connector.
	 * 
	 * @param error details for not sending the message. If {@code null},
	 *            {@link UnknownError} is used to call
	 *            {@link MessageCallback#onError(Throwable)}.
	 */
	public void onError(Throwable error) {
		if (null != callback) {
			if (null == error) {
				error = new UnknownError();
			}
			callback.onError(error);
		}
	}

}
