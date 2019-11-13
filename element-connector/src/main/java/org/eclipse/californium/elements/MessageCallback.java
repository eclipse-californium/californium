/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - add support for correlation context to provide
 *                                      additional information to application layer for
 *                                      matching messages (fix GitHub issue #1)
 *    Achim Kraus (Bosch Software Innovations GmbH) - extend to report the sending 
 *                                                    of the data or errors.
 *                                                    issue #305
 *    Achim Kraus (Bosch Software Innovations GmbH) - add comment on processing
 *                                                    onContextEstablished. issue #311 
 *    Achim Kraus (Bosch Software Innovations GmbH) - add onConnect
 ******************************************************************************/
package org.eclipse.californium.elements;

public interface MessageCallback {

	/**
	 * Called, when connector requires to establish a connection. Not called, if
	 * the connection is already established or the connector doesn't require to
	 * establish a connection.
	 */
	void onConnecting();

	/**
	 * Called, when the dtls connector retransmits a handshake flight.
	 * 
	 * @param flight {@code 1 ... 6}, number of retransmitted flight.
	 */
	void onDtlsRetransmission(int flight);

	/**
	 * Called when the context information for an outbound message has been
	 * established.
	 * <p>
	 * The information contained in the context object depends on the particular
	 * transport layer used to send the message. For a transport using DTLS the
	 * context will include e.g. the DTLS session's ID, epoch number and cipher
	 * that is used for sending the message to the peer.
	 * </p>
	 * Note: usually this callback must be processed in a synchronous manner, because
	 * if it returns, the message is sent. Therefore take special care in methods called
	 * on this callback.
	 *  
	 * @param context transport specific properties describing the context in
	 *                   which the message is sent
	 */
	void onContextEstablished(EndpointContext context);

	/**
	 * Called after message was sent by the connector.
	 */
	void onSent();

	/**
	 * Called, when message was not sent by the connector.
	 * 
	 * @param error details for not sending the message.
	 */
	void onError(Throwable error);
}
