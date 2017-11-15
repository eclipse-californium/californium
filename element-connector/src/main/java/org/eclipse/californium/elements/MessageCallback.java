/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - add support for correlation context to provide
 *                                      additional information to application layer for
 *                                      matching messages (fix GitHub issue #1)
 *    Achim Kraus (Bosch Software Innovations GmbH) - add comment on processing
 *                                                    onContextEstablished. issue #311 
 ******************************************************************************/
package org.eclipse.californium.elements;

public interface MessageCallback {

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
	void onContextEstablished(CorrelationContext context);
}
