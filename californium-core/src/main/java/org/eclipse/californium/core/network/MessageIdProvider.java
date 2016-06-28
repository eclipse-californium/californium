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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.net.InetSocketAddress;

/**
 * A provider of CoAP message IDs.
 */
public interface MessageIdProvider {

	/**
	 * Gets a message ID for a destination endpoint.
	 * <p>
	 * Message IDs are guaranteed to not being issued twice within EXCHANGE_LIFETIME
	 * as defined by the <a href="https://tools.ietf.org/html/rfc7252#section-4.4">CoAP spec</a>.
	 * 
	 * @param destination the destination that the message ID must be <em>free to use</em> for.
	 *        This means that the message ID returned must not have been used in a message
	 *        to this destination for at least EXCHANGE_LIFETIME.
	 * @return a message ID or {@code -1} if there is no message ID available for the given destination
	 *         at the moment.
	 */
	int getNextMessageId(InetSocketAddress destination);
}
