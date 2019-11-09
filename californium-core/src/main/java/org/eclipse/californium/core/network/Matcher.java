/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    (a lot of changes from different authors, please refer to gitlog).
 *    Achim Kraus (Bosch Software Innovations GmbH) - make exchangeStore final
 *                                                    remove setMessageExchangeStore
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace parameter EndpointContext
 *                                                    by EndpointContext of response.
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 ******************************************************************************/
package org.eclipse.californium.core.network;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;

/**
 * The Matcher is the component at the bottom of the CoAP stack.
 * <p>
 * Its main responsibilities are
 * <ul>
 * <li>making sure that outbound messages have a valid token and message ID set</li>
 * <li>keeping track of ongoing exchanges with peers</li>
 * <li>matching incoming messages to ongoing exchanges so that upper layers in the stack can process
 * the inbound messages in the context of the exchange</li>
 * <li>detecting duplicate (inbound) messages</li>
 * </ul>
 */
public interface Matcher {

	/**
	 * Starts this matcher.
	 * 
	 * @throws IllegalStateException if the matcher has not been configured properly.
	 */
	void start();

	/**
	 * Stops this matcher.
	 * <p>
	 * When this method is invoked an implementation may clear up all its internal state.
	 */
	void stop();

	/**
	 * Notifies this matcher about a request message being sent to a peer.
	 * <p>
	 * Implementations should make sure that the request being sent
	 * has a valid token and message ID set (if appropriate for the
	 * underlying transport protocol).
	 * <p>
	 * This method is also a signal for the matcher to begin tracking the
	 * request message. This includes both
	 * <ul>
	 * <li>keeping track of the message ID if the request is sent as a CON
	 * so that it can later be matched to an ACK or RST sent by the peer in
	 * response.</li>
	 * <li>keeping track of the token so that it can be used to identify the
	 * response to the request (regardless of whether the peer sends it
	 * piggy-backed in an ACK or as a separate message).</li>
	 * </ul>
	 * 
	 * @param exchange the message exchange that the request is sent as part of.
	 */
	void sendRequest(Exchange exchange);

	/**
	 * Notifies this matcher about a response message being sent to a peer.
	 * <p>
	 * Implementations should make sure that the response being sent
	 * has a valid token and message ID set (if appropriate for the
	 * underlying transport protocol).
	 * <p>
	 * This method is also a signal for the matcher to begin tracking the
	 * response message if it is sent as a CON so that it can later be matched
	 * to an ACK or RST sent by the peer in response.
	 * 
	 * @param exchange the message exchange that the response is sent as part of.
	 */
	void sendResponse(Exchange exchange);

	/**
	 * Notifies this matcher about an empty ACK or RST being sent to a peer.
	 * <p>
	 * An implementation should remove the given exchange from its internal records if
	 * the message is an RST.
	 * 
	 * @param exchange the exchange that the message is sent as part of.
	 * @param message the message being sent to the peer.
	 */
	void sendEmptyMessage(Exchange exchange, EmptyMessage message);

	/**
	 * Determines the message exchange that a request message received from a peer
	 * is part of.
	 * <p>
	 * An implementation must detect a duplicate request and mark it
	 * accordingly ({@link Request#setDuplicate(boolean)}.
	 * 
	 * @param request the request message received from the peer.
	 * @param receiver handler for received request.
	 */
	void receiveRequest(Request request, EndpointReceiver receiver);

	/**
	 * Determines the message exchange that a response message received from a peer
	 * is part of.
	 * <p>
	 * An implementation must detect a duplicate response that has been sent
	 * as a separate message (i.e. not piggy-backed in an ACK) and mark it
	 * accordingly ({@link Response#setDuplicate(boolean)}.
	 * 
	 * @param response the response message received from the peer.
	 * @param receiver handler for received response.
	 */
	void receiveResponse(Response response, EndpointReceiver receiver);

	/**
	 * Determines the message exchange that an empty message received from a peer
	 * is part of.
	 * <p>
	 * An implementation may use this method to mark the message ID contained in the
	 * received message as <em>available</em> again so that it can be re-used for new
	 * message exchanges after <em>EXCHANGE_LIFETIME</em>.
	 * 
	 * @param message the empty message received from the peer.
	 * @param receiver handler for received empty message.
	 */
	void receiveEmptyMessage(EmptyMessage message, EndpointReceiver receiver);

	/**
	 * Clears all internal state.
	 */
	void clear();

	/**
	 * Cancels all pending blockwise requests that have been induced by a
	 * notification we have received indicating a blockwise transfer of the
	 * resource.
	 * 
	 * @param token the token of the observation.
	 *            The token must not have client-local scope.
	 * @return the exchanges.
	 * @throws IllegalArgumentException if the token has client-local scope.
	 */
	void cancelObserve(Token token);
}
