/*******************************************************************************
 * Copyright (c) 2016 Sierra Wireless and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add Exchange to remove for
 *                                                    save cleanup.
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove setContext().
 *                                                    issue #311
 ******************************************************************************/
package org.eclipse.californium.core.network;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.network.Exchange.KeyMID;
import org.eclipse.californium.core.network.Exchange.KeyToken;
import org.eclipse.californium.core.network.Exchange.KeyUri;

/**
 * A registry for keeping track of message exchanges with peers.
 * <p>
 * The information kept in this registry is particularly intended to be shared
 * with other Californium instances (running on other nodes) to support failing over
 * the processing of notifications received by another node after the original node
 * (which initiated the observation of the resource) has crashed.
 * </p>
 */
public interface MessageExchangeStore {

	/**
	 * Starts this store.
	 */
	void start();

	/**
	 * Stops this store.
	 */
	void stop();

	/**
	 * Assigns an unused message ID to a message.
	 * 
	 * @param message the message. The message to assign the ID to.
	 * @return The assigned message ID. This will be {@link Message#NONE} if all message IDs are currently in use for
	 *         the message's destination endpoint.
	 */
	int assignMessageId(Message message);

	/**
	 * Registers an exchange for an outbound request.
	 * <p>
	 * This method assigns an unused message ID to the request contained in the exchange
	 * and marks it as being <em>in-use</em>.
	 * If the request does not already contain a token, this method also generates a valid
	 * token and sets it on the request.
	 * <p>
	 * The exchange can later be retrieved from this store using the corresponding <em>get</em>
	 * method.
	 * 
	 * @param exchange the exchange to register.
	 * @return {@code true} if the request has been registered successfully.
	 * @throws NullPointerException if any of the given params is {@code null}.
	 * @throws IllegalArgumentException if the exchange does not contain a (current) request
	 *                                  or if the request already has a message ID that is still in use.
	 */
	boolean registerOutboundRequest(Exchange exchange);

	/**
	 * Registers an exchange for an outbound request.
	 * <p>
	 * If the request does not already contain a token, this method generates a valid
	 * and (currently) unused token and sets it on the request. The exchange is then
	 * registered under the request's token.
	 * <p>
	 * The exchange can later be retrieved from this store using the corresponding <em>get</em>
	 * method.
	 * 
	 * @param exchange the exchange to register.
	 * @return {@code true} if the request has been registered successfully.
	 * @throws NullPointerException if any of the given params is {@code null}.
	 * @throws IllegalArgumentException if the exchange does not contain a (current) request.
	 */
	boolean registerOutboundRequestWithTokenOnly(Exchange exchange);

	/**
	 * Registers an exchange for an outbound response.
	 * <p>
	 * If the response contained in the exchange does not already contain a message ID, this method
	 * assigns an unused message ID to the request and marks the message ID as being <em>in-use</em>.
	 * <p>
	 * The exchange can later be retrieved from this store using the corresponding <em>get</em>
	 * method.
	 * 
	 * @param exchange the exchange to register.
	 * @return {@code true} if the response has been registered successfully.
	 * @throws NullPointerException if any of the given params is {@code null}.
	 * @throws IllegalArgumentException if the exchange does not contain a (current) response
	 *                                  or if the response already has a message ID that is still in use.
	 */
	boolean registerOutboundResponse(Exchange exchange);

	/**
	 * Registers an exchange used for doing a blockwise transfer with a given URI.
	 * 
	 * @param requestUri the URI to register the exchange for.
	 * @param exchange the exchange to register.
	 * @throws NullPointerException if any of the given params is {@code null}.
	 * @return the exchange previously registered with the given URI or {@code null}.
	 */
	Exchange registerBlockwiseExchange(KeyUri requestUri, Exchange exchange);

	/**
	 * Removes the exchange registered under a given token.
	 * 
	 * @param token the token of the exchange to remove.
	 * @param exchange Exchange to be removed, if registered with provided token.
	 */
	void remove(KeyToken token, Exchange exchange);

	/**
	 * Removes the exchange registered under a given message ID.
	 * 
	 * @param messageId the message ID to remove the exchange for.
	 * @param exchange Exchange to be removed. If {@code null}, the current
	 *                 exchange with the MID is removed. If not {@code null},
	 *                 only this exchange is removed, if it's registered with
	 *                 the MID.
	 * @return the removed exchange, or {@code null}, if no exchange was removed.
	 */
	Exchange remove(KeyMID messageId, Exchange exchange);

	/**
	 * Removes the exchange used for a blockwise transfer of a resource.
	 * 
	 * @param requestUri the URI under which the exchange has been registered.
	 * @param exchange Exchange to be removed, if registered with provided URI.
	 */
	void remove(KeyUri requestUri, Exchange exchange);

	/**
	 * Gets the exchange registered under a given token.
	 * 
	 * @param token the token under which the exchange has been registered.
	 * @return the exchange or {@code null} if no exchange exists for the given token.
	 */
	Exchange get(KeyToken token);

	/**
	 * Gets the exchange registered under a given message ID.
	 * 
	 * @param messageId the MID under which the exchange has been registered.
	 * @return the exchange or {@code null} if no exchange exists for the given message ID.
	 */
	Exchange get(KeyMID messageId);

	/**
	 * Gets the blockwise transfer exchange registered under a given URI.
	 * 
	 * @param requestUri the URI under which the exchange has been registered.
	 * @return the exchange or {@code null} if no exchange is registered for the given URI.
	 */
	Exchange get(KeyUri requestUri);

	/**
	 * Checks if the specified message ID is already associated with a previous
	 * exchange and otherwise associates the key with the exchange specified. 
	 * This method can also be thought of as <em>put if absent</em>.
	 * This is equivalent to
     * <pre>
     *   if (!duplicator.containsKey(key))
     *       return duplicator.put(key, value);
     *   else
     *       return duplicator.get(key);
     * </pre>
     * except that the action is performed atomically.
	 * 
	 * @param messageId the message ID of the request
	 * @param exchange the exchange
	 * @return the previous exchange associated with the specified key, or
     *         <tt>null</tt> if there was no mapping for the key.
	 */
	Exchange findPrevious(KeyMID messageId, Exchange exchange);

	/**
	 * Checks if a message with a given ID has been processed already.
	 * 
	 * @param messageId the message ID.
	 * @return the exchange that the message has been a part of or {@code null}
	 *         if no message with the given ID has been received for at least
	 *         {@code EXCHANGE_LIFETIME}.
	 */
	Exchange find(KeyMID messageId);

	/**
	 * Checks if there are any exchanges currently being registered in this store.
	 * 
	 * @return {@code true} if there no exchanges registered.
	 */
	boolean isEmpty();

	/**
	 * Releases the given token to be used again.
	 * 
	 * @param keyToken the KeyToken to release.
	 */
	void releaseToken(KeyToken keyToken);
}