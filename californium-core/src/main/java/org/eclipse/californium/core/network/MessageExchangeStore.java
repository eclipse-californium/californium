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
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.util.List;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.network.Exchange.KeyMID;
import org.eclipse.californium.core.network.Exchange.KeyToken;
import org.eclipse.californium.core.network.Exchange.KeyUri;
import org.eclipse.californium.elements.CorrelationContext;

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
	 * @param message the message. The message will have its <em>mid</em> property set
	 *        to {@code -1} if all message IDs are currently in use for the message's destination endpoint.
	 */
	void assignMessageId(Message message);

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
	 * @throws NullPointerException if any of the given params is {@code null}.
	 * @throws IllegalArgumentException if the exchange does not contain a (current) request.
	 */
	void registerOutboundRequest(Exchange exchange);

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
	 * @throws NullPointerException if any of the given params is {@code null}.
	 * @throws IllegalArgumentException if the exchange does not contain a (current) request.
	 */
	void registerOutboundRequestWithTokenOnly(Exchange exchange);

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
	 * @throws NullPointerException if any of the given params is {@code null}.
	 * @throws IllegalArgumentException if the exchange does not contain a (current) response.
	 */
	void registerOutboundResponse(Exchange exchange);

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
	 */
	void remove(KeyToken token);

	/**
	 * Removes the exchange registered under a given message ID.
	 * 
	 * @param messageId the message ID to remove the exchange for.
	 * @return the exchange that was registered under the given message ID or {@code null}
	 * if no exchange was registered under the ID.
	 */
	Exchange remove(KeyMID messageId);

	/**
	 * Removes the exchange used for a blockwise transfer of a resource.
	 * 
	 * @param requestUri the URI under which the exchange has been registered.
	 */
	void remove(KeyUri requestUri);

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
	 * Sets the correlation context on the exchange initiated by a request
	 * with a given token.
	 * <p>
	 * This method is necessary because the correlation context may not be known
	 * when the exchange is originally registered. This is due to the fact
	 * that the information contained in the correlation context is gathered by
	 * the transport layer when the request establishing the observation is sent
	 * to the peer.
	 * 
	 * @param token the token of the request.
	 * @param correlationContext the context.
	 */
	void setContext(KeyToken token, CorrelationContext correlationContext);

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
	 * Gets all message exchanges of local origin that contain a request
	 * with a given token.
	 * 
	 * @param token the token to look for.
	 * @return the exchanges.
	 */
	List<Exchange> findByToken(byte[] token);
}