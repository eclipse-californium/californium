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
 *    initial implementation please refer gitlog
 *    Achim Kraus (Bosch Software Innovations GmbH) - adjust to use Token
 ******************************************************************************/
package org.eclipse.californium.core.observe;

import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.elements.EndpointContext;

/**
 * A registry for keeping information about resources observed on other peers.
 * <p>
 * The information kept in this registry is particularly intended to be shared
 * with other instances (running on other nodes) to support failing over the
 * processing of notifications received by another node after the original node
 * (that initially registered the observation) has crashed.
 * </p>
 */
public interface ObservationStore {

	/**
	 * Adds an observation to the store using the provided token, if not already
	 * added with that token.
	 * 
	 * Preserve previous stored observation with that token.
	 * 
	 * @param token unique token to add the provided observation.
	 * @param obs The observation to add.
	 * @return the previous value associated with the specified key, or
	 *         {@code null} if there was no mapping for the key.
	 * @throws NullPointerException if token or observation is {@code null}.
	 */
	Observation putIfAbsent(Token token, Observation obs);

	/**
	 * Adds an observation to the store using the provided token.
	 * 
	 * Potentially replaces previous stored observation with that token.
	 * 
	 * @param token unique token to add the provided observation.
	 * @param obs The observation to add.
	 * @return the previous value associated with the specified key, or
	 *         {@code null} if there was no mapping for the key.
	 * @throws NullPointerException if token or observation is {@code null}.
	 */
	Observation put(Token token, Observation obs);

	/**
	 * Removes the observation initiated by the request with the given token.
	 * 
	 * @param token The token of the observation to remove.
	 */
	void remove(Token token);

	/**
	 * Gets the observation initiated by the request with the given token.
	 * 
	 * @param token The token of the initiating request.
	 * @return The corresponding observation or {@code null} if no observation
	 *         is registered for the given token.
	 */
	Observation get(Token token);

	/**
	 * Sets the endpoint context on the observation initiated by the request
	 * with the given token.
	 * <p>
	 * This method is necessary because the endpoint context may not be known
	 * when the observation is originally registered. This is due to the fact
	 * that the information contained in the endpoint context is gathered by the
	 * transport layer when the request establishing the observation is sent to
	 * the peer.
	 * </p>
	 * 
	 * @param token The token of the observation to set the context on.
	 * @param endpointContext The context to set.
	 */
	void setContext(Token token, EndpointContext endpointContext);

	void start();

	void stop();
}
