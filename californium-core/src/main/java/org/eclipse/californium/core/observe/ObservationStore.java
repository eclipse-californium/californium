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
package org.eclipse.californium.core.observe;

import org.eclipse.californium.core.identifier.EndpointIdentifier;

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
	 * Adds an observation to the store.
	 * 
	 * @param endpoint The endpoint identifier of the peer that the observe
	 *            relation exists with.
	 * @param obs The observation to add.
	 * @throws NullPointerException if observation is {@code null}.
	 */
	void add(EndpointIdentifier endpoint, Observation obs);

	/**
	 * Removes an observation.
	 * 
	 * @param endpoint The endpoint identifier of the peer that the observe relation exists with.
	 * @param token The token of the request that initiated the observe relation.
	 */
	void remove(EndpointIdentifier endpoint, byte[] token);

	/**
	 * Gets an observation.
	 * 
	 * @param endpoint The endpoint identifier of the peer that the observe relation exists with.
	 * @param token The token of the request that initiated the observe relation.
	 * @return The corresponding observation or {@code null} if no observation is registered for the given
	 *         endpoint and token.
	 */
	Observation get(EndpointIdentifier endpoint, byte[] token);
}