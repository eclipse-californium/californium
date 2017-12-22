/*******************************************************************************
 * Copyright (c) 2016, 2017 Sierra Wireless and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - precalculated hashCode
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - adjust to use Token,
 *                                                    token generator and
 *                                                    ensure putIfAbsent semantic
 ******************************************************************************/
package org.eclipse.californium.core.observe;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.elements.EndpointContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An observation store that keeps all observations in-memory.
 */
public final class InMemoryObservationStore implements ObservationStore {

	private static final Logger LOGGER = LoggerFactory.getLogger(InMemoryObservationStore.class.getName());
	private final ConcurrentMap<Token, Observation> map = new ConcurrentHashMap<>();

	public InMemoryObservationStore() {
	}

	@Override
	public Observation putIfAbsent(Token key, Observation obs) {
		if (key == null) {
			throw new NullPointerException("token must not be null");
		} else if (obs == null) {
			throw new NullPointerException("observation must not be null");
		} else {
			Observation result = map.putIfAbsent(key, obs);
			if (result == null) {
				LOGGER.debug("added observation for token {}", key);
			} else {
				LOGGER.debug("kept observation for token {}", key);
			}
			return result;
		}
	}

	@Override
	public Observation put(Token key, Observation obs) {
		if (key == null) {
			throw new NullPointerException("token must not be null");
		} else if (obs == null) {
			throw new NullPointerException("observation must not be null");
		} else {
			Observation result = map.put(key, obs);
			if (result == null) {
				LOGGER.debug("added observation for token {}", key);
			} else {
				LOGGER.debug("replaced observation for token {}", key);
			}
			return result;
		}
	}

	@Override
	public Observation get(Token token) {
		if (token == null) {
			return null;
		} else {
			LOGGER.debug("looking up observation for token {}", token);
			Observation obs = map.get(token);
			// clone request in order to prevent accumulation of
			// message observers on original request
			return ObservationUtil.shallowClone(obs);
		}
	}

	@Override
	public void remove(Token token) {
		if (token != null) {
			map.remove(token);
			LOGGER.debug("removed observation for token {}", token);
		}
	}

	/**
	 * Checks if this store is empty.
	 * 
	 * @return {@code true} if this store does not contain any observations.
	 */
	public boolean isEmpty() {
		return map.isEmpty();
	}

	/**
	 * Gets the number of observations currently held in this store.
	 * 
	 * @return The number of observations.
	 */
	public int getSize() {
		return map.size();
	}

	/**
	 * Removes all observations from this store.
	 */
	public void clear() {
		map.clear();
	}

	@Override
	public void setContext(Token token, final EndpointContext ctx) {

		if (token != null && ctx != null) {
			Observation obs = map.get(token);
			if (obs != null) {
				map.replace(token, obs, new Observation(obs.getRequest(), ctx));
			}
		}
	}
}
