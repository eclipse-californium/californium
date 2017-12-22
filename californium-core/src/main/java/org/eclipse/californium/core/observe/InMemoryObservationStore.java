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
 *    Achim Kraus (Bosch Software Innovations GmbH) - adjust to use Token
 ******************************************************************************/
package org.eclipse.californium.core.observe;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.elements.EndpointContext;

/**
 * An observation store that keeps all observations in-memory.
 */
public final class InMemoryObservationStore implements ObservationStore {

	private static final Logger LOG = LoggerFactory.getLogger(InMemoryObservationStore.class.getName());
	private Map<Token, Observation> map = new ConcurrentHashMap<>();

	@Override
	public void add(final Observation obs) {

		if (obs == null) {
			throw new NullPointerException("observation must not be null");
		} else {
			final Token token = new Token(obs.getRequest().getToken());
			LOG.debug("adding observation for token {}", token);
			map.put(token, obs);
		}
	}

	@Override
	public Observation get(Token token) {
		if (token == null) {
			return null;
		} else {
			LOG.debug("looking up observation for token {}", token);
			Observation obs = map.get(token);
			// clone request in order to prevent accumulation of message observers
			// on original request
			return ObservationUtil.shallowClone(obs);
		}
	}

	@Override
	public void remove(Token token) {
		if (token != null) {
			map.remove(token);
			LOG.debug("removed observation for token {}", token);
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
				map.put(token, new Observation(obs.getRequest(), ctx));
			}
		}
	}
}
