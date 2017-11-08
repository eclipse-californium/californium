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
 ******************************************************************************/
package org.eclipse.californium.core.observe;

import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.Utils;
import org.eclipse.californium.elements.EndpointContext;

/**
 * An observation store that keeps all observations in-memory.
 *
 */
public final class InMemoryObservationStore implements ObservationStore {

	private static final Logger LOG = LoggerFactory.getLogger(InMemoryObservationStore.class.getName());
	private Map<Key, Observation> map = new ConcurrentHashMap<>();

	@Override
	public void add(final Observation obs) {

		if (obs == null) {
			throw new NullPointerException("observation must not be null");
		} else {
			Key key = Key.fromToken(obs.getRequest().getToken());
			LOG.debug("adding observation for token {}", key);
			map.put(key, obs);
		}
	}

	@Override
	public Observation get(final byte[] token) {
		if (token == null) {
			return null;
		} else {
			Key key = Key.fromToken(token);
			LOG.debug("looking up observation for token {}", key);
			Observation obs = map.get(key);
			// clone request in order to prevent accumulation of message observers
			// on original request
			return ObservationUtil.shallowClone(obs);
		}
	}

	@Override
	public void remove(byte[] token) {
		if (token != null) {
			Key key = Key.fromToken(token);
			map.remove(key);
			LOG.debug("removed observation for token {}", key);
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
	public void setContext(final byte[] token, final EndpointContext ctx) {

		if (token != null && ctx != null) {
			Key key = Key.fromToken(token);
			Observation obs = map.get(key);
			if (obs != null) {
				map.put(key, new Observation(obs.getRequest(), ctx));
			}
		}
	}

	private static class Key {

		private final byte[] token;
		private final int hashCode;

		private Key(final byte[] token) {
			this.token = token;
			hashCode = Arrays.hashCode(token);
		}

		private static Key fromToken(byte[] token) {
			return new Key(token);
		}

		@Override
		public String toString() {
			return Utils.toHexString(token);
		}

		@Override
		public int hashCode() {
			return hashCode;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			Key other = (Key) obj;
			if (!Arrays.equals(token, other.token))
				return false;
			return true;
		}
	}
}
