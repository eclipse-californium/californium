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
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * A map based correlation context.
 */
public class MapBasedCorrelationContext implements CorrelationContext {

	private Map<String, String> entries = new HashMap<>();

	/**
	 * Puts a value to the context.
	 * 
	 * @param key the key to put the value under.
	 * @param value the value to put to the context.
	 * @return the previous value for the given key or <code>null</code> if the context did
	 *         not contain any value for the key yet.
	 */
	public final Object put(String key, String value) {
		return entries.put(key, value);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String get(String key) {
		return entries.get(key);
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Set<Map.Entry<String, String>> entrySet() {
		return entries.entrySet();
	}

	/**
	 * Creates a hash code based on the entries stored in this context.
	 * <p>
	 * The hash code for two instances will be the same if they contain the
	 * same keys and values.
	 * </p>
	 * 
	 * @return the hash code.
	 */
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((entries == null) ? 0 : entries.hashCode());
		return result;
	}

	/**
	 * Checks if this correlation context has the same entries as another instance.
	 * 
	 * @param obj the object to compare this context to.
	 * @return <code>true</code> if the other object also is a <code>MapBasedCorrelationContext</code>
	 *         and has the same entries as this context.
	 */
	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof MapBasedCorrelationContext)) {
			return false;
		}
		MapBasedCorrelationContext other = (MapBasedCorrelationContext) obj;
		if (entries == null) {
			if (other.entries != null) {
				return false;
			}
		} else if (!entries.equals(other.entries)) {
			return false;
		}
		return true;
	}

}
