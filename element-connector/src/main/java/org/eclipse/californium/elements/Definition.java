/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements;

/**
 * Definition of value.
 *
 * @param <T> type of value
 * @since 3.0
 */
public class Definition<T> {

	/**
	 * Lookup key.
	 */
	private final String key;
	/**
	 * Type of value.
	 */
	private final Class<T> valueType;

	/**
	 * Creates definition.
	 * 
	 * @param key key for lookup
	 * @param valueType value type
	 * @throws NullPointerException if any parameter is {@code null}
	 * @throws IllegalArgumentException if key is empty
	 */
	public Definition(String key, Class<T> valueType) {
		this(key, valueType, null);
	}

	/**
	 * Creates definition.
	 * 
	 * @param key key for lookup
	 * @param valueType value type
	 * @param definitions definition set to add this definition. May be
	 *            {@code null}.
	 * @throws NullPointerException if key or value type is {@code null}
	 * @throws IllegalArgumentException if key is empty, or the definitions
	 *             already contains a definition for that key.
	 */
	public Definition(String key, Class<T> valueType, Definitions<Definition<?>> definitions) {
		if (key == null) {
			throw new NullPointerException("Key must not be null!");
		}
		if (valueType == null) {
			throw new NullPointerException("Value Type must not be null!");
		}
		if (key.isEmpty()) {
			throw new IllegalArgumentException("Key must not be empty!");
		}
		this.key = key;
		this.valueType = valueType;
		if (definitions != null) {
			definitions.add(this);
		}
	}

	/**
	 * Gets the value type.
	 * 
	 * @return value type
	 */
	public final Class<T> getValueType() {
		return valueType;
	}

	/**
	 * Gets key for {@link Definitions}.
	 * 
	 * @return key for {@link Definitions}.
	 */
	public final String getKey() {
		return key;
	}

	@Override
	public String toString() {
		return key;
	}
}
