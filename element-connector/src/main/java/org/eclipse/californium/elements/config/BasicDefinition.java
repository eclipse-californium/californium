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
 *    Bosch IO.GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.config;

/**
 * Basic definitions.
 * 
 * Used without additional units.
 *
 * @param <T> value type
 * @see Configuration#get(BasicDefinition)
 * @see Configuration#set(BasicDefinition, Object)
 * @since 3.0
 */
public abstract class BasicDefinition<T> extends DocumentedDefinition<T> {

	/**
	 * Creates basic definition.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param valueType value type.
	 * @throws NullPointerException if key is {@code null}
	 */
	protected BasicDefinition(String key, String documentation, Class<T> valueType) {
		super(key, documentation, valueType);
	}

	/**
	 * Creates basic definition with default value.
	 * 
	 * If the configuration value is mainly used with primitive types (e.g.
	 * `int`), {@code null} causes a {@link NullPointerException} on access.
	 * To prevent that, the default value is returned instead of a
	 * {@code null}.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param valueType value type.
	 * @param defaultValue default value returned instead of {@code null}.
	 * @throws NullPointerException if key is {@code null}
	 */
	protected BasicDefinition(String key, String documentation, Class<T> valueType, T defaultValue) {
		super(key, documentation, valueType, defaultValue);
	}

	/**
	 * Creates basic definition with default value for generic collections.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param dummyValue dummy value to get value type.
	 * @param defaultValue default value returned instead of {@code null}.
	 * @throws NullPointerException if key is {@code null}
	 */
	@SuppressWarnings("unchecked")
	protected BasicDefinition(String key, String documentation, T dummyValue, T defaultValue) {
		super(key, documentation, (Class<T>) dummyValue.getClass(), defaultValue);
	}
}