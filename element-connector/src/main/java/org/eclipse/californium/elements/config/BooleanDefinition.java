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
 * Boolean definition.
 * 
 * @since 3.0
 */
public class BooleanDefinition extends BasicDefinition<Boolean> {

	/**
	 * Creates boolean definition.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @throws NullPointerException if key is {@code null}
	 */
	public BooleanDefinition(String key, String documentation) {
		super(key, documentation, Boolean.class, null);
	}

	/**
	 * Creates boolean definition with default value.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param defaultValue default value returned instead of {@code null}.
	 * @throws NullPointerException if key is {@code null}
	 */
	public BooleanDefinition(String key, String documentation, Boolean defaultValue) {
		super(key, documentation, Boolean.class, defaultValue);
	}

	@Override
	public String getTypeName() {
		return "Boolean";
	}

	@Override
	public String writeValue(Boolean value) {
		return value.toString();
	}

	@Override
	protected Boolean parseValue(String value) {
		return Boolean.parseBoolean(value);
	}
}
