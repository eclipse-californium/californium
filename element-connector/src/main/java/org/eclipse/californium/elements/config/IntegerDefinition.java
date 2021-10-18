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
 * Integer definition.
 * 
 * @since 3.0
 */
public class IntegerDefinition extends BasicDefinition<Integer> {

	/**
	 * Minimum value.
	 * 
	 * {@code null}, if no minimum value is applied.
	 */
	private final Integer minimumValue;

	/**
	 * Creates integer definition.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @throws NullPointerException if key is {@code null}
	 */
	public IntegerDefinition(String key, String documentation) {
		super(key, documentation, Integer.class, null);
		this.minimumValue = null;
	}

	/**
	 * Creates integer definition with default value.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param defaultValue default value returned instead of {@code null}.
	 * @throws NullPointerException if key is {@code null}
	 */
	public IntegerDefinition(String key, String documentation, Integer defaultValue) {
		super(key, documentation, Integer.class, defaultValue);
		this.minimumValue = null;
	}

	/**
	 * Creates integer definition with default value.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param defaultValue default value returned instead of {@code null}.
	 * @param minimumValue minimum value, or {@code null}, if no minimum value
	 *            is applied.
	 * @throws NullPointerException if key is {@code null}
	 */
	public IntegerDefinition(String key, String documentation, Integer defaultValue, Integer minimumValue) {
		super(key, documentation, Integer.class, defaultValue);
		this.minimumValue = minimumValue;
	}

	@Override
	public String getTypeName() {
		return "Integer";
	}

	@Override
	public String writeValue(Integer value) {
		return value.toString();
	}

	@Override
	public Integer checkValue(Integer value) throws ValueException {
		if (minimumValue != null && value != null && value < minimumValue) {
			throw new ValueException("Value " + value + " must be not less than " + minimumValue + "!");
		}
		return value;
	}

	@Override
	protected Integer parseValue(String value) {
		return Integer.parseInt(value);
	}
}
