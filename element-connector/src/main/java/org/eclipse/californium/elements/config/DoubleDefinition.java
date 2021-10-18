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
 * Double definition.
 * 
 * @since 3.0
 */
public class DoubleDefinition extends BasicDefinition<Double> {

	/**
	 * Minimum value.
	 * 
	 * {@code null}, if no minimum value is applied.
	 */
	private final Double minimumValue;

	/**
	 * Creates double definition.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @throws NullPointerException if key is {@code null}
	 */
	public DoubleDefinition(String key, String documentation) {
		super(key, documentation, Double.class, null);
		this.minimumValue = null;
	}

	/**
	 * Creates double definition with default value.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param defaultValue default value returned instead of {@code null}.
	 * @throws NullPointerException if key is {@code null}
	 */
	public DoubleDefinition(String key, String documentation, Double defaultValue) {
		super(key, documentation, Double.class, defaultValue);
		this.minimumValue = null;
	}

	/**
	 * Creates double definition with default value.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param defaultValue default value returned instead of {@code null}.
	 * @param minimumValue minimum value, or {@code null}, if no minimum value
	 *            is applied.
	 * @throws NullPointerException if key is {@code null}
	 */
	public DoubleDefinition(String key, String documentation, Double defaultValue, Double minimumValue) {
		super(key, documentation, Double.class, defaultValue);
		this.minimumValue = minimumValue;
	}

	@Override
	public String getTypeName() {
		return "Double";
	}

	@Override
	public String writeValue(Double value) {
		return value.toString();
	}

	@Override
	public Double checkValue(Double value) throws ValueException {
		if (minimumValue != null && value != null && value < minimumValue) {
			throw new ValueException("Value " + value + " must be not less than " + minimumValue + "!");
		}
		return value;
	}

	@Override
	protected Double parseValue(String value) {
		return Double.parseDouble(value);
	}
}
