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
 * Float definition.
 * 
 * @since 3.0
 */
public class FloatDefinition extends BasicDefinition<Float> {

	/**
	 * Minimum value.
	 * 
	 * {@code null}, if no minimum value is applied.
	 */
	private final Float minimumValue;

	/**
	 * Creates float definition.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @throws NullPointerException if key is {@code null}
	 */
	public FloatDefinition(String key, String documentation) {
		super(key, documentation, Float.class, null);
		this.minimumValue = null;
	}

	/**
	 * Creates float definition with default value.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param defaultValue default value returned instead of {@code null}.
	 * @throws NullPointerException if key is {@code null}
	 */
	public FloatDefinition(String key, String documentation, Float defaultValue) {
		super(key, documentation, Float.class, defaultValue);
		this.minimumValue = null;
	}

	/**
	 * Creates float definition with default value.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param defaultValue default value returned instead of {@code null}.
	 * @param minimumValue minimum value, or {@code null}, if no minimum value
	 *            is applied.
	 * @throws NullPointerException if key is {@code null}
	 */
	public FloatDefinition(String key, String documentation, Float defaultValue, Float minimumValue) {
		super(key, documentation, Float.class, defaultValue);
		this.minimumValue = minimumValue;
	}

	@Override
	public String getTypeName() {
		return "Float";
	}

	@Override
	public String writeValue(Float value) {
		return value.toString();
	}

	@Override
	public Float checkValue(Float value) throws ValueException {
		if (minimumValue != null && value != null && value < minimumValue) {
			throw new ValueException("Value " + value + " must be not less than " + minimumValue + "!");
		}
		return value;
	}

	@Override
	protected Float parseValue(String value) {
		return Float.parseFloat(value);
	}
}
