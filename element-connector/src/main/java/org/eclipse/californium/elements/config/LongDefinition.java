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
 * Long definition.
 * 
 * @since 3.0
 */
public class LongDefinition extends BasicDefinition<Long> {

	/**
	 * Minimum value.
	 * 
	 * {@code null}, if no minimum value is applied.
	 */
	private final Long minimumValue;

	/**
	 * Creates long definition.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @throws NullPointerException if key is {@code null}
	 */
	public LongDefinition(String key, String documentation) {
		super(key, documentation, Long.class, null);
		this.minimumValue = null;
	}

	/**
	 * Creates long definition with {@code null}-value.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param defaultValue default value returned instead of {@code null}.
	 * @throws NullPointerException if key is {@code null}
	 */
	public LongDefinition(String key, String documentation, Long defaultValue) {
		super(key, documentation, Long.class, defaultValue);
		this.minimumValue = null;
	}

	/**
	 * Creates long definition with {@code null}-value.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param defaultValue default value returned instead of {@code null}.
	 * @param minimumValue minimum value, or {@code null}, if no minimum value
	 *            is applied.
	 * @throws NullPointerException if key is {@code null}
	 */
	public LongDefinition(String key, String documentation, Long defaultValue, Long minimumValue) {
		super(key, documentation, Long.class, defaultValue);
		this.minimumValue = minimumValue;
	}

	@Override
	public String getTypeName() {
		return "Long";
	}

	@Override
	public String writeValue(Long value) {
		return value.toString();
	}

	@Override
	public Long checkValue(Long value) throws ValueException {
		if (minimumValue != null && value != null && value < minimumValue) {
			throw new ValueException("Value " + value + " must be not less than " + minimumValue + "!");
		}
		return value;
	}

	@Override
	protected Long parseValue(String value) {
		return Long.parseLong(value);
	}

}
