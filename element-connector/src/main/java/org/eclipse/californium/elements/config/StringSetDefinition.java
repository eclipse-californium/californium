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

import java.util.Arrays;
import java.util.List;

/**
 * String set definition.
 * 
 * @since 3.0
 */
public class StringSetDefinition extends BasicDefinition<String> {

	private final String defaultValue;
	private final List<String> values;
	private final String valuesDocumentation;

	/**
	 * Creates a string set definition.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param values list of supported values. If the first value of the list is
	 *            repeated afterwards in the list, then that value is used as
	 *            default. e.g. "val2", "val1", "val2", "val3", then "val2" is
	 *            used as default value.
	 * @throws NullPointerException if key or values is {@code null}
	 * @throws IllegalArgumentException if values are empty or a value is
	 *             {@code null}
	 */
	public StringSetDefinition(String key, String documentation, String... values) {
		super(key, documentation, String.class, null);
		if (values == null) {
			throw new NullPointerException("Value set must not be null!");
		}
		if (values.length == 0) {
			throw new IllegalArgumentException("Value set must not be empty!");
		}
		for (String in : values) {
			if (in == null) {
				throw new IllegalArgumentException("Value set must not contain null!");
			}
		}
		boolean found = false;
		String defaultValue = values[0];
		for (int index = 1; index < values.length; ++index) {
			if (values[index].equals(defaultValue)) {
				found = true;
				break;
			}
		}
		if (found) {
			this.defaultValue = defaultValue;
			this.values = Arrays.asList(Arrays.copyOfRange(values, 1, values.length));
		} else {
			this.defaultValue = null;
			this.values = Arrays.asList(Arrays.copyOf(values, values.length));
		}
		this.valuesDocumentation = DefinitionUtils.toString(this.values, true);
	}

	/**
	 * Creates a string set definition.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param defaultValue default value.
	 * @param values set of supported values.
	 * @throws NullPointerException if key or values is {@code null}
	 * @throws IllegalArgumentException if values are empty or a value is
	 *             {@code null}
	 */
	public StringSetDefinition(String key, String documentation, String defaultValue, String[] values) {
		super(key, documentation, String.class, null);
		if (values == null) {
			throw new NullPointerException("Value set must not be null!");
		}
		if (values.length == 0) {
			throw new IllegalArgumentException("Value set must not be empty!");
		}
		for (String in : values) {
			if (in == null) {
				throw new IllegalArgumentException("Value set must not contain null!");
			}
		}
		this.values = Arrays.asList(Arrays.copyOf(values, values.length));
		this.valuesDocumentation = DefinitionUtils.toString(this.values, true);
		try {
			this.defaultValue = checkValue(defaultValue);
		} catch (ValueException ex) {
			throw new IllegalArgumentException(ex.getMessage());
		}
	}

	@Override
	public String getTypeName() {
		return "StringSet";
	}

	@Override
	public String writeValue(String value) {
		return value;
	}

	@Override
	public String getDocumentation() {
		return super.getDocumentation() + "\n" + valuesDocumentation + ".";
	}

	@Override
	public String getDefaultValue() {
		return defaultValue;
	}

	@Override
	public String checkValue(String value) throws ValueException {
		if (value == null || values.contains(value)) {
			return value;
		}
		throw new IllegalArgumentException(value + " is not in " + valuesDocumentation);
	}

	@Override
	protected boolean isAssignableFrom(Object value) {
		if (values.contains(value)) {
			return true;
		}
		if (super.isAssignableFrom(value)) {
			throw new IllegalArgumentException(value + " is not in " + valuesDocumentation);
		}
		return false;
	}

	@Override
	protected String parseValue(String value) throws ValueException {
		if (values.contains(value)) {
			return value;
		}
		throw new ValueException(value + " is not in " + valuesDocumentation);
	}
}
