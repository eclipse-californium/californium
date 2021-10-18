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
 * Enumeration set definition.
 *
 * @param <E> enumeration type
 * @since 3.0
 */
public class EnumDefinition<E extends Enum<?>> extends BasicDefinition<E> {

	private final E defaultValue;
	private final List<E> values;
	private final String valuesDocumentation;

	/**
	 * Creates enumeration set definition.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param values list of supported values. If the first value of the list is
	 *            repeated afterwards in the list, then that value is used as
	 *            default. e.g. SECOND, FIRST, SECOND, THIRD, then SECOND is
	 *            used as default value.
	 * @throws NullPointerException if key or values is {@code null}
	 * @throws IllegalArgumentException if values are empty or a value is
	 *             {@code null}
	 */
	@SuppressWarnings("unchecked")
	public EnumDefinition(String key, String documentation, E... values) {
		super(key, documentation, DefinitionUtils.getClass(values), null);
		if (values == null) {
			throw new NullPointerException("Enum set must not be null!");
		}
		if (values.length == 0) {
			throw new IllegalArgumentException("Enum set must not be empty!");
		}
		for (E in : values) {
			if (in == null) {
				throw new IllegalArgumentException("Enum set must not contain null!");
			}
		}
		boolean found = false;
		E defaultValue = values[0];
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
		this.valuesDocumentation = DefinitionUtils.toNames(Arrays.asList(values), true);
	}

	/**
	 * Creates enumeration set definition.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param defaultValue default value.
	 * @param values set of supported values.
	 * @throws NullPointerException if key or values is {@code null}
	 * @throws IllegalArgumentException if values are empty or a value is
	 *             {@code null}
	 */
	public EnumDefinition(String key, String documentation, E defaultValue, E[] values) {
		super(key, documentation, DefinitionUtils.getClass(values), null);
		if (values == null) {
			throw new NullPointerException("Enum set must not be null!");
		}
		if (values.length == 0) {
			throw new IllegalArgumentException("Enum set must not be empty!");
		}
		for (E in : values) {
			if (in == null) {
				throw new IllegalArgumentException("Enum set must not contain null!");
			}
		}
		this.defaultValue = defaultValue;
		this.values = Arrays.asList(Arrays.copyOf(values, values.length));
		this.valuesDocumentation = DefinitionUtils.toNames(this.values, true);
		if (defaultValue != null) {
			isAssignableFrom(defaultValue);
		}
	}

	@Override
	public String writeValue(E value) {
		return value.name();
	}

	@Override
	public String getDocumentation() {
		return super.getDocumentation() + "\n" + valuesDocumentation + ".";
	}

	@Override
	public E getDefaultValue() {
		return defaultValue;
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
	protected E parseValue(String value) throws ValueException {
		E result = DefinitionUtils.toValue(value, values);
		if (result == null) {
			throw new ValueException(value + " is not in " + valuesDocumentation);
		}
		return result;
	}
}
