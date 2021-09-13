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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * List of values out of enumeration set definition.
 *
 * @param <E> enumeration type
 * @since 3.0
 */
public class EnumListDefinition<E extends Enum<?>> extends BasicDefinition<List<E>> {

	private final String typeName;
	private final List<E> values;
	private final String valuesDocumentation;

	/**
	 * Creates list of values out of enumeration set definition.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param values set of supported values.
	 * @throws NullPointerException if key or values is {@code null}
	 * @throws IllegalArgumentException if values are empty or a value is
	 *             {@code null}
	 */
	public EnumListDefinition(String key, String documentation, E[] values) {
		this(key, documentation, null, values);
	}

	/**
	 * Creates list of values out of enumeration set definition.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param defaultValue default value.
	 * @param values set of supported values.
	 * @throws NullPointerException if key or values is {@code null}
	 * @throws IllegalArgumentException if values are empty or a value is
	 *             {@code null}
	 */
	public EnumListDefinition(String key, String documentation, List<E> defaultValue, E[] values) {
		super(key, documentation, new ArrayList<E>(), defaultValue);
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
		this.typeName = "List<" + values[0].getClass().getSimpleName() + ">";
		this.values = Arrays.asList(Arrays.copyOf(values, values.length));
		this.valuesDocumentation = DefinitionUtils.toNames(this.values, true);
		if (defaultValue != null) {
			isAssignableFrom(defaultValue);
		}
	}

	@Override
	public String getTypeName() {
		return typeName;
	}

	@Override
	public String writeValue(List<E> value) {
		return DefinitionUtils.toNames(value, false);
	}

	@Override
	public String getDocumentation() {
		return super.getDocumentation() + "\nList of " + valuesDocumentation + ".";
	}

	@Override
	protected boolean isAssignableFrom(Object value) {
		if (value instanceof List<?>) {
			for (Object item : (List<?>) value) {
				if (values.contains(item)) {
					continue;
				}
				if (super.isAssignableFrom(item)) {
					throw new IllegalArgumentException(item + " is not in " + valuesDocumentation);
				}
				return false;
			}
			return true;
		}
		return false;
	}

	@Override
	protected List<E> parseValue(String value) throws ValueException {
		String[] list = value.split(",");
		List<E> result = new ArrayList<>(list.length);
		for (String valueItem : list) {
			valueItem = valueItem.trim();
			E elementitem = DefinitionUtils.toValue(valueItem, values);
			if (elementitem == null) {
				throw new ValueException(valueItem + " is not in " + valuesDocumentation);
			}
			result.add(elementitem);
		}
		return result;
	}

}
