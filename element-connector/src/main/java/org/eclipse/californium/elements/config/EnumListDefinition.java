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
public class EnumListDefinition<E extends Enum<?>> extends BasicListDefinition<E> {

	private final List<E> defaultValue;
	private final Class<E> itemType;
	private final String typeName;
	private final List<E> values;
	private final String valuesDocumentation;
	private final int minimumItems;

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
		this(key, documentation, null, 0, values);
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
		this(key, documentation, defaultValue, 0, values);
	}

	/**
	 * Creates list of values out of enumeration set definition.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param defaultValue default value.
	 * @param minimumItems minimum number of items for a valid list. Used in {@link #checkValue(List)}.
	 * @param values set of supported values.
	 * @throws NullPointerException if key or values is {@code null}
	 * @throws IllegalArgumentException if values are empty or a value is
	 *             {@code null}
	 */
	@SuppressWarnings("unchecked")
	public EnumListDefinition(String key, String documentation, List<E> defaultValue, int minimumItems, E[] values) {
		super(key, documentation, null);
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
		this.itemType = (Class<E>) values[0].getClass();
		this.typeName = "List<" + itemType.getSimpleName() + ">";
		this.values = Arrays.asList(Arrays.copyOf(values, values.length));
		this.valuesDocumentation = DefinitionUtils.toNames(this.values, true);
		this.minimumItems = minimumItems;
		try {
			this.defaultValue = checkValue(defaultValue);
		} catch (ValueException e) {
			throw new IllegalArgumentException(e.getMessage());
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
	public List<E> checkValue(List<E> value) throws ValueException {
		if (value != null) {
			if (value.size() < minimumItems) {
				if (value.isEmpty()) {
					throw new ValueException("Values must not be empty!");
				} else {
					throw new ValueException("Values with " + value.size() + " items must not contain less items than "
							+ minimumItems + "!");
				}
			}
			for (E item : value) {
				if (!values.contains(item)) {
					if (itemType.isInstance(item)) {
						throw new IllegalArgumentException(item + " is not in " + valuesDocumentation);
					} else {
						throw new IllegalArgumentException(item + " is no " + itemType.getSimpleName());
					}
				}
			}
		}
		return super.checkValue(value);
	}

	@Override
	public List<E> getDefaultValue() {
		return defaultValue;
	}

	@Override
	public String getDocumentation() {
		return super.getDocumentation() + "\nList of " + valuesDocumentation + ".";
	}

	@Override
	protected boolean isAssignableFrom(Object value) {
		if (value instanceof List<?>) {
			for (Object item : (List<?>) value) {
				if (!itemType.isInstance(item)) {
					throw new IllegalArgumentException(item + " is no " + itemType.getSimpleName());
				}
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
