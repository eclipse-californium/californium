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

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Collection of utility functions for {@link DocumentedDefinition}.
 *
 * @since 3.0
 */
public class DefinitionUtils {
	private static final Logger LOGGER = LoggerFactory.getLogger(DefinitionUtils.class);

	/**
	 * Get element class from array of enumeration values.
	 * 
	 * @param <E> enumeration
	 * @param list array of enumeration values
	 * @return class of enumeration
	 * @throws NullPointerException if list is {@code null}
	 * @throws IllegalArgumentException if list is empty
	 */
	@SuppressWarnings("unchecked")
	public static <E extends Enum<?>> Class<E> getClass(E[] list) {
		if (list == null) {
			throw new NullPointerException("Enums must not be null!");
		}
		if (list.length == 0) {
			throw new IllegalArgumentException("Enums must not be empty!");
		}
		return (Class<E>) list[0].getClass();
	}

	/**
	 * Convert list of strings into textual representation.
	 * 
	 * @param list list to convert
	 * @param brackets {@code true}, to add surrounding brackets, {@code false},
	 *            for no brackets.
	 * @return list as string
	 * @throws NullPointerException if list is {@code null}
	 */
	public static String toString(List<String> list, boolean brackets) {
		if (list == null) {
			throw new NullPointerException("List must not be null!");
		}
		StringBuilder message = new StringBuilder();
		if (brackets) {
			message.append('[');
		}
		for (String in : list) {
			message.append(in).append(", ");
		}
		message.setLength(message.length() - 2);
		if (brackets) {
			message.append(']');
		}
		return message.toString();
	}

	/**
	 * Convert list into string of names.
	 * 
	 * @param <E> enumeration
	 * @param list list of enumeration values
	 * @param brackets {@code true}, to add surrounding brackets, {@code false},
	 *            for no brackets.
	 * @return names as string
	 * @throws NullPointerException if list is {@code null}
	 */
	public static <E extends Enum<?>> String toNames(List<E> list, boolean brackets) {
		if (list == null) {
			throw new NullPointerException("List must not be null!");
		}
		StringBuilder message = new StringBuilder();
		if (brackets) {
			message.append('[');
		}
		for (E in : list) {
			message.append(in.name()).append(", ");
		}
		message.setLength(message.length() - 2);
		if (brackets) {
			message.append(']');
		}
		return message.toString();
	}

	/**
	 * Convert textual value into enumeration value.
	 * 
	 * @param <E> enumeration
	 * @param text value as text
	 * @param values list of enumeration values.
	 * @return enumeration value of text, or {@code null}, if not contained in
	 *         the list.
	 * @throws NullPointerException if text or values are {@code null}
	 */
	public static <E extends Enum<?>> E toValue(String text, List<E> values) {
		if (text == null) {
			throw new NullPointerException("Text must not be null!");
		}
		if (values == null) {
			throw new NullPointerException("values must not be null!");
		}
		for (E in : values) {
			if (in.name().equals(text)) {
				return in;
			}
		}
		return null;
	}

	/**
	 * Verify, if all declared {@link DocumentedDefinition} fields in the
	 * provided class are available in the configuration.
	 * 
	 * @param definitionClz class with {@code static final}
	 *            {@link DocumentedDefinition} fields.
	 * @param config configuration to check, if fields are available.
	 * @since 3.11
	 */
	public static void verify(Class<?> definitionClz, Configuration config) {
		Field[] declaredFields = definitionClz.getDeclaredFields();
		for (Field field : declaredFields) {
			int modifiers = field.getModifiers();
			if (Modifier.isStatic(modifiers) && Modifier.isFinal(modifiers)) {
				try {
					Object value = field.get(null);
					if (value instanceof DocumentedDefinition<?>) {
						DocumentedDefinition<?> definition = (DocumentedDefinition<?>) value;
						if (!config.hasDefinition(definition)) {
							LOGGER.warn("Missing definition {} in {}.", definition.getKey(),
									definitionClz.getSimpleName());
						}
					}
				} catch (IllegalArgumentException e) {
				} catch (IllegalAccessException e) {
				}
			}
		}
	}
}
