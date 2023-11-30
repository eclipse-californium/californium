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

import org.eclipse.californium.elements.Definition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Definition of configuration value.
 *
 * @param <T> type of configuration value
 * @since 3.0
 */
public abstract class DocumentedDefinition<T> extends Definition<T> {
	/**
	 * The logger.
	 * 
	 * @deprecated to be removed.
	 */
	@Deprecated
	protected static final Logger LOGGER = LoggerFactory.getLogger(DocumentedDefinition.class);

	/**
	 * Documentation for properties.
	 */
	private final String documentation;
	/**
	 * Default value.
	 */
	private final T defaultValue;

	/**
	 * Creates definition with default value.
	 * 
	 * If the configuration value is mainly used with primitive types (e.g.
	 * `int`), {@code null} causes a {@link NullPointerException} on access. To
	 * prevent that, the default value is returned instead of a {@code null}.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param valueType value type.
	 * @param defaultValue default value returned instead of {@code null}.
	 * @throws NullPointerException if key is {@code null}
	 */
	DocumentedDefinition(String key, String documentation, Class<T> valueType, T defaultValue) {
		super(key, valueType);
		this.documentation = documentation;
		this.defaultValue = defaultValue;
	}

	/**
	 * Gets type name for diagnose messages.
	 * 
	 * @return type name
	 */
	public String getTypeName() {
		return getValueType().getSimpleName();
	}

	/**
	 * Write typed value in textual presentation.
	 * 
	 * @param value value as type
	 * @return value in textual presentation
	 * @throws NullPointerException if value is {@code null}.
	 */
	public abstract String writeValue(T value);

	/**
	 * Gets documentation for properties.
	 * 
	 * @return documentation for properties
	 */
	public String getDocumentation() {
		return documentation;
	}

	/**
	 * Gets the default-value.
	 * 
	 * @return default-value, intended to be returned by
	 *         {@link Configuration#get(BasicDefinition)} instead of
	 *         {@code null}.
	 */
	public T getDefaultValue() {
		return defaultValue;
	}

	/**
	 * Reads textual presentation to type.
	 * 
	 * Applies {@link #useTrim()} before passing none-empty values to
	 * {@link #parseValue(String)}.
	 * 
	 * @param value value in textual presentation. May be {@code null}.
	 * @return value as type, or {@code null}, if provided textual value is
	 *         {@code null}, empty, or could not be parsed.
	 * @throws NullPointerException if value is {@code null}
	 * @throws IllegalArgumentException if value is empty or could not parsed.
	 */
	public T readValue(String value) {
		String errorMessage = null;
		if (value == null) {
			errorMessage = String.format("Key '%s': textual value must not be null!", getKey());
			throw new NullPointerException(errorMessage);
		}
		if (useTrim()) {
			value = value.trim();
		}
		if (value.isEmpty()) {
			errorMessage = String.format("Key '%s': textual value must not be empty!", getKey());
			throw new IllegalArgumentException(errorMessage);
		}
		try {
			T result = parseValue(value);
			return checkValue(result);
		} catch (NumberFormatException e) {
			errorMessage = String.format("Key '%s': value '%s' is no %s", getKey(), value, getTypeName());
		} catch (ValueException e) {
			errorMessage = String.format("Key '%s': %s", getKey(), e.getMessage());
		} catch (IllegalArgumentException e) {
			errorMessage = String.format("Key '%s': value '%s' %s", getKey(), value, e.getMessage());
		}
		throw new IllegalArgumentException(errorMessage);
	}

	/**
	 * Check, if value is valid.
	 * 
	 * @param value value to check
	 * @return the value to store. The provided value or the equivalent
	 *         unmodifiable value.
	 * @throws ValueException if the value is not valid, e.g. out of the
	 *             intended range.
	 */
	public T checkValue(T value) throws ValueException {
		return value;
	}

	/**
	 * Check, if value is assignable to the converter's type.
	 * 
	 * @param value value to be checked.
	 * @return {@code true}, if value is assignable, {@code false} otherwise.
	 * @throws IllegalArgumentException if value doesn't match any specific
	 *             constraints and the error message contains the details.
	 */
	protected boolean isAssignableFrom(Object value) {
		return getValueType().isInstance(value);
	}

	/**
	 * Check, if value is valid.
	 * 
	 * @param value value to check
	 * @return the value to store. Usually the provided value or 
	 * @throws ValueException if the value is not valid, e.g. out of the
	 *             intended range.
	 */
	@SuppressWarnings("unchecked")
	protected Object checkRawValue(Object value) throws ValueException {
		return checkValue((T) value);
	}

	/**
	 * Parser textual presentation to type.
	 * 
	 * @param value value in textual presentation.
	 * @return value as type
	 * @throws NullPointerException if value is {@code null}.
	 * @throws IllegalArgumentException if the textual value doesn't fit.
	 * @throws ValueException if the textual value doesn't fit and details of
	 *             the failure are available.
	 */
	protected abstract T parseValue(String value) throws ValueException;

	/**
	 * {@code true} to trim the textual value before passing it to
	 * {@link #parseValue(String)}.
	 * 
	 * @return {@code true} to trim, {@code false} to keep the delimiting
	 *         whitespace
	 */
	protected boolean useTrim() {
		return true;
	}

	@SuppressWarnings("unchecked")
	protected String write(Object value) {
		return writeValue((T) value);
	}

}
