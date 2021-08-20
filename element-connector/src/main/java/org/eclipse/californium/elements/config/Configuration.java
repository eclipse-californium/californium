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
 *    Bosch IO.GmbH - initial creation (derived from former NetworkConfig
 *                         in org.eclipse.californium.core.network.config)
 ******************************************************************************/
package org.eclipse.californium.elements.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Dictionary;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.Definition;
import org.eclipse.californium.elements.Definitions;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The configuration for a Californium's components.
 * 
 * Depending on the environment, the configuration is stored and loaded from
 * properties files. When missing, Californium will generated this properties
 * file. If file access is not possible, there are variants, which are marked as
 * "WithoutFile" or variants, which use a {@link InputStream} to read the
 * properties. Please use such a variant, e.g.
 * {@link #createStandardWithoutFile()}, if you want Californium to stop
 * generating a properties file.
 * 
 * Note: For Android it's recommended to use the AssetManager and pass in the
 * InputStream to the variants using that as parameter. Alternatively you may
 * chose to use the "WithoutFile" variant and, if required, adjust the defaults
 * in your code. If the "File" variants are used, ensure, that you have the
 * android-os-permission to do so.
 * 
 * In order to use this {@link Configuration} with modules (sets of
 * {@link DocumentedDefinition}),
 * {@link #addModule(String, DefinitionsProvider)} is used to register a
 * {@link DefinitionsProvider} for such a module. When creating a new
 * {@link Configuration}, all registered {@link DefinitionsProvider} are called
 * and will fill the map of {@link DocumentedDefinition}s and values. In order
 * to ensure, that the modules are register in a early stage, a application
 * should call e.g. {@link SystemConfig#register()} of the used modules at the
 * begin. See {@link SystemConfig} as example.
 * 
 * To access the values always using the original {@link DocumentedDefinition}s
 * of a module, e.g. {@link SystemConfig#HEALTH_STATUS_INTERVAL}.
 * 
 * <code>
 *  Configuration config = Configuration.getStandard();
 *  config.set(NetworkConfig.HEALTH_STATUS_INTERVAL, 30, TimeUnit.SECONDS);
 *  ...
 *  long timeMillis = config.get(NetworkConfig.HEALTH_STATUS_INTERVAL, TimeUnit.MILLISSECONDS); 
 * </code>
 * 
 * When primitive types (e.g. {@code int}) are used to process configuration
 * values, care must be taken to define a proper default value instead of
 * returning {@code null}. The {@link DocumentedDefinition}s therefore offer
 * variants, where such a default could be provided, e.g.
 * {@link IntegerDefinition#IntegerDefinition(String, String, Integer)}.
 * 
 * For definitions a optional minimum value may be provided. That doesn't grant,
 * that the resulting configuration is proper, neither general nor for specific
 * conditions. If a minimum value is too high for your use-case, please create
 * an issue in the
 * <a href="https://github.com/eclipse/californium" target="_blank">Californium
 * github repository</a>.
 * 
 * @see SystemConfig
 * @see TcpConfig
 * @see UdpConfig
 * 
 * @since 3.0 (derived from the former NetworkConfig in
 *        org.eclipse.californium.core.network.config)
 */
public final class Configuration {

	/** The default name for the configuration. */
	public static final String DEFAULT_FILE_NAME = "Californium3.properties";
	/**
	 * The default file for the configuration.
	 */
	public static final File DEFAULT_FILE = new File(DEFAULT_FILE_NAME);

	/** The default header for a configuration file. */
	public static final String DEFAULT_HEADER = "Californium3 CoAP Properties file";

	private static final Logger LOGGER = LoggerFactory.getLogger(Configuration.class);

	/**
	 * Map of registered modules.
	 */
	private static final ConcurrentMap<String, DefinitionsProvider> MODULES = new ConcurrentHashMap<>();

	/** The standard configuration that is used if none is defined. */
	private static Configuration standard;

	/** The properties definitions. */
	private static Definitions<DocumentedDefinition<?>> definitions = new Definitions<>("Configuration");

	/** The properties. */
	private Map<String, Object> values = new HashMap<>();

	/**
	 * Value exception.
	 * 
	 * Message contains the value and details about the failure.
	 * 
	 * @see DocumentedDefinition#parseValue(String)
	 * @see DocumentedDefinition#checkValue(Object)
	 */
	public static class ValueException extends Exception {

		private static final long serialVersionUID = 3254131344341974160L;

		/**
		 * Create value exception with details description.
		 * 
		 * @param description message with value and details description
		 */
		public ValueException(String description) {
			super(description);
		}
	}

	/**
	 * Definition of configuration value.
	 *
	 * @param <T> type of configuration value
	 */
	public static abstract class DocumentedDefinition<T> extends Definition<T> {

		/**
		 * Documentation for properties.
		 */
		private final String documentation;
		/**
		 * Default value.
		 */
		private final T defaultValue;

		/**
		 * Creates definition.
		 * 
		 * @param key key for properties. Must be global unique.
		 * @param documentation documentation for properties.
		 * @param valueType value type.
		 * @throws NullPointerException if key is {@code null}
		 */
		private DocumentedDefinition(String key, String documentation, Class<T> valueType) {
			this(key, documentation, valueType, null);
		}

		/**
		 * Creates definition with default value.
		 * 
		 * If the configuration value is mainly used with primitive types (e.g.
		 * `int`), {@code null} causes a {@link NullPointerException} on access.
		 * To prevent that, the default value is returned instead of a
		 * {@code null}.
		 * 
		 * @param key key for properties. Must be global unique.
		 * @param documentation documentation for properties.
		 * @param valueType value type.
		 * @param defaultValue default value returned instead of {@code null}.
		 * @throws NullPointerException if key is {@code null}
		 */
		private DocumentedDefinition(String key, String documentation, Class<T> valueType, T defaultValue) {
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
		public T defaultValue() {
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
		 */
		public T readValue(String value) {
			if (value == null) {
				LOGGER.debug("key [{}] is undefined", getKey());
				return null;
			}
			if (useTrim()) {
				value = value.trim();
			}
			if (value.isEmpty()) {
				LOGGER.debug("key [{}] is empty", getKey());
				return null;
			}
			try {
				T result = parseValue(value);
				return checkValue(result);
			} catch (NumberFormatException e) {
				LOGGER.warn("Key '{}': value '{}' is no {}", getKey(), value, getTypeName());
			} catch (ValueException e) {
				LOGGER.warn("Key '{}': {}", getKey(), e.getMessage());
			} catch (IllegalArgumentException e) {
				LOGGER.warn("Key '{}': value '{}' {}", getKey(), value, e.getMessage());
			}
			return null;
		}

		/**
		 * Check, if value is valid.
		 * 
		 * @param value value to check
		 * @return the provided value
		 * @throws ValueException if the value is not valid, e.g. out
		 *             of the intended range.
		 */
		public T checkValue(T value) throws ValueException {
			return value;
		}

		/**
		 * Check, if value is assignable to the converter's type.
		 * 
		 * @param value value to be checked.
		 * @return {@code true}, if value is assignable, {@code false}
		 *         otherwise.
		 * @throws IllegalArgumentException if value doesn't match any
		 *             constraints
		 */
		protected abstract boolean isAssignableFrom(Object value);

		/**
		 * Parser textual presentation to type.
		 * 
		 * @param value value in textual presentation.
		 * @return value as type
		 * @throws NullPointerException if value is {@code null}.
		 * @throws IllegalArgumentException if the textual value doesn't fit.
		 * @throws ValueException if the textual value doesn't fit and
		 *             details of the failure are available.
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

	/**
	 * Basic definitions.
	 * 
	 * Used without additional units.
	 *
	 * @param <T> value type
	 * @see Configuration#get(BasicDefinition)
	 * @see Configuration#set(BasicDefinition, Object)
	 */
	public static abstract class BasicDefinition<T> extends DocumentedDefinition<T> {

		/**
		 * Creates basic definition.
		 * 
		 * @param key key for properties. Must be global unique.
		 * @param documentation documentation for properties.
		 * @param valueType value type.
		 * @throws NullPointerException if key is {@code null}
		 */
		protected BasicDefinition(String key, String documentation, Class<T> valueType) {
			super(key, documentation, valueType);
		}

		/**
		 * Creates basic definition with default value.
		 * 
		 * If the configuration value is mainly used with primitive types (e.g.
		 * `int`), {@code null} causes a {@link NullPointerException} on access.
		 * To prevent that, the default value is returned instead of a
		 * {@code null}.
		 * 
		 * @param key key for properties. Must be global unique.
		 * @param documentation documentation for properties.
		 * @param valueType value type.
		 * @param defaultValue default value returned instead of {@code null}.
		 * @throws NullPointerException if key is {@code null}
		 */
		protected BasicDefinition(String key, String documentation, Class<T> valueType, T defaultValue) {
			super(key, documentation, valueType, defaultValue);
		}

		/**
		 * Creates basic definition with default value for generic collections.
		 * 
		 * @param key key for properties. Must be global unique.
		 * @param documentation documentation for properties.
		 * @param dummyValue dummy value to get value type.
		 * @param defaultValue default value returned instead of {@code null}.
		 * @throws NullPointerException if key is {@code null}
		 */
		@SuppressWarnings("unchecked")
		protected BasicDefinition(String key, String documentation, T dummyValue, T defaultValue) {
			super(key, documentation, (Class<T>) dummyValue.getClass(), defaultValue);
		}
	}

	/**
	 * String definition.
	 */
	public static class StringDefinition extends BasicDefinition<String> {

		/**
		 * Creates string definition.
		 * 
		 * @param key key for properties. Must be global unique.
		 * @param documentation documentation for properties.
		 * @throws NullPointerException if key is {@code null}
		 */
		public StringDefinition(String key, String documentation) {
			super(key, documentation, String.class);
		}

		/**
		 * Creates string definition with default value.
		 * 
		 * @param key key for properties. Must be global unique.
		 * @param documentation documentation for properties.
		 * @param defaultValue default value returned instead of {@code null}.
		 * @throws NullPointerException if key is {@code null}
		 */
		public StringDefinition(String key, String documentation, String defaultValue) {
			super(key, documentation, String.class, defaultValue);
		}

		@Override
		public String getTypeName() {
			return "String";
		}

		@Override
		public String writeValue(String value) {
			return value;
		}

		@Override
		protected boolean useTrim() {
			return false;
		}

		@Override
		protected boolean isAssignableFrom(Object value) {
			return value instanceof String;
		}

		@Override
		protected String parseValue(String value) {
			return value;
		}

	}

	/**
	 * String set definition.
	 */
	public static class StringSetDefinition extends BasicDefinition<String> {

		private final String defaultValue;
		private final String[] values;
		private final String valuesDocumentation;

		/**
		 * Creates a string set definition.
		 * 
		 * @param key key for properties. Must be global unique.
		 * @param documentation documentation for properties.
		 * @param values list of supported values. If the first value of the
		 *            list is repeated afterwards in the list, then that value
		 *            is used as default. e.g. "val2", "val1", "val2", "val3",
		 *            then "val2" is used as default value.
		 * @throws NullPointerException if key or values is {@code null}
		 * @throws IllegalArgumentException if values are empty or a value is
		 *             {@code null}
		 */
		public StringSetDefinition(String key, String documentation, String... values) {
			super(key, documentation, String.class);
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
				this.values = Arrays.copyOfRange(values, 1, values.length);
			} else {
				this.defaultValue = null;
				this.values = Arrays.copyOf(values, values.length);
			}
			this.valuesDocumentation = toList(Arrays.asList(values), true);
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
			super(key, documentation, String.class);
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
			this.defaultValue = defaultValue;
			this.values = Arrays.copyOf(values, values.length);
			this.valuesDocumentation = toList(Arrays.asList(values), true);
			if (defaultValue != null) {
				isAssignableFrom(defaultValue);
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
		public String defaultValue() {
			return defaultValue;
		}

		@Override
		protected boolean isAssignableFrom(Object value) {
			if (value instanceof String) {
				for (String in : values) {
					if (in.equals(value)) {
						return true;
					}
				}
				throw new IllegalArgumentException(value + " is not in " + valuesDocumentation);
			}
			return false;
		}

		@Override
		protected String parseValue(String value) throws ValueException {
			for (String in : values) {
				if (in.equals(value)) {
					return value;
				}
			}
			throw new ValueException(value + " is not in " + valuesDocumentation);
		}
	}

	/**
	 * Enumeration set definition.
	 *
	 * @param <E> enumeration type
	 */
	public static class EnumDefinition<E extends Enum<?>> extends BasicDefinition<E> {

		private final E defaultValue;
		private final E[] values;
		private final String valuesDocumentation;

		/**
		 * Creates enumeration set definition.
		 * 
		 * @param key key for properties. Must be global unique.
		 * @param documentation documentation for properties.
		 * @param values list of supported values. If the first value of the
		 *            list is repeated afterwards in the list, then that value
		 *            is used as default. e.g. SECOND, FIRST, SECOND, THIRD,
		 *            then SECOND is used as default value.
		 * @throws NullPointerException if key or values is {@code null}
		 * @throws IllegalArgumentException if values are empty or a value is
		 *             {@code null}
		 */
		@SuppressWarnings("unchecked")
		public EnumDefinition(String key, String documentation, E... values) {
			super(key, documentation, Configuration.getClass(values));
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
				this.values = Arrays.copyOfRange(values, 1, values.length);
			} else {
				this.defaultValue = null;
				this.values = Arrays.copyOf(values, values.length);
			}
			this.valuesDocumentation = toNameList(Arrays.asList(values), true);
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
			super(key, documentation, Configuration.getClass(values));
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
			this.values = Arrays.copyOf(values, values.length);
			this.valuesDocumentation = toNameList(Arrays.asList(values), true);
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
		public E defaultValue() {
			return defaultValue;
		}

		@Override
		protected boolean isAssignableFrom(Object value) {
			return Configuration.isAssignableFrom(valuesDocumentation, value, values);
		}

		@Override
		protected E parseValue(String value) throws ValueException {
			return parse(valuesDocumentation, value, values);
		}
	}

	/**
	 * List of values out of enumeration set definition.
	 *
	 * @param <E> enumeration type
	 */
	public static class EnumListDefinition<E extends Enum<?>> extends BasicDefinition<List<E>> {

		private final String typeName;
		private final E[] values;
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
			this.values = Arrays.copyOf(values, values.length);
			this.valuesDocumentation = toNameList(Arrays.asList(values), true);
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
			return toNameList(value, false);
		}

		@Override
		public String getDocumentation() {
			return super.getDocumentation() + "\nList of " + valuesDocumentation + ".";
		}

		@Override
		protected boolean isAssignableFrom(Object value) {
			if (value instanceof List<?>) {
				for (Object item : (List<?>) value) {
					if (!Configuration.isAssignableFrom(valuesDocumentation, item, values)) {
						return false;
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
			for (String in : list) {
				E item = parse(valuesDocumentation, in.trim(), values);
				result.add(item);
			}
			return result;
		}

	}

	/**
	 * Boolean definition.
	 */
	public static class BooleanDefinition extends BasicDefinition<Boolean> {

		/**
		 * Creates boolean definition.
		 * 
		 * @param key key for properties. Must be global unique.
		 * @param documentation documentation for properties.
		 * @throws NullPointerException if key is {@code null}
		 */
		public BooleanDefinition(String key, String documentation) {
			super(key, documentation, Boolean.class);
		}

		/**
		 * Creates boolean definition with default value.
		 * 
		 * @param key key for properties. Must be global unique.
		 * @param documentation documentation for properties.
		 * @param defaultValue default value returned instead of {@code null}.
		 * @throws NullPointerException if key is {@code null}
		 */
		public BooleanDefinition(String key, String documentation, Boolean defaultValue) {
			super(key, documentation, Boolean.class, defaultValue);
		}

		@Override
		public String getTypeName() {
			return "Boolean";
		}

		@Override
		public String writeValue(Boolean value) {
			return value.toString();
		}

		@Override
		protected boolean isAssignableFrom(Object value) {
			return value instanceof Boolean;
		}

		@Override
		protected Boolean parseValue(String value) {
			return Boolean.parseBoolean(value);
		}
	}

	/**
	 * Integer definition.
	 */
	public static class IntegerDefinition extends BasicDefinition<Integer> {

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
			super(key, documentation, Integer.class);
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
		 * @param minimumValue minimum value, or {@code null}, if no minimum
		 *            value is applied.
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
				throw new ValueException ("Value " + value + " must be not less than " + minimumValue + "!");
			}
			return value;
		}

		@Override
		protected boolean isAssignableFrom(Object value) {
			return value instanceof Integer;
		}

		@Override
		protected Integer parseValue(String value) {
			return Integer.parseInt(value);
		}
	}

	/**
	 * Long definition.
	 */
	public static class LongDefinition extends BasicDefinition<Long> {

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
			super(key, documentation, Long.class);
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
		 * @param minimumValue minimum value, or {@code null}, if no minimum
		 *            value is applied.
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
		protected boolean isAssignableFrom(Object value) {
			return value instanceof Long;
		}

		@Override
		protected Long parseValue(String value) {
			return Long.parseLong(value);
		}

	}

	/**
	 * Float definition.
	 */
	public static class FloatDefinition extends BasicDefinition<Float> {

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
			super(key, documentation, Float.class);
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
		 * @param minimumValue minimum value, or {@code null}, if no minimum
		 *            value is applied.
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
		protected boolean isAssignableFrom(Object value) {
			return value instanceof Float;
		}

		@Override
		protected Float parseValue(String value) {
			return Float.parseFloat(value);
		}
	}

	/**
	 * Double definition.
	 */
	public static class DoubleDefinition extends BasicDefinition<Double> {

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
			super(key, documentation, Double.class);
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
		 * @param minimumValue minimum value, or {@code null}, if no minimum
		 *            value is applied.
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
		protected boolean isAssignableFrom(Object value) {
			return value instanceof Double;
		}

		@Override
		protected Double parseValue(String value) {
			return Double.parseDouble(value);
		}
	}

	/**
	 * Time definition.
	 * 
	 * Access always with {@link TimeUnit}.
	 * 
	 * @see Configuration#set(TimeDefinition, int, TimeUnit)
	 * @see Configuration#set(TimeDefinition, Long, TimeUnit)
	 * @see Configuration#get(TimeDefinition, TimeUnit)
	 * @see Configuration#getTimeAsInt(TimeDefinition, TimeUnit)
	 */
	public static class TimeDefinition extends DocumentedDefinition<Long> {

		/**
		 * Creates time definition.
		 * 
		 * @param key key for properties. Must be global unique.
		 * @param documentation documentation for properties.
		 * @throws NullPointerException if key is {@code null}
		 */
		public TimeDefinition(String key, String documentation) {
			super(key, documentation, Long.class);
		}

		/**
		 * Creates time definition with default value.
		 * 
		 * @param key key for properties. Must be global unique.
		 * @param documentation documentation for properties.
		 * @param defaultValue default value returned instead of {@code null}.
		 * @param unit time unit of value
		 * @throws NullPointerException if key or unit is {@code null}
		 */
		public TimeDefinition(String key, String documentation, long defaultValue, TimeUnit unit) {
			super(key, documentation, Long.class, TimeUnit.NANOSECONDS.convert(defaultValue, unit));
		}

		@Override
		public String getTypeName() {
			return "Time";
		}

		@Override
		public String writeValue(Long value) {
			TimeUnit unit = TimeUnit.MILLISECONDS;
			if (value != 0) {
				unit = TimeUnit.NANOSECONDS;
				if (value % 1000L == 0) {
					unit = TimeUnit.MICROSECONDS;
					value /= 1000L;
					if (value % 1000L == 0) {
						unit = TimeUnit.MILLISECONDS;
						value /= 1000L;
						if (value % 1000L == 0) {
							unit = TimeUnit.SECONDS;
							value /= 1000L;
							if (value % 60L == 0) {
								unit = TimeUnit.MINUTES;
								value /= 60L;
								if (value % 60L == 0) {
									unit = TimeUnit.HOURS;
									value /= 60L;
									if (value % 24L == 0) {
										unit = TimeUnit.DAYS;
										value /= 24L;
									}
								}
							}
						}
					}
				}
			}
			return value + "[" + getTimeUnitAsText(unit) + "]";
		}

		@Override
		public Long checkValue(Long value) throws ValueException {
			if (value != null && value < 0) {
				throw new ValueException("Time " + value + " must be not less than 0!");
			}
			return value;
		}

		@Override
		protected boolean isAssignableFrom(Object value) {
			return value instanceof Long;
		}

		@Override
		protected Long parseValue(String value) throws ValueException {
			TimeUnit valueUnit = TimeUnit.MILLISECONDS;
			String num = value;
			int pos = value.indexOf('[');
			if (pos >= 0) {
				int end = value.indexOf(']');
				if (pos < end) {
					num = value.substring(0, pos).trim();
					String textUnit = value.substring(pos + 1, end).trim();
					valueUnit = getTimeUnit(textUnit);
					if (valueUnit == null) {
						throw new ValueException(textUnit + " unknown unit!");
					}
				} else {
					throw new ValueException(value + " doesn't match value[unit]!");
				}
			} else {
				char last = value.charAt(value.length() - 1);
				if (!Character.isDigit(last)) {
					TimeUnit unit = getTimeUnit(value);
					if (unit != null) {
						valueUnit = unit;
						num = value.substring(0, value.length() - getTimeUnitAsText(unit).length()).trim();
					}
				}
			}
			long time = Long.parseLong(num);
			return TimeUnit.NANOSECONDS.convert(time, valueUnit);
		}

		/**
		 * Gets time unit as text.
		 * 
		 * @param unit time unit
		 * @return time unit as text
		 */
		public static String getTimeUnitAsText(TimeUnit unit) {
			switch (unit) {
			case NANOSECONDS:
				return "ns";
			case MICROSECONDS:
				return "ys";
			case MILLISECONDS:
				return "ms";
			case SECONDS:
				return "s";
			case MINUTES:
				return "min";
			case HOURS:
				return "h";
			case DAYS:
				return "d";
			}
			return "";
		}

		/**
		 * Gets time unit
		 * 
		 * @param timeUnitText textual time unit
		 * @return time unit, {@code null}, if not supported
		 */
		public static TimeUnit getTimeUnit(String timeUnitText) {
			String matchUnitText = "";
			TimeUnit matchingUnit = null;
			for (TimeUnit unit : TimeUnit.values()) {
				String text = getTimeUnitAsText(unit);
				if (!text.isEmpty()) {
					if (text.equals(timeUnitText)) {
						return unit;
					} else if (timeUnitText.endsWith(text) && text.length() > matchUnitText.length()) {
						matchingUnit = unit;
						matchUnitText = text;
					}
				}
			}
			return matchingUnit;
		}
	}

	/**
	 * Handler for (custom) setup of configuration
	 * {@link DocumentedDefinition}s.
	 */
	public interface DefinitionsProvider {

		/**
		 * Apply definitions.
		 * 
		 * Use {@link Configuration#set(BasicDefinition, Object)},
		 * {@link Configuration#set(TimeDefinition, int, TimeUnit)} or
		 * {@link Configuration#set(TimeDefinition, Long, TimeUnit)} to apply
		 * the definitions.
		 * 
		 * @param config configuration to be apply the definitions.
		 */
		void applyDefinitions(Configuration config);
	}

	private static String toList(List<String> list, boolean brackets) {
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

	@SuppressWarnings("unchecked")
	private static <E extends Enum<?>> Class<E> getClass(E[] list) {
		if (list == null) {
			throw new NullPointerException("Enums must not be null!");
		}
		if (list.length == 0) {
			throw new IllegalArgumentException("Enums must not be empty!");
		}
		return (Class<E>) list[0].getClass();
	}

	private static <E extends Enum<?>> String toNameList(List<E> list, boolean brackets) {
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

	private static <E extends Enum<?>> boolean isAssignableFrom(String valuesDocumentation, Object value,
			@SuppressWarnings("unchecked") E... values) {
		Class<?> clz = values[0].getClass();
		if (clz.isInstance(value)) {
			for (E in : values) {
				if (in.equals(value)) {
					return true;
				}
			}
			throw new IllegalArgumentException(value + " is not in " + valuesDocumentation);
		}
		return false;
	}

	private static <E extends Enum<?>> E parse(String valuesDocumentation, String text,
			@SuppressWarnings("unchecked") E... values) throws ValueException {
		for (E in : values) {
			if (in.name().equals(text)) {
				return in;
			}
		}
		throw new ValueException(text + " is not in " + valuesDocumentation);
	}

	/**
	 * Apply custom definitions provider.
	 * 
	 * If the custom definitions provider registers new modules (explicit or
	 * implicit), the definitions provider of the new modules are also applied.
	 * 
	 * @param configuration configuration
	 * @param customProvider custom definitions provider.
	 */
	private static void apply(Configuration configuration, DefinitionsProvider customProvider) {
		if (customProvider != null) {
			ConcurrentMap<String, DefinitionsProvider> before = new ConcurrentHashMap<>(MODULES);
			customProvider.applyDefinitions(configuration);
			if (before.size() < MODULES.size()) {
				Set<String> set = MODULES.keySet();
				set.removeAll(before.keySet());
				for (String newModule : set) {
					MODULES.get(newModule).applyDefinitions(configuration);
				}
				customProvider.applyDefinitions(configuration);
			}
		}
	}

	/**
	 * Add definitions provider for module.
	 * 
	 * @param module unique name of module
	 * @param definitionsProvider definitions provider of module
	 * @throws NullPointerException if any parameter is {@code null}
	 * @throws IllegalArgumentException if the module name is empty or a
	 *             different definitions provider is already registered with
	 *             that module name.
	 */
	public static void addModule(String module, DefinitionsProvider definitionsProvider) {
		if (module == null) {
			throw new NullPointerException("Module must not be null!");
		}
		if (module.isEmpty()) {
			throw new IllegalArgumentException("Module name must not be empty!");
		}
		if (definitionsProvider == null) {
			throw new NullPointerException("DefinitionsProvider must not be null!");
		}
		if (MODULES.putIfAbsent(module, definitionsProvider) != null) {
			throw new IllegalArgumentException("Module " + module + " already registered!");
		}
		LOGGER.info("add {}", module);
	}

	/**
	 * Gives access to the standard configuration.
	 * 
	 * When a new endpoint or server is created without a specific
	 * configuration, it will use this standard configuration.
	 * 
	 * Apply all {@link DefinitionsProvider} of registered modules.
	 * 
	 * For Android, please ensure, that either
	 * {@link Configuration#setStandard(Configuration)},
	 * {@link Configuration#createStandardWithoutFile()}, or
	 * {@link Configuration#createStandardFromStream(InputStream)} is called
	 * before!
	 * 
	 * @return the standard configuration
	 * @see #addModule(String, DefinitionsProvider)
	 */
	public static Configuration getStandard() {
		synchronized (Configuration.class) {
			if (standard == null)
				createStandardWithFile(DEFAULT_FILE);
		}
		return standard;
	}

	/**
	 * Sets the standard configuration.
	 *
	 * @param standard the new standard configuration
	 */
	public static void setStandard(Configuration standard) {
		Configuration.standard = standard;
	}

	/**
	 * Creates the standard configuration without reading it or writing it to a
	 * file.
	 *
	 * Apply all {@link DefinitionsProvider} of registered modules.
	 * 
	 * @return the standard configuration
	 * @see #addModule(String, DefinitionsProvider)
	 */
	public static Configuration createStandardWithoutFile() {
		LOGGER.info("Creating standard configuration properties without a file");
		standard = new Configuration();
		return standard;
	}

	/**
	 * Creates the standard configuration from stream.
	 *
	 * Support environments without file access.
	 * 
	 * Apply all {@link DefinitionsProvider} of registered modules.
	 * 
	 * @param inStream input stream to read properties.
	 * @return the standard configuration
	 * @throws NullPointerException if the in stream is {@code null}.
	 * @see #addModule(String, DefinitionsProvider)
	 */
	public static Configuration createStandardFromStream(InputStream inStream) {
		standard = createFromStream(inStream, null);
		return standard;
	}

	/**
	 * Creates a configuration from stream.
	 *
	 * Support environments without file access.
	 * 
	 * Apply all {@link DefinitionsProvider} of registered modules.
	 * 
	 * @param inStream input stream to read properties.
	 * @param customProvider custom definitions handler. May be {@code null}.
	 * @return the configuration
	 * @throws NullPointerException if the in stream is {@code null}.
	 * @see #addModule(String, DefinitionsProvider)
	 */
	public static Configuration createFromStream(InputStream inStream, DefinitionsProvider customProvider) {
		LOGGER.info("Creating configuration properties from stream");
		Configuration standard = new Configuration();
		apply(standard, customProvider);
		try {
			standard.load(inStream);
		} catch (IOException e) {
			LOGGER.warn("cannot load properties from stream: {}", e.getMessage());
		}
		return standard;
	}

	/**
	 * Creates the standard configuration with a file.
	 * 
	 * If the provided file exists, the configuration reads the properties from
	 * this file. Otherwise it creates the file.
	 * 
	 * Apply all {@link DefinitionsProvider} of registered modules.
	 *
	 * For Android, please use
	 * {@link Configuration#createStandardWithoutFile()}, or
	 * {@link Configuration#createStandardFromStream(InputStream)}.
	 * 
	 * @param file the configuration file
	 * @return the standard configuration
	 * @throws NullPointerException if the file is {@code null}.
	 * @see #addModule(String, DefinitionsProvider)
	 */
	public static Configuration createStandardWithFile(File file) {
		standard = createWithFile(file, DEFAULT_HEADER, null);
		return standard;
	}

	/**
	 * Creates a configuration with a file.
	 * 
	 * If the provided file exists, the configuration reads the properties from
	 * this file. Otherwise it creates the file with the provided header.
	 * 
	 * Apply all {@link DefinitionsProvider} of registered modules.
	 * 
	 * For Android, please use {@link Configuration#Configuration()}, and load
	 * the values using {@link Configuration#load(InputStream)} or adjust the in
	 * your code.
	 * 
	 * @param file the configuration file
	 * @param header The header to write to the top of the file.
	 * @param customProvider custom definitions handler. May be {@code null}.
	 * @return the configuration
	 * @throws NullPointerException if the file or header is {@code null}.
	 * @see #addModule(String, DefinitionsProvider)
	 */
	public static Configuration createWithFile(File file, String header, DefinitionsProvider customProvider) {
		if (file == null) {
			throw new NullPointerException("file must not be null!");
		}
		Configuration configuration = new Configuration();
		apply(configuration, customProvider);
		if (file.exists()) {
			configuration.load(file);
		} else {
			configuration.store(file, header);
		}
		return configuration;
	}

	/**
	 * Instantiates a new configuration and sets the value definitions using the
	 * registered module's {@link DefinitionsProvider}s.
	 * 
	 * @see #addModule(String, DefinitionsProvider)
	 */
	public Configuration() {
		for (DefinitionsProvider handler : MODULES.values()) {
			handler.applyDefinitions(this);
		}
	}

	/**
	 * Instantiates a new configuration and sets the values and from the
	 * provided configuration.
	 * 
	 * @param config configuration to copy
	 */
	public Configuration(Configuration config) {
		this.values.putAll(config.values);
	}

	/**
	 * Loads properties from a file.
	 * 
	 * Requires to add the {@link DocumentedDefinition}s of the modules ahead.
	 *
	 * For Android, please use {@link Configuration#load(InputStream)}.
	 * 
	 * @param file the file
	 * @throws NullPointerException if the file is {@code null}.
	 * @see #addModule(String, DefinitionsProvider)
	 */
	public void load(final File file) {
		if (file == null) {
			throw new NullPointerException("file must not be null");
		} else {
			LOGGER.info("loading properties from file {}", file.getAbsolutePath());
			try (InputStream inStream = new FileInputStream(file)) {
				load(inStream);
			} catch (IOException e) {
				LOGGER.warn("cannot load properties from file {}: {}", file.getAbsolutePath(), e.getMessage());
			}
		}
	}

	/**
	 * Loads properties from a input stream.
	 * 
	 * Requires to add the {@link DocumentedDefinition}s of the modules ahead.
	 *
	 * @param inStream the input stream
	 * @throws NullPointerException if the inStream is {@code null}.
	 * @throws IOException if an error occurred when reading from the input
	 *             stream
	 * @see #addModule(String, DefinitionsProvider)
	 */
	public void load(final InputStream inStream) throws IOException {
		if (inStream == null) {
			throw new NullPointerException("input stream must not be null");
		}
		Properties properties = new Properties();
		properties.load(inStream);
		add(properties);
	}

	/**
	 * Add properties.
	 * 
	 * Requires to add the {@link DocumentedDefinition}s of the modules ahead.
	 * Apply conversion defined by that {@link DocumentedDefinition}s.
	 * 
	 * @param properties properties to convert and add
	 * @throws NullPointerException if properties is {@code null}.
	 * @see #addModule(String, DefinitionsProvider)
	 */
	public void add(Properties properties) {
		if (properties == null) {
			throw new NullPointerException("properties must not be null!");
		}
		for (Object k : properties.keySet()) {
			if (k instanceof String) {
				String key = (String) k;
				DocumentedDefinition<?> definition = definitions.get(key);
				if (definition != null) {
					String text = properties.getProperty(key);
					Object value = definition.readValue(text);
					values.put(key, value);
				} else {
					LOGGER.warn("Ignore {}, no configuration definition available!", key);
				}
			}
		}
	}

	/**
	 * Add dictionary.
	 * 
	 * Requires to add the {@link DocumentedDefinition}s of the modules ahead.
	 * Apply conversion defined by that {@link DocumentedDefinition}s to String
	 * entries. Entries of other types are added, if
	 * {@link DocumentedDefinition#isAssignableFrom(Object)} returns
	 * {@code true}.
	 * 
	 * @param dictionary dictionary to convert and add
	 * @throws NullPointerException if dictionary is {@code null}.
	 * @see #addModule(String, DefinitionsProvider)
	 */
	public void add(Dictionary<String, ?> dictionary) {
		if (dictionary == null) {
			throw new NullPointerException("dictionary must not be null!");
		}
		for (Enumeration<String> allKeys = dictionary.keys(); allKeys.hasMoreElements();) {
			String key = allKeys.nextElement();
			Object value = dictionary.get(key);
			DocumentedDefinition<?> definition = definitions.get(key);
			if (definition != null) {
				if (value instanceof String) {
					value = definition.readValue((String) value);
				} else if (value != null && !definition.isAssignableFrom(value)) {
					throw new IllegalArgumentException(
							value.getClass().getSimpleName() + " is not a " + definition.getTypeName());
				}
				values.put(key, value);
			} else {
				LOGGER.warn("Ignore {}, no configuration definition available!", key);
			}
		}
	}

	/**
	 * Stores the configuration to a file.
	 * 
	 * Not intended for Android!
	 *
	 * @param file The file to write to.
	 * @throws NullPointerException if the file is {@code null}.
	 */
	public void store(final File file) {
		store(file, DEFAULT_HEADER);
	}

	/**
	 * Stores the configuration to a file using a given header.
	 * 
	 * Not intended for Android!
	 * 
	 * @param file The file to write to.
	 * @param header The header to write to the top of the file.
	 * @throws NullPointerException if the file or header is {@code null}.
	 */
	public void store(File file, String header) {
		if (file == null) {
			throw new NullPointerException("file must not be null");
		} else {
			try (FileOutputStream out = new FileOutputStream(file)) {
				store(out, header, file.getAbsolutePath());
			} catch (IOException e) {
				LOGGER.warn("cannot write properties to {}: {}", file.getAbsolutePath(), e.getMessage());
			}
		}
	}

	/**
	 * Stores the configuration to a stream using a given header.
	 * 
	 * @param out stream to store
	 * @param header header to use
	 * @param resourceName resource name of store for logging, if available. May
	 *            be {@code null}, if not.
	 * @throws NullPointerException if out stream or header is {@code null}
	 */
	public void store(OutputStream out, String header, String resourceName) {
		if (out == null) {
			throw new NullPointerException("output stream must not be null!");
		}
		if (header == null) {
			throw new NullPointerException("header must not be null!");
		}
		if (resourceName != null) {
			LOGGER.info("writing properties to {}", resourceName);
		}
		try {
			Set<String> modules = MODULES.keySet();
			List<String> generalKeys = new ArrayList<>();
			List<String> moduleKeys = new ArrayList<>();
			for (String key : values.keySet()) {
				boolean add = true;
				for (String head : modules) {
					if (key.startsWith(head)) {
						moduleKeys.add(key);
						add = false;
						break;
					}
				}
				if (add) {
					generalKeys.add(key);
				}
			}
			Collections.sort(generalKeys);
			Collections.sort(moduleKeys);
			try (OutputStreamWriter fileWriter = new OutputStreamWriter(out)) {
				String line = PropertiesUtility.normalizeComments(header);
				fileWriter.write(line);
				fileWriter.write(StringUtil.lineSeparator());
				line = PropertiesUtility.normalizeComments(new Date().toString());
				fileWriter.write(line);
				fileWriter.write(StringUtil.lineSeparator());
				fileWriter.write("#");
				fileWriter.write(StringUtil.lineSeparator());
				for (String key : generalKeys) {
					writeProperty(key, fileWriter);
				}
				for (String key : moduleKeys) {
					writeProperty(key, fileWriter);
				}
			}
		} catch (IOException e) {
			if (resourceName != null) {
				LOGGER.warn("cannot write properties to {}: {}", resourceName, e.getMessage());
			} else {
				LOGGER.warn("cannot write properties: {}", e.getMessage());
			}
		}
	}

	/**
	 * Write single property.
	 * 
	 * If {@link DocumentedDefinition} contains a
	 * {@link DocumentedDefinition#getDocumentation()}, then first write that
	 * documentation as comment.
	 * 
	 * @param key key of definition.
	 * @param writer writer to write property
	 * @throws IOException if an i/o-error occurred
	 * @throws IllegalArgumentException if no entry for key is found
	 * @see PropertiesUtility#normalize(String, boolean)
	 * @see PropertiesUtility#normalizeComments(String)
	 */
	private void writeProperty(String key, Writer writer) throws IOException {
		DocumentedDefinition<? extends Object> definition = definitions.get(key);
		if (definition == null) {
			throw new IllegalArgumentException("Definition for " + key + " not found!");
		}
		StringBuilder documentation = new StringBuilder();
		String docu = definition.getDocumentation();
		if (docu != null) {
			documentation.append(docu);
		}
		Object defaultValue = definition.defaultValue();
		if (defaultValue != null) {
			String defaultText = definition.write(defaultValue);
			if (defaultText != null) {
				if (documentation.length() > 0) {
					documentation.append('\n');
				}
				documentation.append("Default: ").append(defaultText);
			}
		}
		if (documentation.length() > 0) {
			String line = PropertiesUtility.normalizeComments(documentation.toString());
			writer.write(line);
			writer.write(StringUtil.lineSeparator());
		}
		String encoded = PropertiesUtility.normalize(key, true);
		writer.write(encoded);
		writer.write('=');
		Object value = values.get(key);
		if (value != null) {
			encoded = PropertiesUtility.normalize(definition.write(value), false);
			writer.write(encoded);
		}
		writer.write(StringUtil.lineSeparator());
	}

	/**
	 * Associates the specified textual value with the specified definition.
	 * 
	 * @param <T> value type
	 * @param definition the value definition
	 * @param value the textual value
	 * @return the configuration for chaining
	 * @throws NullPointerException if the definition is {@code null}
	 * @throws IllegalArgumentException if a different definition is already
	 *             available for the key of the provided definition.
	 */
	public <T> Configuration setFromText(DocumentedDefinition<T> definition, String value) {
		setInternal(definition, null, value);
		return this;
	}

	public <T> String getAsText(DocumentedDefinition<T> definition) {
		T value = getInternal(definition);
		return definition.writeValue(value);
	}

	/**
	 * Associates the specified value with the specified definition.
	 * 
	 * @param <T> value type
	 * @param definition the value definition
	 * @param value the value
	 * @return the configuration for chaining
	 * @throws NullPointerException if the definition is {@code null}
	 * @throws IllegalArgumentException if a different definition is already
	 *             available for the key of the provided definition.
	 */
	public <T> Configuration set(BasicDefinition<T> definition, T value) {
		setInternal(definition, value, null);
		return this;
	}

	/**
	 * Associates the specified list of values with the specified definition.
	 * 
	 * @param <T> item value type
	 * @param definition the value definition
	 * @param values the list of values
	 * @return the configuration for chaining
	 * @throws NullPointerException if the definition or values is {@code null}
	 * @throws IllegalArgumentException if a different definition is already
	 *             available for the key of the provided definition or the
	 *             values are empty.
	 */
	public <T extends Enum<?>> Configuration setList(EnumListDefinition<T> definition,
			@SuppressWarnings("unchecked") T... values) {
		if (values == null) {
			throw new NullPointerException("Values must not be null!");
		}
		if (values.length == 0) {
			throw new IllegalArgumentException("Values must not be empty!");
		}
		setInternal(definition, Arrays.asList(values), null);
		return this;
	}

	/**
	 * Gets the associated value.
	 * 
	 * @param <T> value type
	 * @param definition the value definition
	 * @return the value
	 * @throws NullPointerException if the definition is {@code null}
	 * @throws IllegalArgumentException if a different definition is already
	 *             available for the key of the provided definition.
	 */
	public <T> T get(BasicDefinition<T> definition) {
		return getInternal(definition);
	}

	/**
	 * Associates the specified time value with the specified definition.
	 * 
	 * @param definition the value definition
	 * @param value the value
	 * @param unit the time unit of the value
	 * @return the configuration for chaining
	 * @throws NullPointerException if the definition or unit is {@code null}
	 * @throws IllegalArgumentException if a different definition is already
	 *             available for the key of the provided definition. Or the
	 *             provided value is less than {@code 0}
	 */
	public Configuration set(TimeDefinition definition, Long value, TimeUnit unit) {
		if (unit == null) {
			throw new NullPointerException("unit must not be null");
		}
		if (value != null) {
			value = TimeUnit.NANOSECONDS.convert(value, unit);
		}
		setInternal(definition, value, null);
		return this;
	}

	/**
	 * Associates the specified time value with the specified definition.
	 * 
	 * @param definition the value definition
	 * @param value the value
	 * @param unit the time unit of the value
	 * @return the configuration for chaining
	 * @throws NullPointerException if the definition or unit is {@code null}
	 * @throws IllegalArgumentException if a different definition is already
	 *             available for the key of the provided definition. Or the
	 *             provided value is less than {@code 0}
	 */
	public Configuration set(TimeDefinition definition, int value, TimeUnit unit) {
		return set(definition, (long) value, unit);
	}

	/**
	 * Gets the associated time value.
	 * 
	 * @param definition the value definition
	 * @param unit the wanted unit
	 * @return the value in the provided units
	 * @throws NullPointerException if the definition or unit is {@code null}
	 * @throws IllegalArgumentException if a different definition is already
	 *             available for the key of the provided definition.
	 */
	public Long get(TimeDefinition definition, TimeUnit unit) {
		Long time = getInternal(definition);
		if (unit == null) {
			throw new NullPointerException("unit must not be null");
		}
		if (time != null) {
			time = unit.convert(time, TimeUnit.NANOSECONDS);
		}
		return time;
	}

	/**
	 * Gets the associated time value as {@code int}.
	 * 
	 * <b>Note:</b> Please provide a {@code null}-value to the
	 * {@link TimeDefinition} using
	 * {@link TimeDefinition#TimeDefinition(String, String, long, TimeUnit)}.
	 * 
	 * @param definition the value definition
	 * @param unit the wanted unit
	 * @return the value in the provided units as {@code int}
	 * @throws NullPointerException if the definition or unit is {@code null}
	 * @throws IllegalArgumentException if a different definition is already
	 *             available for the key of the provided definition. Or the
	 *             resulting value exceeds the {@code int} range.
	 */
	public int getTimeAsInt(TimeDefinition definition, TimeUnit unit) {
		Long time = get(definition, unit);
		if (time != null) {
			if (time > Integer.MAX_VALUE) {
				throw new IllegalArgumentException(time + " doesn't fit to int (Max. " + Integer.MAX_VALUE + ")!");
			} else if (time < Integer.MIN_VALUE) {
				throw new IllegalArgumentException(time + " doesn't fit to int (Min. " + Integer.MIN_VALUE + ")!");
			}
			return time.intValue();
		} else {
			return 0;
		}
	}

	/**
	 * Gets the associated value.
	 * 
	 * @param <T> type of the value
	 * @param definition definition of the value.
	 * @return the associated value. if {@code null}, return the
	 *         {@link DocumentedDefinition#defaultValue()} instead.
	 * @throws NullPointerException if the definition is {@code null}
	 * @throws IllegalArgumentException if a different definition is already
	 *             available for the key of the provided definition.
	 */
	@SuppressWarnings("unchecked")
	private <T> T getInternal(DocumentedDefinition<T> definition) {
		if (definition == null) {
			throw new NullPointerException("definition must not be null");
		}
		DocumentedDefinition<?> def = definitions.addIfAbsent(definition);
		if (def != null && def != definition) {
			throw new IllegalArgumentException("Definition " + definition + " doesn't match " + def);
		}
		T value = (T) values.get(definition.getKey());
		if (value == null) {
			return definition.defaultValue();
		} else {
			return value;
		}
	}

	/**
	 * Associates the specified value with the specified definition.
	 * 
	 * @param <T> type of the value
	 * @param definition definition of the value.
	 * @param value value to associate. May be {@code null}.
	 * @param text value as text to associate. May be {@code null}. If provided
	 *            and the typed value is missing, parser the text to get a typed
	 *            value.
	 * @throws NullPointerException if the definition is {@code null}
	 * @throws IllegalArgumentException if a different definition is already
	 *             available for the key of the provided definition.
	 */
	private <T> void setInternal(DocumentedDefinition<T> definition, T value, String text) {
		if (definition == null) {
			throw new NullPointerException("definition must not be null");
		}
		DocumentedDefinition<?> def = definitions.addIfAbsent(definition);
		if (def != null && def != definition) {
			throw new IllegalArgumentException("Definition " + definition + " doesn't match " + def);
		}
		if (value == null && text != null) {
			value = definition.readValue(text);
		}
		if (value != null && !definition.isAssignableFrom(value)) {
			throw new IllegalArgumentException(
					value.getClass().getSimpleName() + " is not a " + definition.getTypeName());
		}
		try { 
			definition.checkValue(value);
		} catch (ValueException ex) {
			throw new IllegalArgumentException(ex.getMessage());
		}
		values.put(definition.getKey(), value);
	}

}
