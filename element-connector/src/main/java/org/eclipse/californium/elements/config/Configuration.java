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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

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
 * {@link #addDefaultModule(ModuleDefinitionsProvider)} is used to register a
 * {@link ModuleDefinitionsProvider} for such a module. When creating a new
 * {@link Configuration}, all registered {@link ModuleDefinitionsProvider} are
 * called and will fill the map of {@link DocumentedDefinition}s and values. In
 * order to ensure, that the modules are register in a early stage, a
 * application should call e.g. {@link SystemConfig#register()} of the used
 * modules at the begin. See {@link SystemConfig} as example.
 * 
 * Alternatively
 * {@link Configuration#Configuration(ModuleDefinitionsProvider...)} may be used
 * to provide the set of modules the {@link Configuration} is based of.
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

	/**
	 * The default name for the configuration.
	 */
	public static final String DEFAULT_FILE_NAME = "Californium3.properties";
	/**
	 * The default file for the configuration.
	 */
	public static final File DEFAULT_FILE = new File(DEFAULT_FILE_NAME);
	/**
	 * The default header for a configuration file.
	 */
	public static final String DEFAULT_HEADER = "Californium3 CoAP Properties file";

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

	/**
	 * Handler for (custom) setup of configuration
	 * {@link DocumentedDefinition}s.
	 */
	public interface ModuleDefinitionsProvider extends DefinitionsProvider {

		/**
		 * Get module name
		 * 
		 * @return module name
		 */
		String getModule();

	}

	private static final Logger LOGGER = LoggerFactory.getLogger(Configuration.class);

	/**
	 * The map of registered default modules.
	 */
	private static final ConcurrentMap<String, DefinitionsProvider> DEFAULT_MODULES = new ConcurrentHashMap<>();

	/**
	 * The default properties definitions.
	 */
	private static final Definitions<DocumentedDefinition<?>> DEFAULT_DEFINITIONS = new Definitions<>("Configuration");

	/**
	 * The standard configuration that is used if none is defined.
	 */
	private static Configuration standard;

	/**
	 * Modules.
	 */
	private final ConcurrentMap<String, DefinitionsProvider> modules;
	/**
	 * Definitions.
	 */
	private final Definitions<DocumentedDefinition<?>> definitions;
	/**
	 * The typed properties.
	 */
	private final Map<String, Object> values = new HashMap<>();

	/**
	 * Add definitions provider for module.
	 * 
	 * @param modules available modules to add the module
	 * @param definitionsProvider definitions provider of module
	 * @throws NullPointerException if any parameter is {@code null}
	 * @throws IllegalArgumentException if the module name is {@code null} or
	 *             empty or a different definitions provider is already
	 *             registered with that module name.
	 */
	private static void addModule(ConcurrentMap<String, DefinitionsProvider> modules,
			ModuleDefinitionsProvider definitionsProvider) {
		if (modules == null) {
			throw new NullPointerException("Modules must not be null!");
		}
		if (definitionsProvider == null) {
			throw new NullPointerException("DefinitionsProvider must not be null!");
		}
		String module = definitionsProvider.getModule();
		if (module == null) {
			throw new IllegalArgumentException("DefinitionsProvider's module must not be null!");
		}
		if (module.isEmpty()) {
			throw new IllegalArgumentException("DefinitionsProvider's module name must not be empty!");
		}
		DefinitionsProvider previous = modules.putIfAbsent(module, definitionsProvider);
		if (previous != null && previous != definitionsProvider) {
			throw new IllegalArgumentException("Module " + module + " already registered with different provider!");
		}
		LOGGER.info("add {}", module);
	}

	/**
	 * Add definitions provider for module.
	 * 
	 * @param definitionsProvider definitions provider of module
	 * @throws NullPointerException if any parameter is {@code null}
	 * @throws IllegalArgumentException if the module name is {@code null} or
	 *             empty or a different definitions provider is already
	 *             registered with that module name.
	 */
	public static void addDefaultModule(ModuleDefinitionsProvider definitionsProvider) {
		addModule(DEFAULT_MODULES, definitionsProvider);
	}

	/**
	 * Gives access to the standard configuration.
	 * 
	 * When a new endpoint or server is created without a specific
	 * configuration, it will use this standard configuration.
	 * 
	 * Apply all {@link ModuleDefinitionsProvider} of registered modules.
	 * 
	 * For Android, please ensure, that either
	 * {@link Configuration#setStandard(Configuration)},
	 * {@link Configuration#createStandardWithoutFile()}, or
	 * {@link Configuration#createStandardFromStream(InputStream)} is called
	 * before!
	 * 
	 * @return the standard configuration
	 * @see #addDefaultModule(ModuleDefinitionsProvider)
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
	 * Apply all {@link ModuleDefinitionsProvider} of registered modules.
	 * 
	 * @return the standard configuration
	 * @see #addDefaultModule(ModuleDefinitionsProvider)
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
	 * Apply all {@link ModuleDefinitionsProvider} of registered modules.
	 * 
	 * @param inStream input stream to read properties.
	 * @return the standard configuration
	 * @throws NullPointerException if the in stream is {@code null}.
	 * @see #addDefaultModule(ModuleDefinitionsProvider)
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
	 * Apply all {@link ModuleDefinitionsProvider} of registered modules.
	 * 
	 * @param inStream input stream to read properties.
	 * @param customProvider custom definitions handler. May be {@code null}.
	 * @return the configuration
	 * @throws NullPointerException if the in stream is {@code null}.
	 * @see #addDefaultModule(ModuleDefinitionsProvider)
	 */
	public static Configuration createFromStream(InputStream inStream, DefinitionsProvider customProvider) {
		LOGGER.info("Creating configuration properties from stream");
		Configuration configuration = new Configuration();
		configuration.apply(customProvider);
		try {
			configuration.load(inStream);
		} catch (IOException e) {
			LOGGER.warn("cannot load properties from stream: {}", e.getMessage());
		}
		return configuration;
	}

	/**
	 * Creates the standard configuration with a file.
	 * 
	 * If the provided file exists, the configuration reads the properties from
	 * this file. Otherwise it creates the file.
	 * 
	 * Apply all {@link ModuleDefinitionsProvider} of registered modules.
	 *
	 * For Android, please use
	 * {@link Configuration#createStandardWithoutFile()}, or
	 * {@link Configuration#createStandardFromStream(InputStream)}.
	 * 
	 * @param file the configuration file
	 * @return the standard configuration
	 * @throws NullPointerException if the file is {@code null}.
	 * @see #addDefaultModule(ModuleDefinitionsProvider)
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
	 * Apply all {@link ModuleDefinitionsProvider} of registered modules.
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
	 * @see #addDefaultModule(ModuleDefinitionsProvider)
	 */
	public static Configuration createWithFile(File file, String header, DefinitionsProvider customProvider) {
		if (file == null) {
			throw new NullPointerException("file must not be null!");
		}
		Configuration configuration = new Configuration();
		configuration.apply(customProvider);
		if (file.exists()) {
			configuration.load(file);
		} else {
			configuration.store(file, header);
		}
		return configuration;
	}

	/**
	 * Instantiates a new configuration and sets the value definitions using the
	 * registered module's {@link ModuleDefinitionsProvider}s.
	 * 
	 * @see #addDefaultModule(ModuleDefinitionsProvider)
	 */
	public Configuration() {
		this.definitions = DEFAULT_DEFINITIONS;
		this.modules = DEFAULT_MODULES;
		applyModules();
	}

	/**
	 * Instantiates a new configuration and sets the values and from the
	 * provided configuration.
	 * 
	 * @param config configuration to copy
	 */
	public Configuration(Configuration config) {
		this.definitions = DEFAULT_DEFINITIONS == config.definitions ? DEFAULT_DEFINITIONS
				: new Definitions<DocumentedDefinition<?>>(config.definitions);
		this.modules = DEFAULT_MODULES == config.modules ? DEFAULT_MODULES
				: new ConcurrentHashMap<String, Configuration.DefinitionsProvider>(config.modules);
		this.values.putAll(config.values);
	}

	/**
	 * Instantiates a new configuration and sets the value definitions using the
	 * provided {@link ModuleDefinitionsProvider}s.
	 * 
	 * @param providers module definitions provider
	 */
	public Configuration(ModuleDefinitionsProvider... providers) {
		this.definitions = new Definitions<>("Configuration");
		this.modules = new ConcurrentHashMap<>();
		for (ModuleDefinitionsProvider provider : providers) {
			addModule(modules, provider);
		}
		applyModules();
	}

	/**
	 * Apply module's definitions.
	 * 
	 * Add default values and definitions.
	 */
	private void applyModules() {
		for (DefinitionsProvider handler : modules.values()) {
			handler.applyDefinitions(this);
		}
	}

	/**
	 * Apply custom provider.
	 * 
	 * @param customProvider custom provider. May be {@code null}.
	 */
	private void apply(DefinitionsProvider customProvider) {
		if (customProvider != null) {
			Set<String> before = new HashSet<>(modules.keySet());
			customProvider.applyDefinitions(this);
			if (before.size() < modules.size()) {
				Set<String> set = modules.keySet();
				set.removeAll(before);
				for (String newModule : set) {
					modules.get(newModule).applyDefinitions(this);
				}
				customProvider.applyDefinitions(this);
			}
		}
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
	 * @see #addDefaultModule(ModuleDefinitionsProvider)
	 * @see #Configuration(ModuleDefinitionsProvider...)
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
	 * @see #addDefaultModule(ModuleDefinitionsProvider)
	 * @see #Configuration(ModuleDefinitionsProvider...)
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
	 * @see #addDefaultModule(ModuleDefinitionsProvider)
	 * @see #Configuration(ModuleDefinitionsProvider...)
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
	 * @see #addDefaultModule(ModuleDefinitionsProvider)
	 * @see #Configuration(ModuleDefinitionsProvider...)
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
			Set<String> modules = this.modules.keySet();
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
		DocumentedDefinition<?> def = definitions.get(definition.getKey());
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
