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
 * In Californium the configuration is considered to be used via 3 interfaces:
 * <ul>
 * <li>The modules of Californium are consuming their configuration values using
 * the get functions.</li>
 * <li>The configuration values of the used modules are presented in a
 * properties file in order to enable a end-user to provide values according the
 * specific usage.</li>
 * <li>The applications using Californium may use the set functions in order to
 * provide application specific values.</li>
 * </ul>
 * <p>
 * 
 * Example parts of "Californium3.properties":
 * 
 * <pre>
 * <code>
 * # Californium CoAP Properties file for client
 * # Tue Oct 19 10:21:43 CEST 2021
 * #
 * # Random factor for initial CoAP acknowledge timeout.
 * # Default: 1.5
 * COAP.ACK_INIT_RANDOM=1.5
 * # Initial CoAP acknowledge timeout.
 * # Default: 2[s]
 * COAP.ACK_TIMEOUT=2[s]
 * # Scale factor for CoAP acknowledge backoff-timeout.
 * # Default: 2.0
 * COAP.ACK_TIMEOUT_SCALE=2.0
 * # Enable automatic failover on "entity too large" response.
 * # Default: true
 * COAP.BLOCKWISE_ENTITY_TOO_LARGE_AUTO_FAILOVER=true
 * ...
 * </code>
 * </pre>
 * 
 * If an application uses the properties file, an user may adapt the values
 * according the specific requirements by editing this file.
 * <p>
 * If you want to implement an application, you need to decide which modules you
 * want to use. Currently the following modules are available:
 * 
 * <dl>
 * <dt>UdpConfig</dt>
 * <dd>Configuration options for plain UDP communication</dd>
 * <dt>TcpConfig</dt>
 * <dd>Configuration options for TCP and TLS communication</dd>
 * <dt>DtlsConfig</dt>
 * <dd>Configuration options for DTLS communication</dd>
 * <dt>CoapConfig</dt>
 * <dd>Configuration options for CoAP processing</dd>
 * <dt>Proxy2Config</dt>
 * <dd>Configuration options for CoAP proxy processing</dd>
 * </dl>
 * 
 * Register the required modules ahead using
 * 
 * <pre>
 * <code>
 *   ...
 *   static {
 *      DtlsConfig.register();
 *      CoapConfig.register();
 *   }
 *   ...
 *   public static void main(String[] args) {
 *      Configuration.getStandard();
 *      ...
 *   }
 * </code>
 * </pre>
 * 
 * You will need to add the modules also to your maven {@code pom.xml} in order
 * to use them. Please refer to that specific {@code ???fConfig.xml} to see,
 * which values are supported.
 * <p>
 * The configuration may be changed via the API.
 * 
 * <pre>
 * <code>
 * Configuration config = Configuration.getStandard()
 *    .set(CoapConfig.PREFERRED_BLOCK_SIZE, 1_024)
 *    .set(CoapConfig.EXCHANGE_LIFETIME, 2, TimeUnit.MINUTES)
 *    .set(CoapConfig.MAX_RESOURCE_BODY_SIZE, 1_000_000);
 * </code>
 * </pre>
 * <p>
 * 
 * <b>Note:</b> an application, which uses this API, doesn't allow a end user to
 * configure these value using the properties file. If the application doesn't
 * support to use a properties file at all, the end user must use the mechanism
 * defined by that application.
 * <p>
 * In order to simplify the consumption by Californium itself, the data-model is
 * kept (mostly) simple and usually already defines the defaults. That prevents
 * to apply several different defaults when accessing them.
 * <p>
 * If custom logic is required for properties files, please consider to
 * {@link #setTransient(DocumentedDefinition)} such a value and replace it by a
 * custom definition (with different name and detailed documentation!). It's
 * then the responsibility of that custom code to determine the value for the
 * original Californium configuration value and set that before passing the
 * configuration to Californium's functions.
 * 
 * <pre>
 * <code>
 * 	public static final TimeDefinition APPL_HEALTH_STATUS_INTERVAL = new TimeDefinition(
 * 			"APPL_HEALTH_STATUS_INTERVAL", "Application Health status interval. 0 to disable the health status. Default depends on CLI parameter.");
 *  ...
 *  Configuration config = Configuration.getStandard();
 *  config.setTransient(NetworkConfig.HEALTH_STATUS_INTERVAL);
 *  config.set(APPL_HEALTH_STATUS_INTERVAL, null, TimeUnit.SECONDS);
 *  ...
 *  config.save();
 *  config.load();
 *  ...
 *  Long time = config.get(APPL_HEALTH_STATUS_INTERVAL, TimeUnit.SECONDS);
 *  if (time == null)  {
 *    time = cli.healthInterval;
 *  }
 *  config.set(SystemConfig.HEALTH_STATUS_INTERVAL, time, TimeUnit.SECONDS);
 *  ... 
 * </code>
 * </pre>
 * 
 * <p>
 * If both, the file-based provider and the setter-API, provides values for one
 * configuration topic, the value of the setter has precedence over the one from
 * the file. CLI parameters may be passed in with that. For other overwrites,
 * please consider to document them in order to make it transparent for users.
 * In cases, where the configuration value is always overwritten by a CLI
 * parameter, consider to mark the value as transient.
 * <p>
 * Depending on the environment, the configuration is stored and loaded from
 * properties files. When that file does not exist, Californium generates a
 * properties file. If file access is not possible, there are variants, which
 * are marked as "WithoutFile" or variants, which use a {@link InputStream} to
 * read the properties. Please use such a variant, e.g.
 * {@link #createStandardWithoutFile()}, if you want Californium to stop
 * generating a properties file. In order to still use the properties file to
 * provide specific values, such a file may be generate on a system, where files
 * are possible to write. Take that generated file as template, edit it
 * accordingly and then use it as "read-only" source.
 * <p>
 * <b>Note</b>: For Android it's recommended to use the AssetManager and pass in
 * the InputStream to the variants using that as parameter. Alternatively you
 * may chose to use the "WithoutFile" variant and, if required, adjust the
 * defaults in your code. If the "File" variants are used, ensure, that you have
 * the android-os-permission to do so.
 * <p>
 * In order to use this {@link Configuration} with modules (sets of
 * {@link DocumentedDefinition}),
 * {@link #addDefaultModule(ModuleDefinitionsProvider)} is used to register a
 * {@link ModuleDefinitionsProvider}. When creating a new {@link Configuration},
 * all registered {@link ModuleDefinitionsProvider} are applied and will fill
 * the map of {@link DocumentedDefinition}s and values. In order to ensure, that
 * the modules are register in a early stage, a application should call e.g.
 * {@link SystemConfig#register()} of the used modules at the begin. See
 * {@link SystemConfig} as example.
 * 
 * <p>
 * Alternatively
 * {@link Configuration#Configuration(ModuleDefinitionsProvider...)} may be used
 * to provide the set of modules the {@link Configuration} is based of.
 * <p>
 * In some case an application may adapt the default definitions by providing an
 * {@link DefinitionsProvider} to
 * {@link #createFromStream(InputStream, DefinitionsProvider)} or
 * {@link #createWithFile(File, String, DefinitionsProvider)}.
 * 
 * <pre>
 * <code>
 * private static DefinitionsProvider DEFAULTS = new DefinitionsProvider() {
 * 
 * 		&#064;Override
 * 		public void applyDefinitions(Configuration config) {
 * 			config.set(CoapConfig.MAX_ACTIVE_PEERS, 100);
 * 			config.set(CoapConfig.PROTOCOL_STAGE_THREAD_COUNT, 2);
 * 			config.set(DtlsConfig.DTLS_RECEIVER_THREAD_COUNT, 1);
 * 		}
 * };
 * 
 * Configuration config = Configuration.createWithFile(new File("My3.properties"), "My properties", DEFAULTS);
 * </code>
 * </pre>
 * <p>
 * Especially if Californium is used with a set of applications instead of a
 * single one, ensure, that it's either clear, which file is used by which
 * application, or use the same modules for all files, regardless, if a specific
 * application of that set is using a module or not. The same applies, if single
 * values are marked with {@link #setTransient(DocumentedDefinition)}.
 * <p>
 * To access the values always using the original {@link DocumentedDefinition}s
 * of a module, e.g. {@link SystemConfig#HEALTH_STATUS_INTERVAL}.
 * 
 * <pre>
 * <code>
 *  Configuration config = Configuration.getStandard();
 *  config.set(SystemConfig.HEALTH_STATUS_INTERVAL, 30, TimeUnit.SECONDS);
 *  ...
 *  long timeMillis = config.get(SystemConfig.HEALTH_STATUS_INTERVAL, TimeUnit.MILLISECONDS); 
 * </code>
 * </pre>
 * <p>
 * When primitive types (e.g. {@code int}) are used to process configuration
 * values, care must be taken to define a proper default value instead of
 * returning {@code null}. The {@link DocumentedDefinition}s therefore offer
 * variants, where such a default could be provided, e.g.
 * {@link IntegerDefinition#IntegerDefinition(String, String, Integer)}.
 * <p>
 * For definitions a optional minimum value may be provided. That doesn't grant,
 * that the resulting configuration is proper, neither general nor for specific
 * conditions. If a minimum value is too high for your use-case, please create
 * an issue in the
 * <a href="https://github.com/eclipse-californium/californium" target=
 * "_blank">Californium github repository</a>.
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
		 * <pre>
		 * <code>
		 * private static DefinitionsProvider DEFAULTS = new DefinitionsProvider() {
		 * 
		 * 		&#064;Override
		 * 		public void applyDefinitions(Configuration config) {
		 * 			config.set(CoapConfig.MAX_ACTIVE_PEERS, 100);
		 * 			config.set(CoapConfig.PROTOCOL_STAGE_THREAD_COUNT, 2);
		 * 			config.set(DtlsConfig.DTLS_RECEIVER_THREAD_COUNT, 1);
		 * 		}
		 * };
		 * 
		 * Configuration config = Configuration.createWithFile(new File("My3.properties"), "My properties", DEFAULTS);
		 * </code>
		 * </pre>
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
	 * The transient property names.
	 */
	private final Set<String> transientValues = new HashSet<>();
	/**
	 * The deprecated property names.
	 * 
	 * @since 3.5
	 */
	private final Map<String, String> deprecatedValues = new HashMap<>();

	/**
	 * Add definitions provider for module.
	 * 
	 * @param modules available modules to add the module
	 * @param definitionsProvider definitions provider of module
	 * @return {@code true}, if module is added, {@code false}, if modules was
	 *         already added.
	 * @throws NullPointerException if any parameter is {@code null}
	 * @throws IllegalArgumentException if the module name is {@code null} or
	 *             empty or a different definitions provider is already
	 *             registered with that module name.
	 */
	private static boolean addModule(ConcurrentMap<String, DefinitionsProvider> modules,
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
		return previous == null;
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
		if (addModule(DEFAULT_MODULES, definitionsProvider)) {
			LOGGER.info("defaults added {}", definitionsProvider.getModule());
		}
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
	 * <pre>
	 * <code>
	 * CoapConfig.register();
	 * DtlsConfig.register();
	 * ...
	 * Configuration.getStandard();
	 * </code>
	 * </pre>
	 * 
	 * @return the standard configuration
	 * @throws IllegalStateException if configuration has no definitions.
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
	 * Applies all {@link ModuleDefinitionsProvider} of registered modules. A
	 * previous standard configuration will be replaced by this.
	 * 
	 * <pre>
	 * <code>
	 * CoapConfig.register();
	 * DtlsConfig.register();
	 * ...
	 * Configuration.createStandardWithoutFile();
	 * </code>
	 * </pre>
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
	 * Applies all {@link ModuleDefinitionsProvider} of registered modules. A
	 * previous standard configuration will be replaced by this.
	 * 
	 * <pre>
	 * <code>
	 * CoapConfig.register();
	 * DtlsConfig.register();
	 * ...
	 * Configuration.createStandardFromStream(in);
	 * </code>
	 * </pre>
	 * 
	 * @param inStream input stream to read properties.
	 * @return the standard configuration
	 * @throws NullPointerException if the in stream is {@code null}.
	 * @throws IllegalStateException if configuration has no definitions.
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
	 * Applies all {@link ModuleDefinitionsProvider} of registered modules.
	 * 
	 * <pre>
	 * <code>
	 * CoapConfig.register();
	 * ...
	 * Configuration.createStandardWithoutFile();
	 * </code>
	 * </pre>
	 * 
	 * @param inStream input stream to read properties.
	 * @param customProvider custom definitions handler. May be {@code null}.
	 * @return the configuration
	 * @throws NullPointerException if the in stream is {@code null}.
	 * @throws IllegalStateException if configuration has no definitions.
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
	 * Applies all {@link ModuleDefinitionsProvider} of registered modules. A
	 * previous standard configuration will be replaced by this.
	 *
	 * For Android, please use
	 * {@link Configuration#createStandardWithoutFile()}, or
	 * {@link Configuration#createStandardFromStream(InputStream)}.
	 * 
	 * <pre>
	 * <code>
	 * CoapConfig.register();
	 * DtlsConfig.register();
	 * ...
	 * Configuration.createStandardWithFile(file);
	 * </code>
	 * </pre>
	 * 
	 * @param file the configuration file
	 * @return the standard configuration
	 * @throws NullPointerException if the file is {@code null}.
	 * @throws IllegalStateException if configuration has no definitions.
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
	 * Applies all {@link ModuleDefinitionsProvider} of registered modules.
	 * 
	 * For Android, please use {@link Configuration#Configuration()}, and load
	 * the values using {@link Configuration#load(InputStream)} or adjust the in
	 * your code.
	 * 
	 * <pre>
	 * <code>
	 * CoapConfig.register();
	 * DtlsConfig.register();
	 * ...
	 * Configuration.createWithFile(...);
	 * </code>
	 * </pre>
	 * 
	 * @param file the configuration file
	 * @param header The header to write to the top of the file.
	 * @param customProvider custom definitions handler. May be {@code null}.
	 * @return the configuration
	 * @throws NullPointerException if the file or header is {@code null}.
	 * @throws IllegalStateException if configuration has no definitions.
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
		this.transientValues.addAll(config.transientValues);
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
			if (addModule(modules, provider)) {
				LOGGER.trace("added {}", provider.getModule());
			}
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
					LOGGER.warn("Add missing module {}", newModule);
					modules.get(newModule).applyDefinitions(this);
				}
				customProvider.applyDefinitions(this);
			}
		}
	}

	/**
	 * Loads properties from a file.
	 * 
	 * Requires to add the {@link DocumentedDefinition}s of the modules or
	 * custom definitions using a setter ahead.
	 *
	 * Unknown, transient or invalid values are ignored and the
	 * {@link DocumentedDefinition#getDefaultValue()} will be used instead.
	 * 
	 * For Android, please use {@link Configuration#load(InputStream)}.
	 * 
	 * @param file the file
	 * @throws NullPointerException if the file is {@code null}.
	 * @throws IllegalStateException if configuration has no definitions.
	 * @see #addDefaultModule(ModuleDefinitionsProvider)
	 * @see #Configuration(ModuleDefinitionsProvider...)
	 * @see #set(BasicDefinition, Object)
	 * @see #set(TimeDefinition, int, TimeUnit)
	 * @see #set(TimeDefinition, Long, TimeUnit)
	 * @see #setFromText(DocumentedDefinition, String)
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
	 * Requires to add the {@link DocumentedDefinition}s of the modules or
	 * custom definitions using a setter ahead.
	 * 
	 * Unknown, transient or invalid values are ignored and the
	 * {@link DocumentedDefinition#getDefaultValue()} will be used instead.
	 *
	 * @param inStream the input stream
	 * @throws NullPointerException if the inStream is {@code null}.
	 * @throws IOException if an error occurred when reading from the input
	 *             stream
	 * @throws IllegalStateException if configuration has no definitions.
	 * @see #addDefaultModule(ModuleDefinitionsProvider)
	 * @see #Configuration(ModuleDefinitionsProvider...)
	 * @see #set(BasicDefinition, Object)
	 * @see #set(TimeDefinition, int, TimeUnit)
	 * @see #set(TimeDefinition, Long, TimeUnit)
	 * @see #setFromText(DocumentedDefinition, String)
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
	 * Requires to add the {@link DocumentedDefinition}s of the modules or
	 * custom definitions using a setter ahead.
	 * 
	 * Unknown, transient or invalid values are ignored and the
	 * {@link DocumentedDefinition#getDefaultValue()} will be used instead.
	 * 
	 * Applies conversion defined by that {@link DocumentedDefinition}s to the
	 * textual values.
	 * 
	 * @param properties properties to convert and add
	 * @throws NullPointerException if properties is {@code null}.
	 * @throws IllegalStateException if configuration has no definitions.
	 * @see #addDefaultModule(ModuleDefinitionsProvider)
	 * @see #Configuration(ModuleDefinitionsProvider...)
	 * @see #set(BasicDefinition, Object)
	 * @see #set(TimeDefinition, int, TimeUnit)
	 * @see #set(TimeDefinition, Long, TimeUnit)
	 * @see #setFromText(DocumentedDefinition, String)
	 */
	public void add(Properties properties) {
		if (properties == null) {
			throw new NullPointerException("properties must not be null!");
		}
		if (definitions.isEmpty()) {
			throw new IllegalStateException("Configuration contains no definitions!");
		}
		for (Object k : properties.keySet()) {
			if (k instanceof String) {
				String key = (String) k;
				DocumentedDefinition<?> definition = definitions.get(key);
				if (definition == null) {
					LOGGER.warn("Ignore {}, no configuration definition available!", key);
				} else if (useLoad(key)) {
					String text = properties.getProperty(key);
					Object value = loadValue(definition, text);
					values.put(key, value);
				}
			}
		}
	}

	/**
	 * Add dictionary.
	 * 
	 * Requires to add the {@link DocumentedDefinition}s of the modules or
	 * custom definitions using a setter ahead.
	 * 
	 * Unknown, transient or invalid values are ignored and the
	 * {@link DocumentedDefinition#getDefaultValue()} will be used instead.
	 * 
	 * Applies conversion defined by that {@link DocumentedDefinition}s to
	 * String entries. Entries of other types are added, if
	 * {@link DocumentedDefinition#isAssignableFrom(Object)} returns
	 * {@code true}.
	 * 
	 * @param dictionary dictionary to convert and add
	 * @throws NullPointerException if dictionary is {@code null}.
	 * @throws IllegalStateException if configuration has no definitions.
	 * @see #addDefaultModule(ModuleDefinitionsProvider)
	 * @see #Configuration(ModuleDefinitionsProvider...)
	 * @see #set(BasicDefinition, Object)
	 * @see #set(TimeDefinition, int, TimeUnit)
	 * @see #set(TimeDefinition, Long, TimeUnit)
	 * @see #setFromText(DocumentedDefinition, String)
	 */
	public void add(Dictionary<String, ?> dictionary) {
		if (dictionary == null) {
			throw new NullPointerException("dictionary must not be null!");
		}
		if (definitions.isEmpty()) {
			throw new IllegalStateException("Configuration contains no definitions!");
		}
		for (Enumeration<String> allKeys = dictionary.keys(); allKeys.hasMoreElements();) {
			String key = allKeys.nextElement();
			Object value = dictionary.get(key);
			DocumentedDefinition<?> definition = definitions.get(key);
			if (definition == null) {
				LOGGER.warn("Ignore {}, no configuration definition available!", key);
			} else if (useLoad(key)) {
				if (value instanceof String) {
					String text = (String) value;
					value = loadValue(definition, text);
				} else if (value != null) {
					if (!definition.isAssignableFrom(value)) {
						LOGGER.warn("{} is not a {}!", value.getClass().getSimpleName(), definition.getTypeName());
						value = null;
					}
					try {
						value = definition.checkRawValue(value);
					} catch (ValueException e) {
						value = null;
					}
				}
				values.put(key, value);
			}
		}
	}

	/**
	 * Check, if value is to be loaded.
	 * 
	 * Transient values are not loaded. For both, transient and deprecated
	 * values, a warning message is written to the logging.
	 * 
	 * @param key key to check
	 * @return {@code true}, to load the value, {@code false}, to ignore it.
	 * @see #setTransient(DocumentedDefinition)
	 * @see #setDeprecated(DocumentedDefinition, DocumentedDefinition)
	 * @since 3.5
	 */
	private boolean useLoad(String key) {
		if (transientValues.contains(key)) {
			LOGGER.warn("Ignore {}, definition set transient!", key);
			return false;
		} else {
			if (deprecatedValues.containsKey(key)) {
				String replace = deprecatedValues.get(key);
				if (replace != null) {
					LOGGER.warn("Deprecated {}, please replace it by {}!", key, replace);
				} else {
					LOGGER.warn("Deprecated {}, please remove it!", key);
				}
			} else {
				LOGGER.debug("Load {}", key);
			}
			return true;
		}
	}

	/**
	 * Load value from text.
	 * 
	 * @param definition value's definition
	 * @param text textual value
	 * @return value, or {@code null}, if textual value is empty or could not be
	 *         read.
	 */
	private Object loadValue(DocumentedDefinition<?> definition, String text) {
		Object value = null;
		if (text != null) {
			text = text.trim();
			if (!text.isEmpty()) {
				try {
					value = definition.readValue(text);
				} catch (RuntimeException ex) {
					LOGGER.warn("{}", ex.getMessage());
					value = null;
				}
			}
		}
		return value;
	}

	/**
	 * Stores the configuration to a file.
	 * 
	 * Not intended for Android!
	 *
	 * @param file The file to write to.
	 * @throws NullPointerException if the file is {@code null}.
	 * @throws IllegalStateException if configuration has no definitions.
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
	 * @throws IllegalStateException if configuration has no definitions.
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
	 * @throws IllegalStateException if configuration has no definitions.
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
		if (values.isEmpty()) {
			throw new IllegalStateException("Configuration contains no values!");
		}
		try {
			Set<String> modules = this.modules.keySet();
			List<String> generalKeys = new ArrayList<>();
			List<String> moduleKeys = new ArrayList<>();
			for (String key : values.keySet()) {
				if (transientValues.contains(key) || deprecatedValues.containsKey(key)) {
					continue;
				}
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
		Object defaultValue = definition.getDefaultValue();
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
	 * Set definition transient.
	 * 
	 * {@link DocumentedDefinition} are used by the components to access their
	 * configuration value. Usually, these values are kept in property files. If
	 * an application wants to replace such a configuration value and set it
	 * based on own custom values, the application may mark that definition as
	 * transient in order to prevent loading or storing that value.
	 * 
	 * @param <T> value type of definition
	 * @param definition definition to set transient
	 * @return the configuration for chaining
	 * @throws NullPointerException if the definition is {@code null}
	 */
	public <T> Configuration setTransient(DocumentedDefinition<T> definition) {
		if (definition == null) {
			throw new NullPointerException("Definition must not be null!");
		}
		transientValues.add(definition.getKey());
		return this;
	}

	/**
	 * Set definition deprecated.
	 * 
	 * Deprecate definitions are continued to be loaded, but are not longer
	 * saved. Clears already set values in order to check, if the value is still
	 * loaded from file or stream.
	 * 
	 * @param <T> value type of definition
	 * @param deprecatedDefinition definition to set deprecated
	 * @param newDefinition definition which replace the deprecated defintion.
	 *            May be {@code null}.
	 * @return the configuration for chaining
	 * @throws NullPointerException if the definition is {@code null}
	 * @since 3.5
	 */
	public <T> Configuration setDeprecated(DocumentedDefinition<T> deprecatedDefinition,
			DocumentedDefinition<T> newDefinition) {
		if (deprecatedDefinition == null) {
			throw new NullPointerException("Deprecated definition must not be null!");
		}
		String replace = newDefinition == null ? null : newDefinition.getKey();
		deprecatedValues.put(deprecatedDefinition.getKey(), replace);
		setInternal(deprecatedDefinition, null, null);
		return this;
	}

	/**
	 * Check, if definitions is already available.
	 * 
	 * Definitions are automatically added by their first use with one of the
	 * getter or setter. This checks, if the definition has been added before
	 * calling this method.
	 * 
	 * @param <T> value type
	 * @param definition definition to check
	 * @return {@code true}, if available, {@code false}, if not.
	 * @throws NullPointerException if definition is {@code null}
	 * @since 3.11
	 */
	public <T> boolean hasDefinition(DocumentedDefinition<T> definition) {
		if (definition == null) {
			throw new NullPointerException("definition must not be null");
		}
		return definitions.get(definition.getKey()) != null;
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

	/**
	 * Get the textual configuration value of the definition.
	 * 
	 * @param <T> value type
	 * @param definition the value definition
	 * @return the configuration value of the definition
	 */
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
	 * Also used, if only a single value is set as list.
	 * 
	 * @param <T> item value type
	 * @param definition the value definition
	 * @param values the list of values
	 * @return the configuration for chaining
	 * @throws NullPointerException if the definition or values is {@code null}
	 * @throws IllegalArgumentException if a different definition is already
	 *             available for the key of the provided definition or the
	 *             values doesn't match the constraints of the definition.
	 */
	public <T> Configuration setAsList(BasicListDefinition<T> definition, @SuppressWarnings("unchecked") T... values) {
		if (values == null) {
			throw new NullPointerException("Values must not be null!");
		}
		setInternal(definition, Arrays.asList(values), null);
		return this;
	}

	/**
	 * Associates the specified list of text values with the specified
	 * definition.
	 * 
	 * @param <T> item value type
	 * @param definition the value definition
	 * @param values the list of text values
	 * @return the configuration for chaining
	 * @throws NullPointerException if the definition or values is {@code null}
	 * @throws IllegalArgumentException if a different definition is already
	 *             available for the key of the provided definition or the
	 *             values doesn't match the constraints of the definition.
	 */
	public <T> Configuration setAsListFromText(BasicListDefinition<T> definition, String... values) {
		if (values == null) {
			throw new NullPointerException("Values must not be null!");
		}
		if (values.length > 0) {
			StringBuffer all = new StringBuffer();
			for (String value : values) {
				all.append(value).append(",");
			}
			int len = all.length();
			if (len > 0) {
				all.setLength(len - 1);
			}
			setInternal(definition, null, all.toString());
		} else {
			List<T> empty = Collections.emptyList();
			setInternal(definition, empty, null);
		}
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
	 *         {@link DocumentedDefinition#getDefaultValue()} instead.
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
			return definition.getDefaultValue();
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
		} else {
			if (value != null && !definition.isAssignableFrom(value)) {
				throw new IllegalArgumentException(
						value.getClass().getSimpleName() + " is not a " + definition.getTypeName());
			}
			try {
				value = definition.checkValue(value);
			} catch (ValueException ex) {
				throw new IllegalArgumentException(ex.getMessage());
			}
		}
		values.put(definition.getKey(), value);
	}

}
