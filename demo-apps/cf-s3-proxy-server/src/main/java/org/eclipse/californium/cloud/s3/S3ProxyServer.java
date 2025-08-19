/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.cloud.s3;

import static org.eclipse.californium.cloud.s3.http.SinglePageApplication.HTTPS_SCHEME;
import static org.eclipse.californium.cloud.s3.http.SinglePageApplication.S3_SCHEME;

import java.io.File;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

import org.eclipse.californium.cloud.BaseServer;
import org.eclipse.californium.cloud.http.HttpService;
import org.eclipse.californium.cloud.option.ServerCustomOptions;
import org.eclipse.californium.cloud.option.TimeOption;
import org.eclipse.californium.cloud.resources.Diagnose;
import org.eclipse.californium.cloud.resources.MyContext;
import org.eclipse.californium.cloud.resources.Provisioning;
import org.eclipse.californium.cloud.s3.forward.BasicHttpForwardConfiguration;
import org.eclipse.californium.cloud.s3.forward.HttpForwardConfiguration;
import org.eclipse.californium.cloud.s3.forward.HttpForwardConfiguration.DeviceIdentityMode;
import org.eclipse.californium.cloud.s3.forward.HttpForwardConfigurationProvider;
import org.eclipse.californium.cloud.s3.forward.HttpForwardConfigurationProviders;
import org.eclipse.californium.cloud.s3.forward.HttpForwardServiceManager;
import org.eclipse.californium.cloud.s3.http.AuthorizedCoapProxyHandler;
import org.eclipse.californium.cloud.s3.http.Aws4Authorizer;
import org.eclipse.californium.cloud.s3.http.ConfigHandler;
import org.eclipse.californium.cloud.s3.http.GroupsHandler;
import org.eclipse.californium.cloud.s3.http.S3Login;
import org.eclipse.californium.cloud.s3.http.SinglePageApplication;
import org.eclipse.californium.cloud.s3.option.S3ProxyCustomOptions;
import org.eclipse.californium.cloud.s3.processor.S3Processor;
import org.eclipse.californium.cloud.s3.processor.S3ProcessorHealthLogger;
import org.eclipse.californium.cloud.s3.proxy.S3AsyncProxyClient;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClient;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClientProvider;
import org.eclipse.californium.cloud.s3.resources.S3Devices;
import org.eclipse.californium.cloud.s3.resources.S3ProxyResource;
import org.eclipse.californium.cloud.s3.util.DeviceGroupProvider;
import org.eclipse.californium.cloud.s3.util.DomainDeviceManager;
import org.eclipse.californium.cloud.s3.util.Domains;
import org.eclipse.californium.cloud.s3.util.WebAppConfigProvider;
import org.eclipse.californium.cloud.s3.util.WebAppDomainUser;
import org.eclipse.californium.cloud.s3.util.WebAppUser;
import org.eclipse.californium.cloud.s3.util.WebAppUserParser;
import org.eclipse.californium.cloud.s3.util.WebAppUserProvider;
import org.eclipse.californium.cloud.util.DeviceIdentifier;
import org.eclipse.californium.cloud.util.DeviceParser;
import org.eclipse.californium.cloud.util.DeviceProvisioningConsumer;
import org.eclipse.californium.cloud.util.LinuxConfigParser;
import org.eclipse.californium.cloud.util.ResourceStore;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.option.MapBasedOptionRegistry;
import org.eclipse.californium.core.coap.option.OptionRegistry;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.elements.config.CertificateAuthenticationMode;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.config.IntegerDefinition;
import org.eclipse.californium.elements.config.TimeDefinition;
import org.eclipse.californium.elements.util.SslContextUtil.Credentials;
import org.eclipse.californium.proxy2.config.Proxy2Config;
import org.eclipse.californium.proxy2.http.HttpClientFactory;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * The CoAP-S3-proxy server.
 * 
 * @since 3.12
 */
public class S3ProxyServer extends BaseServer {

	private static final String LOGGER_CONFIG = "logback.configurationFile";

	static {
		Proxy2Config.register();

		String property = System.getProperty(LOGGER_CONFIG);
		if (property == null) {
			String[] config = { "./logback.xml", "./src/main/resources/logback.xml" };
			String path = config[0];
			for (String file : config) {
				if (new File(file).exists()) {
					path = file;
					break;
				}
			}
			System.setProperty(LOGGER_CONFIG, path);
		}
	}

	private static final Logger LOGGER = LoggerFactory.getLogger(CoapServer.class);

	public static final String DEFAULT_DOMAIN = "default";

	private static final File CONFIG_FILE = new File("CaliforniumS3Proxy.properties");
	private static final String CONFIG_HEADER = "Californium CoAP Properties file for S3 Proxy Server";

	@Command(name = "S3ProxyServer", version = "(c) 2024, Contributors to the Eclipse Foundation.", footer = { "",
			"Examples:", "  S3ProxyServer --no-loopback --device-file devices.txt \\",
			"                --s3-config ~/.s3cfg",
			"    (S3ProxyServer listening only on external network interfaces.)", "",
			"  S3ProxyServer --store-file dtls.bin --store-max-age 168 \\",
			"                --store-password64 ZVhiRW5pdkx1RUs2dmVoZg== \\",
			"                --device-file devices.txt --user-file users.txt \\",
			"                --s3-config ~/.s3cfg", "",
			"    (S3ProxyServer with device credentials and web application user",
			"     from file and dtls-graceful restart. Devices/sessions with no",
			"     exchange for more then a week (168 hours) are skipped when saving.)", "",
			"  S3ProxyServer --store-file dtls.bin --store-max-age 168 \\",
			"                --store-password64 ZVhiRW5pdkx1RUs2dmVoZg== \\",
			"                --device-file devices.txt --user-file users.txt \\",
			"                --https-credentials . --s3-config ~/.s3cfg", "",
			"    (S3ProxyServer with device credentials and web application user",
			"     from file and dtls-graceful restart. The Web-Login HTTP server",
			"     is started at port 8080 using the x509 certificates from the",
			"     current directory (certificate is required to be provided).",
			"     Devices/sessions with no exchange for more then a week", "     (168 hours) are skipped when saving.)",
			"", "For device data forwarding via http currently four variants for the",
			"  '--http-authentication' are supported: 'Bearer <token>',",
			"  'Header <name>:<value>', 'PreBasic <username>:<password>' or",
			"  '<username>:<password>'. The 'Bearer', 'Header' and 'PreBasic'",
			"  authentication data will be send without challenge from the server.",
			"  The '<username>:<password>' variant will be used on challenge by",
			"  server and supports BASIC and DIGEST.",
			"  The response filter is a regular expression. If that matches, the",
			"  response payload is dropped and not forwarded to the device. If",
			"  no filter is given, all response payloads are dropped.", "",
			"Search path for '--spa-css', '--spa-script', and '--spa-script-v2':",
			"  If the provided path starts with 'http:' or 'https:' then the path",
			"  is used for the web app unmodified as provided.",
			"  If '--spa-s3' is used, the paths are translated into external S3 paths.",
			"  Otherwise, if the provided path starts with 'classpath://', then the",
			"  resource is loaded from that classpath.",
			"  If none of the above rule applies, then the local file system is used",
			"  to locate the path. If it's not found in the current directory, the",
			"  common maven path for resources 'src/main/resources/<path>' is used",
			"  as prefix. If it's also not found there, then it's searched in the",
			"  classpath even without the prefix 'classpath://'.", })
	public static class S3ProxyConfig extends ServerConfig {

		@ArgGroup(exclusive = true, multiplicity = "1")
		public Mode mode;

		public static class Mode {

			@ArgGroup(exclusive = false)
			public DomainStore domainStore;

			@ArgGroup(exclusive = false)
			public Single single;

		}

		public static class DomainStore {

			@Option(names = "--domain-file", required = true, description = "Filename of domain-store.")
			public String file;

			@Option(names = "--domain-file-password64", required = false, description = "Password for domain-store. Base 64 encoded.")
			public String password64;
		}

		public static class UserStore {

			@Option(names = "--user-file", required = true, description = "Filename of user-store.")
			public String file;

			@Option(names = "--user-file-password64", required = false, description = "Password for user-store. Base 64 encoded.")
			public String password64;

		}

		public static class ConfigStore {

			@Option(names = "--config-file", required = true, description = "Filename of configs-store.")
			public String file;

			@Option(names = "--config-file-password64", required = false, description = "Password for configs-store. Base 64 encoded.")
			public String password64;
		}

		public static class HttpForward {

			@Option(names = "--http-forward", required = true, description = "Http destination to forward device data (coap-requests).")
			public String httpForward;

			@Option(names = "--http-authentication", description = "Http authentication for forward device data (coap-requests). Supports 'Bearer <access-token>', 'Header <name:value>', 'PreBasic <username:password' and '<username:password>'")
			public String httpAuthentication;

			@Option(names = "--http-device-identity-mode", defaultValue = "NONE", description = "Http device identity mode for forwarding device data (coap-requests) . Supported values: NONE, HEADLINE and QUERY_PARAMETER. Default: ${DEFAULT-VALUE}")
			public HttpForwardConfiguration.DeviceIdentityMode httpDeviceIdentityMode;

			@Option(names = "--http-response-filter", description = "Regular expression to filter http response payload.")
			public String httpResponseFilter;

			@Option(names = "--http-service-name", description = "Name of java-service to forward device data (coap-requests).")
			public String httpServiceName;
		}

		public static class Single {

			@ArgGroup(exclusive = false)
			public S3Config s3Config;

			@ArgGroup(exclusive = false)
			public UserStore userStore;

			@ArgGroup(exclusive = false)
			public ConfigStore configStore;

			@ArgGroup(exclusive = false)
			public HttpForward httpForward;

		}

		public static class S3Credentials {

			@Option(names = "--s3-config", description = "s3 configuration file.")
			public String s3ConfigFile;

			@ArgGroup(exclusive = false)
			public S3CliCredentials s3Credentials;
		}

		public static class S3CliCredentials {

			@Option(names = "--s3-access-key", required = true, description = "s3 access key.")
			public String accessKey;

			@Option(names = "--s3-secret", required = true, description = "s3 secret access key.")
			public String secret;
		}

		public static class S3Config {

			public String accessKey;

			public String secret;

			@ArgGroup(exclusive = true, multiplicity = "1")
			public S3Credentials s3credentials;

			@Option(names = "--s3-endpoint", required = false, description = "s3 endoint URI. e.g.: https://sos-de-fra-1.exo.io for ExoScale in DE-FRA1.")
			public String endpoint;

			@Option(names = "--s3-region", required = false, description = "s3 region. Only AWS regions are supported. Default: 'us-east-1'. (For other providers, try, if the default works).")
			public String region;

			@Option(names = "--s3-bucket", required = false, description = "s3 bucket. Default: devices")
			public String bucket;

			@Option(names = "--s3-acl", required = false, description = "s3 canned acl. e.g. public-read")
			public String acl;

			@Option(names = "--s3-concurrency", defaultValue = "200", required = false, description = "s3 concurrency. Default ${DEFAULT-VALUE}")
			public int concurrency;

			@Option(names = "--s3-external-endpoint", required = false, description = "s3 external endoint URI. e.g.: https://devices.sos-de-fra-1.exo.io for bucket \"devices\" on ExoScale in DE-FRA1.")
			public String externalEndpoint;

			@Option(names = "--s3-redirect", required = false, description = "s3 supports redirects for endpoint.")
			public boolean redirect;

			@Option(names = "--s3-compress", defaultValue = "true", fallbackValue = "true", required = false, description = "s3 use compression for archive files. Default true.")
			public boolean compress = true;

			private void httpsEndpoints() {
				// ensure https
				if (endpoint != null) {
					endpoint = https(endpoint);
				}
				if (externalEndpoint != null) {
					externalEndpoint = https(externalEndpoint);
				}
			}

			public void apply(LinuxConfigParser s3Cmd, String domain) {
				accessKey = s3Cmd.get(domain, "access_key");
				secret = s3Cmd.get(domain, "secret_key");
				endpoint = s3Cmd.getWithDefault(domain, "host_base", endpoint);
				acl = s3Cmd.getWithDefault(domain, "acl", acl);
				region = s3Cmd.getWithDefault(domain, "bucket_location", region);
				if (region == null) {
					region = S3ProxyClient.DEFAULT_REGION;
				}
				bucket = s3Cmd.getWithDefault(domain, "bucket", bucket);
				if (bucket == null) {
					bucket = S3AsyncProxyClient.DEFAULT_S3_BUCKET;
				}
				if (externalEndpoint == null) {
					externalEndpoint = s3Cmd.get(domain, "host_bucket");
					if (externalEndpoint != null) {
						externalEndpoint = externalEndpoint.replace("%(bucket)s", bucket);
					}
				}
				String value = s3Cmd.get(domain, "concurrency");
				if (value != null) {
					concurrency = Integer.parseInt(value);
				}
				value = s3Cmd.get(domain, "redirect");
				if (value != null) {
					redirect = Boolean.parseBoolean(value);
				}
				value = s3Cmd.get(domain, "compress");
				if (value != null) {
					compress = Boolean.parseBoolean(value);
				}
				httpsEndpoints();
			}

			public void defaults() {
				if (s3credentials != null) {
					if (s3credentials.s3ConfigFile != null) {
						LOGGER.info("S3cfg: {}", s3credentials.s3ConfigFile);
						ResourceStore<LinuxConfigParser> s3Cmd = new ResourceStore<>(new LinuxConfigParser(true, true));
						s3Cmd.load(s3credentials.s3ConfigFile);
						LinuxConfigParser s3Config = s3Cmd.getResource();
						apply(s3Config, LinuxConfigParser.DEFAULT_SECTION);
					} else {
						accessKey = s3credentials.s3Credentials.accessKey;
						secret = s3credentials.s3Credentials.secret;
						httpsEndpoints();
					}
				}
			}
		}

		@ArgGroup(exclusive = false)
		public SinglePageApplication spa;

		public static class SinglePageApplication extends HttpsConfig {

			@Option(names = "--spa-script", defaultValue = "appv3.js", description = "Single-Page-Application script. See applied search path below. Default ${DEFAULT-VALUE}")
			public String singlePageApplicationScript;

			@Option(names = "--spa-css", defaultValue = "stylesheet.css", description = "Single-Page-Application Cascading Style Sheets. See applied search path below. Default ${DEFAULT-VALUE}")
			public String singlePageApplicationCss;

			@Option(names = "--spa-reload", description = "Reload Single-Page-Application script.")
			public boolean singlePageApplicationReload;

			@Option(names = "--spa-s3", description = "Single-Page-Application in S3. Load scripts and ccs from S3.")
			public boolean s3;

			@Option(names = "--spa-script-v2", description = "Single-Page-Application script v2. See applied search path below.")
			public String singlePageApplicationScriptV2;

			@Option(names = "--spa-script-v1", description = "Single-Page-Application script v1. See applied search path below.")
			public String singlePageApplicationScriptV1;

		}

		@Option(names = "--no-coap", negatable = true, description = "Disable coap endpoints.")
		public boolean coap = true;

		@ArgGroup(exclusive = false)
		public S3ProcessorConfig s3Processor;

		public static class S3ProcessorConfig {

			@Option(names = "--s3p-function", description = "S3Processor function. Default arch.")
			public String function;

			@Option(names = "--s3p-upto", description = "S3Processor up to date. Either a date in format yyyy-mm-dd, or a number. Negative numbers are replaced by the date that days ago, positive numbers keeps that last available days.")
			public String upTo;

			@Option(names = "--s3p-domains", split = ",", required = false, description = "S3Processor list of domains. Separated by ','. Default all domains.")
			public List<String> domains;

			@Option(names = "--s3p-devices", split = ",", required = false, description = "S3Processor list of devices. Separated by ','. Default all devices.")
			public List<String> devices;

			@Option(names = "--s3p-test", required = false, description = "S3Processor test run, don't save nor delete files.")
			public boolean test;
		}

		@Override
		public void defaults() {
			super.defaults();
			noCoap = !coap;
			if (mode.single != null) {
				S3Config s3Config = mode.single.s3Config;
				if (s3Config != null) {
					s3Config.defaults();
				}
			}
			if (spa != null) {
				super.https = spa;
			}
		}
	}

	/**
	 * Interval to reload user credentials.
	 */
	public static final TimeDefinition USER_CREDENTIALS_RELOAD_INTERVAL = new TimeDefinition(
			"USER_CREDENTIALS_RELOAD_INTERVAL",
			"Reload user credentials interval. 0 to load credentials only on startup.", 30, TimeUnit.SECONDS);
	/**
	 * Initial delay of S3 processing.
	 */
	public static final TimeDefinition S3_PROCESSING_INITIAL_DELAY = new TimeDefinition("S3_PROCESSING_INITIAL_DELAY",
			"S3 processing initial delay. S3 processing combines the messages of the last day into a weeks archive file.",
			20, TimeUnit.SECONDS);
	/**
	 * Interval for S3 processing.
	 */
	public static final TimeDefinition S3_PROCESSING_INTERVAL = new TimeDefinition("S3_PROCESSING_INTERVAL",
			"S3 processing interval. S3 processing combines the messages of the last day into a weeks archive file. Usually run once a day. 0 to disable S3 processing.",
			24, TimeUnit.HOURS);
	/**
	 * Daily time for S3 processing.
	 */
	public static final TimeDefinition S3_PROCESSING_DAILY_TIME = new TimeDefinition("S3_PROCESSING_DAILY_TIME",
			"S3 processing daily time after UTC midnight. S3 processing combines the messages of the last day into a weeks archive file. Usually run once a day. 0 to disable S3 processing.",
			5, TimeUnit.MINUTES);
	/**
	 * Maximum device in cache.
	 */
	public static final IntegerDefinition MAX_DEVICE_CONFIG_SIZE = new IntegerDefinition("MAX_DEVICE_CONFIG_SIZE",
			"Maximum size of device configuration.", 1024);

	public static DefinitionsProvider DEFAULTS = (config) -> {
		BaseServer.DEFAULTS.applyDefinitions(config);
		config.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.WANTED);
		config.set(DtlsConfig.DTLS_APPLICATION_AUTHORIZATION_TIMEOUT, 15, TimeUnit.SECONDS);
		config.set(USER_CREDENTIALS_RELOAD_INTERVAL, 30, TimeUnit.SECONDS);
		config.set(S3_PROCESSING_INITIAL_DELAY, 20, TimeUnit.SECONDS);
		config.set(S3_PROCESSING_INTERVAL, 0, TimeUnit.HOURS);
		config.set(S3_PROCESSING_DAILY_TIME, 5, TimeUnit.MINUTES);
		config.set(MAX_DEVICE_CONFIG_SIZE, 1024);
	};

	public static void main(String[] args) {
		OptionRegistry registry = MapBasedOptionRegistry.builder()
				.add(StandardOptionRegistry.getDefaultOptionRegistry()).add(ServerCustomOptions.CUSTOM)
				.add(S3ProxyCustomOptions.CUSTOM)
				.add(TimeOption.DEPRECATED_DEFINITION).build();

		StandardOptionRegistry.setDefaultOptionRegistry(registry);

		Configuration configuration = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		HttpClientFactory.setNetworkConfig(configuration);

		start(args, S3ProxyServer.class.getSimpleName(), new S3ProxyConfig(), new S3ProxyServer(configuration));
	}

	/**
	 * Get valid URL with https scheme.
	 * <p>
	 * Keep or add https scheme. Fails, if different scheme is provided.
	 * 
	 * @param url URL
	 * @return URL with https scheme
	 * @throws IllegalArgumentException if url uses an other scheme than https
	 */
	private static String https(String url) {
		if (url != null) {
			String scheme = CoAP.getSchemeFromUri(url);
			if (scheme == null) {
				url = "https://" + url;
			} else if (!scheme.equals("https")) {
				throw new IllegalArgumentException("S3 endpoint must use https not " + scheme);
			}
		}
		return url;
	}

	/**
	 * Domains, if multi-domain setup is used, otherwise {@code null}.
	 */
	private Domains domains;
	/**
	 * S3 clients provider.
	 */
	private S3ProxyClientProvider s3clients;
	/**
	 * S3 processor.
	 */
	private S3Processor s3processor;
	/**
	 * Device group provider.
	 */
	private DeviceGroupProvider deviceGroupProvider;
	/**
	 * Web application configuration provider.
	 */
	private WebAppConfigProvider webAppConfigProvider;
	/**
	 * Web application user provider.
	 */
	private WebAppUserProvider domainUserProvider;
	/**
	 * Device based forward provider.
	 * 
	 * @since 4.0
	 */
	private HttpForwardConfigurationProvider deviceHttpForwardProvider;
	/**
	 * Device notifier.
	 * 
	 * @since 4.0
	 */
	private BiConsumer<String, DeviceIdentifier> deviceNotifier;

	/**
	 * Create CoAP-S3-proxy server
	 * 
	 * @param config configuration to use
	 */
	public S3ProxyServer(Configuration config) {
		super(config);
		setTag("S3-Proxy");
	}

	@Override
	public void start() {
		super.start();
		if (s3processor != null) {
			s3processor.start();
		}
	}

	@Override
	public void stop() {
		super.stop();
		if (s3processor != null) {
			s3processor.stop();
		}
	}

	@Override
	public void setupDeviceCredentials(ServerConfig cliArguments, Credentials credentials) {
		S3ProxyConfig cliS3Arguments = (S3ProxyConfig) cliArguments;
		if (cliS3Arguments.mode.domainStore != null) {
			setupMultiDomainDeviceCredentials(cliS3Arguments, credentials);
		} else {
			setupSingleDomainDeviceCredentials(cliS3Arguments, credentials);
		}
	}

	/**
	 * Setup device credentials for single domain setup.
	 * 
	 * @param cliArguments command line arguments.
	 * @param credentials server's credentials for DTLS 1.2 certificate based
	 *            authentication
	 */
	public void setupSingleDomainDeviceCredentials(S3ProxyConfig cliArguments, Credentials credentials) {

		ConcurrentMap<String, ResourceStore<DeviceParser>> singleDomain = new ConcurrentHashMap<>();

		if (cliArguments.deviceStore != null) {
			long interval = getConfig().get(DEVICE_CREDENTIALS_RELOAD_INTERVAL, TimeUnit.SECONDS);
			boolean replace = cliArguments.provisioning != null ? cliArguments.provisioning.replace : false;
			if (replace) {
				LOGGER.info(
						"New device credentials will replace already available ones. Use this only for development!");
			}
			DeviceParser factory = new DeviceParser(true, replace, HttpForwardServiceManager.getDeviceConfigFields());
			final ResourceStore<DeviceParser> configResource = new ResourceStore<>(factory).setTag("Devices ");
			configResource.loadAndCreateMonitor(cliArguments.deviceStore.file, cliArguments.deviceStore.password64,
					interval > 0);
			monitors.addOptionalMonitor("Devices", interval, TimeUnit.SECONDS, configResource.getMonitor());
			singleDomain.put(DEFAULT_DOMAIN, configResource);
		}

		long addTimeout = getConfig().get(DEVICE_CREDENTIALS_ADD_TIMEOUT, TimeUnit.MILLISECONDS);
		DomainDeviceManager deviceManager = new DomainDeviceManager(singleDomain, credentials, addTimeout);
		deviceGroupProvider = deviceManager;
		deviceCredentials = deviceManager;
		deviceHttpForwardProvider = deviceManager;

		createS3Client(cliArguments.mode.single.s3Config);
	}

	/**
	 * Setup device credentials for multi domain setup.
	 * 
	 * @param cliArguments command line arguments.
	 * @param credentials server's credentials for DTLS 1.2 certificate based
	 *            authentication
	 */
	public void setupMultiDomainDeviceCredentials(S3ProxyConfig cliArguments, Credentials credentials) {
		ResourceStore<LinuxConfigParser> domainStore = new ResourceStore<>(new LinuxConfigParser(false, false))
				.setTag("Domains ");
		domainStore.loadAndCreateMonitor(cliArguments.mode.domainStore.file, cliArguments.mode.domainStore.password64,
				false);
		LinuxConfigParser configuration = domainStore.getResource();
		domains = new Domains(monitors, configuration, getConfig());
		s3clients = domains;
		DomainDeviceManager deviceManager = domains.loadDevices(credentials, getConfig());
		deviceGroupProvider = deviceManager;
		deviceCredentials = deviceManager;
		deviceHttpForwardProvider = deviceManager;
	}

	@Override
	public void addResource(ServerConfig cliArguments, ScheduledExecutorService executor) {
		if (s3clients != null) {
			S3ProxyConfig cliS3Arguments = (S3ProxyConfig) cliArguments;
			// add resources to the server
			if (cliArguments.diagnose) {
				add(new Diagnose(this));
			}
			HttpForwardConfigurationProvider forward = domains;
			if (forward == null) {
				if (cliS3Arguments.mode.single != null && cliS3Arguments.mode.single.httpForward != null) {
					S3ProxyConfig.HttpForward httpForward = cliS3Arguments.mode.single.httpForward;
					String forwardDestination = httpForward.httpForward;
					if (forwardDestination != null) {
						String serviceName = httpForward.httpServiceName;
						if (HttpForwardServiceManager.getService(serviceName) != null) {
							final String authentication = httpForward.httpAuthentication;
							final String responseFilter = httpForward.httpResponseFilter;
							final DeviceIdentityMode deviceIdentityMode = httpForward.httpDeviceIdentityMode;
							LOGGER.info("http forward {}, {}", forwardDestination, deviceIdentityMode);
							if (responseFilter != null) {
								LOGGER.info("http forward response filter {}", responseFilter);
							}
							if (serviceName != null) {
								LOGGER.info("http forward java-service {}", serviceName);
							}
							forward = new BasicHttpForwardConfiguration(forwardDestination, authentication,
									deviceIdentityMode, responseFilter, serviceName, Collections.emptyMap());
						} else if (serviceName == null) {
							LOGGER.warn("Failed to configure http forward '{}', default java-service not available.",
									forwardDestination);
						} else {
							LOGGER.warn("Failed to configure http forward '{}', java-service {} not available.",
									forwardDestination, serviceName);
						}
					}
				}
			}
			HttpForwardConfigurationProvider provider = new HttpForwardConfigurationProviders(deviceHttpForwardProvider,
					forward);
			HttpForwardServiceManager.createHealthStatistics(getTag(), s3clients.getDomains()).forEach((health) -> {
				addServerStatistic(health, true);
			});

			add(new MyContext(MyContext.RESOURCE_NAME, CALIFORNIUM_BUILD_VERSION, false));
			S3Devices s3Devices = new S3Devices(getConfig(), s3clients, provider);
			add(s3Devices);
			this.deviceNotifier = s3Devices.getDeviceNotifier();
			add(new S3ProxyResource("fw", 0, getConfig(), s3clients));
			if (cliArguments.provisioning != null && cliArguments.provisioning.provisioning
					&& deviceCredentials instanceof DeviceProvisioningConsumer) {
				add(new Provisioning((DeviceProvisioningConsumer) deviceCredentials));
			}
		} else {
			super.addResource(cliArguments, executor);
		}
	}

	@Override
	public void setupHttpService(ServerConfig cliArguments) {
		HttpService httpService = HttpService.getHttpService();
		if (httpService != null) {
			S3ProxyConfig cliS3Arguments = ((S3ProxyConfig) cliArguments);
			S3ProxyConfig.SinglePageApplication cliSpaArguments = cliS3Arguments.spa;
			if (cliSpaArguments == null) {
				throw new RuntimeException("http-service requires one of the '--spa-???' parameter.");
			}
			LOGGER.info("Create Single Page Application.");
			boolean withDiagnose = false;
			if (domains != null) {
				setupMultiDomainHttpService(cliS3Arguments);
			} else {
				setupSingleDomainHttpService(cliS3Arguments);
			}
			Aws4Authorizer aws4 = new Aws4Authorizer(domainUserProvider, S3ProxyClient.DEFAULT_REGION);
			if (cliArguments.diagnose && !cliArguments.noCoap) {
				AuthorizedCoapProxyHandler proxy = new AuthorizedCoapProxyHandler("proxy", aws4, webAppConfigProvider,
						this, httpService.getExecutor(), "/" + Diagnose.RESOURCE_NAME);
				httpService.createContext("/proxy", proxy);
				withDiagnose = true;
			}
			httpService.createContext("/login",
					new S3Login(aws4, s3clients, webAppConfigProvider, deviceGroupProvider, withDiagnose));
			if (deviceGroupProvider != null) {
				httpService.createContext("/groups", new GroupsHandler(aws4, deviceGroupProvider));
				Integer maxDeviceConfigSize = getConfig().get(MAX_DEVICE_CONFIG_SIZE);
				if (maxDeviceConfigSize > 0) {
					httpService.createContext("/config/", new ConfigHandler(maxDeviceConfigSize, aws4, s3clients,
							webAppConfigProvider, deviceGroupProvider, deviceNotifier));
				}
			}
			S3ProxyClient webClient = cliSpaArguments.s3 ? s3clients.getWebClient() : null;

			SinglePageApplication spa = new SinglePageApplication("CloudCoap", webClient,
					cliSpaArguments.singlePageApplicationCss, cliSpaArguments.singlePageApplicationScript);
			httpService.createContext("/", spa);

			if (cliSpaArguments.singlePageApplicationScriptV2 != null) {
				SinglePageApplication spaV2 = new SinglePageApplication("CloudCoap V2", webClient,
						cliSpaArguments.singlePageApplicationCss, cliSpaArguments.singlePageApplicationScriptV2);
				httpService.createContext("/v2", spaV2);
			}

			if (cliSpaArguments.singlePageApplicationScriptV1 != null) {
				SinglePageApplication spaV1 = new SinglePageApplication("CloudCoap V1", webClient,
						cliSpaArguments.singlePageApplicationCss, cliSpaArguments.singlePageApplicationScriptV1);
				httpService.createContext("/v1", spaV1);
			}

			String defaultScheme = cliSpaArguments.s3 ? S3_SCHEME : HTTPS_SCHEME;
			if (SinglePageApplication.getScheme(cliSpaArguments.singlePageApplicationScript, defaultScheme)
					.equals(HTTPS_SCHEME)) {
				httpService.createFileHandler(cliSpaArguments.singlePageApplicationScript,
						"text/javascript; charset=utf-8", cliSpaArguments.singlePageApplicationReload);
			}
			if (cliSpaArguments.singlePageApplicationScriptV2 != null) {
				if (SinglePageApplication.getScheme(cliSpaArguments.singlePageApplicationScriptV2, defaultScheme)
						.equals(HTTPS_SCHEME)) {
					httpService.createFileHandler(cliSpaArguments.singlePageApplicationScriptV2,
							"text/javascript; charset=utf-8", cliSpaArguments.singlePageApplicationReload);
				}
			}
			if (SinglePageApplication.getScheme(cliSpaArguments.singlePageApplicationCss, defaultScheme)
					.equals(HTTPS_SCHEME)) {
				httpService.createFileHandler(cliSpaArguments.singlePageApplicationCss, "text/css; charset=utf-8",
						cliSpaArguments.singlePageApplicationReload);
			}
		}
	}

	/**
	 * Setup HTTP service for single domain setup.
	 * 
	 * @param cliArguments command line arguments.
	 */
	public void setupSingleDomainHttpService(S3ProxyConfig cliArguments) {
		S3ProxyConfig.S3Config s3Arguments = cliArguments.mode.single.s3Config;
		if (s3Arguments != null && s3Arguments.externalEndpoint != null) {
			long interval = getConfig().get(USER_CREDENTIALS_RELOAD_INTERVAL, TimeUnit.SECONDS);

			final ResourceStore<WebAppUserParser> userStore = new ResourceStore<>(new WebAppUserParser(false))
					.setTag("Users ");

			createS3Client(s3Arguments);

			if (cliArguments.mode.single.userStore != null) {
				userStore.loadAndCreateMonitor(cliArguments.mode.single.userStore.file,
						cliArguments.mode.single.userStore.password64, interval > 0);
				monitors.addOptionalMonitor("Users", interval, TimeUnit.SECONDS, userStore.getMonitor());
			} else {
				WebAppUser.Builder builder = WebAppUser.builder();
				builder.name = "Thingy:91";
				builder.password = "cloudcoap";
				builder.accessKeyId = s3Arguments.accessKey;
				builder.accessKeySecret = s3Arguments.secret;
				userStore.getResource().add(builder.build());
				LOGGER.warn("Using the default user is not recommended! Please provide a '--user-file'.");
			}

			if (cliArguments.mode.single.configStore != null) {
				final ResourceStore<LinuxConfigParser> configStore = new ResourceStore<>(
						new LinuxConfigParser(false, false)).setTag("Configs ");
				configStore.loadAndCreateMonitor(cliArguments.mode.single.configStore.file,
						cliArguments.mode.single.configStore.password64, interval > 0);
				monitors.addOptionalMonitor("Configs", interval, TimeUnit.SECONDS, configStore.getMonitor());
				webAppConfigProvider = new WebAppConfigProvider() {

					@Override
					public Map<String, Map<String, String>> getSubSections(String domain, String section) {

						return configStore.getResource().getSubSections(section);
					}

					@Override
					public String get(String domain, String section, String name) {
						return configStore.getResource().get(section, name);
					}

					@Override
					public String remove(String domain, String section, String name) {
						return configStore.getResource().remove(section, name);
					}
				};
			}
			domainUserProvider = new WebAppUserProvider() {

				@Override
				public WebAppDomainUser getDomainUser(String domainName, String userName) {
					if (domainName == null || domainName.equals(DEFAULT_DOMAIN)) {
						WebAppUser user = userStore.getResource().get(userName);
						if (user != null) {
							return new WebAppDomainUser(DEFAULT_DOMAIN, user);
						}
					}
					return null;
				}

			};
		} else {
			throw new RuntimeException("http-service requires '--s3-external-endpoint'.");
		}
	}

	/**
	 * Setup HTTP service for multi domain setup.
	 * 
	 * @param cliArguments command line arguments.
	 */
	public void setupMultiDomainHttpService(S3ProxyConfig cliArguments) {
		domains.loadHttpUsers(getConfig());
		domainUserProvider = domains;
		webAppConfigProvider = domains;
		s3clients = domains;
	}

	/**
	 * Create S3 client.
	 * 
	 * @param s3Arguments command line arguments.
	 * @return S3 client
	 */
	public S3ProxyClient createS3Client(S3ProxyConfig.S3Config s3Arguments) {
		if (s3Arguments != null && s3clients == null) {
			long minutes = getConfig().get(BaseServer.CACHE_STALE_DEVICE_THRESHOLD, TimeUnit.MINUTES);
			int maxDevices = getConfig().get(BaseServer.CACHE_MAX_DEVICES);
			final S3ProxyClient s3Client = createS3Client(s3Arguments, minutes, maxDevices);
			s3clients = new S3ProxyClientProvider() {

				private final Set<String> DEFAULT = Collections.singleton("default");

				@Override
				public Set<String> getDomains() {
					return DEFAULT;
				}

				@Override
				public S3ProxyClient getProxyClient(String domain) {
					return s3Client;
				}

				@Override
				public S3ProxyClient getWebClient() {
					return s3Client;
				}
			};
			return s3Client;
		}
		return null;
	}

	/**
	 * Create S3 client.
	 * 
	 * @param s3Arguments command line arguments.
	 * @param minutes threshold in minutes to keep devices without communication
	 * @param maxDevices maximum devices
	 * @return S3 client
	 */
	public static S3ProxyClient createS3Client(S3ProxyConfig.S3Config s3Arguments, long minutes, int maxDevices) {
		if (s3Arguments != null) {
			int minDevices = maxDevices / 10;
			if (minDevices < 100) {
				minDevices = maxDevices;
			}

			LOGGER.info("S3 endpoint: {}", s3Arguments.endpoint);
			LOGGER.info("S3 extern  : {}", s3Arguments.externalEndpoint);
			LOGGER.info("S3 bucket  : {}", s3Arguments.bucket);
			LOGGER.info("S3 region  : {}", s3Arguments.region);
			LOGGER.info("S3 acl     : {}", s3Arguments.acl);

			S3AsyncProxyClient.Builder builder = S3AsyncProxyClient.builder();
			if (s3Arguments.endpoint != null) {
				builder.endpoint(s3Arguments.endpoint);
			}
			if (s3Arguments.externalEndpoint != null) {
				builder.externalEndpoint(s3Arguments.externalEndpoint);
			}
			builder.concurrency(s3Arguments.concurrency);
			builder.bucket(s3Arguments.bucket);
			builder.acl(s3Arguments.acl);
			builder.region(s3Arguments.region);
			builder.keyId(s3Arguments.accessKey);
			builder.keySecret(s3Arguments.secret);
			builder.threshold(minutes, TimeUnit.MINUTES);
			builder.minEtags(minDevices);
			builder.maxEtags(maxDevices);
			builder.supportRedirect(s3Arguments.redirect);
			builder.useCompression(s3Arguments.compress);
			return builder.build();
		}
		return null;
	}

	@Override
	public void setupProcessors(ServerConfig cliArguments, ScheduledExecutorService secondaryExecutor) {
		if (s3clients != null) {
			S3ProxyConfig cli = (S3ProxyConfig) cliArguments;
			S3ProcessorHealthLogger health = new S3ProcessorHealthLogger(getTag(), s3clients.getDomains());
			s3processor = new S3Processor(cli.s3Processor, getConfig(), s3clients, health, secondaryExecutor);
			// S3ProcessorHealthLogger are dumped based on the jobs,
			// not on intervals
			addServerStatistic(health, false);
		}
	}
}
