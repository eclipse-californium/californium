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
import java.net.URI;
import java.net.URISyntaxException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.cloud.BaseServer;
import org.eclipse.californium.cloud.http.HttpService;
import org.eclipse.californium.cloud.option.ReadEtagOption;
import org.eclipse.californium.cloud.option.ReadResponseOption;
import org.eclipse.californium.cloud.option.TimeOption;
import org.eclipse.californium.cloud.resources.Diagnose;
import org.eclipse.californium.cloud.resources.MyContext;
import org.eclipse.californium.cloud.s3.http.AuthorizedCoapProxyHandler;
import org.eclipse.californium.cloud.s3.http.Aws4Authorizer;
import org.eclipse.californium.cloud.s3.http.S3Login;
import org.eclipse.californium.cloud.s3.http.SinglePageApplication;
import org.eclipse.californium.cloud.s3.option.ForwardResponseOption;
import org.eclipse.californium.cloud.s3.option.IntervalOption;
import org.eclipse.californium.cloud.s3.proxy.S3AsyncProxyClient;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClient;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClientProvider;
import org.eclipse.californium.cloud.s3.resources.S3Devices;
import org.eclipse.californium.cloud.s3.resources.S3ProxyResource;
import org.eclipse.californium.cloud.s3.util.DeviceGroupProvider;
import org.eclipse.californium.cloud.s3.util.DomainDeviceManager;
import org.eclipse.californium.cloud.s3.util.Domains;
import org.eclipse.californium.cloud.s3.util.HttpForwardDestinationProvider;
import org.eclipse.californium.cloud.s3.util.HttpForwardDestinationProvider.DeviceIdentityMode;
import org.eclipse.californium.cloud.s3.util.WebAppConfigProvider;
import org.eclipse.californium.cloud.s3.util.WebAppDomainUser;
import org.eclipse.californium.cloud.s3.util.WebAppUser;
import org.eclipse.californium.cloud.s3.util.WebAppUserParser;
import org.eclipse.californium.cloud.s3.util.WebAppUserProvider;
import org.eclipse.californium.cloud.util.DeviceManager;
import org.eclipse.californium.cloud.util.DeviceParser;
import org.eclipse.californium.cloud.util.LinuxConfigParser;
import org.eclipse.californium.cloud.util.ResourceStore;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.option.MapBasedOptionRegistry;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.Configuration.DefinitionsProvider;
import org.eclipse.californium.elements.config.TimeDefinition;
import org.eclipse.californium.proxy2.config.Proxy2Config;
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
			"Examples:", "  S3ProxyServer --no-loopback",
			"    (S3ProxyServer listening only on external network interfaces.)", "",
			"  S3ProxyServer --store-file dtls.bin --store-max-age 168 \\",
			"                --store-password64 ZVhiRW5pdkx1RUs2dmVoZg== \\",
			"                --device-file devices.txt --user-file users.txt", "",
			"    (S3ProxyServer with device credentials and web application user.",
			"     from file and dtls-graceful restart. Devices/sessions with no",
			"     exchange for more then a week (168 hours) are skipped when saving.)", "", })
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

			@Option(names = "--http-forward", required = true, description = "Http destination to forward coap-requests.")
			public String httpForward;

			@Option(names = "--http-authentication", description = "Http authentication for forward coap-requests.")
			public String httpAuthentication;

			@Option(names = "--http-device-identity-mode", defaultValue = "NONE", description = "Http device identity mode. Supported values: NONE, HEADLINE and QUERY_PARAMETER. Default: ${DEFAULT-VALUE}")
			public HttpForwardDestinationProvider.DeviceIdentityMode httpDeviceIdentityMode;
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

		public static class SinglePageApplication {

			@Option(names = "--spa-script", defaultValue = "app.js", required = true, description = "Single-Page-Application script. Default ${DEFAULT-VALUE}")
			public String singlePageApplicationScript;

			@Option(names = "--spa-css", defaultValue = "stylesheet.css", required = true, description = "Single-Page-Application Cascading Style Sheets. Default ${DEFAULT-VALUE}")
			public String singlePageApplicationCss;

			@Option(names = "--spa-reload", description = "Reload Single-Page-Application script.")
			public boolean singlePageApplicationReload;

			@Option(names = "--spa-s3", description = "Single-Page-Application in S3.")
			public boolean s3;

		}

		@Option(names = "--no-coap", negatable = true, description = "Disable coap endpoints.")
		public boolean coap = true;

		/**
		 * Setup dependent defaults.
		 */
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
		}
	}

	/**
	 * Interval to reload user credentials.
	 */
	public static final TimeDefinition USER_CREDENTIALS_RELOAD_INTERVAL = new TimeDefinition(
			"USER_CREDENTIALS_RELOAD_INTERVAL",
			"Reload user credentials interval. 0 to load credentials only on startup.", 30, TimeUnit.SECONDS);

	public static DefinitionsProvider DEFAULTS = new DefinitionsProvider() {

		@Override
		public void applyDefinitions(Configuration config) {
			BaseServer.DEFAULTS.applyDefinitions(config);
			config.set(USER_CREDENTIALS_RELOAD_INTERVAL, 30, TimeUnit.SECONDS);
		}
	};

	public static void main(String[] args) {
		MapBasedOptionRegistry registry = new MapBasedOptionRegistry(StandardOptionRegistry.getDefaultOptionRegistry(),
				TimeOption.DEFINITION, ReadEtagOption.DEFINITION, ReadResponseOption.DEFINITION,
				IntervalOption.DEFINITION, ForwardResponseOption.DEFINITION, TimeOption.DEPRECATED_DEFINITION);
		StandardOptionRegistry.setDefaultOptionRegistry(registry);

		Configuration configuration = Configuration.createWithFile(CONFIG_FILE, CONFIG_HEADER, DEFAULTS);
		start(args, S3ProxyServer.class.getSimpleName(), new S3ProxyConfig(), new S3ProxyServer(configuration));
	}

	/**
	 * Get valid URL with https scheme.
	 * 
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
	 * Create CoAP-S3-proxy server
	 * 
	 * @param config configuration to use
	 */
	public S3ProxyServer(Configuration config) {
		super(config);
		setTag("S3-Proxy");
	}

	@Override
	public void setupDeviceCredentials(ServerConfig cliArguments, PrivateKey privateKey, PublicKey publicKey) {
		S3ProxyConfig cliS3Arguments = (S3ProxyConfig) cliArguments;
		if (cliS3Arguments.mode.domainStore != null) {
			setupMultiDomainDeviceCredentials(cliS3Arguments, privateKey, publicKey);
		} else {
			setupSingleDomainDeviceCredentials(cliS3Arguments, privateKey, publicKey);
		}
	}

	/**
	 * Setup device credentials for single domain setup.
	 * 
	 * @param cliArguments command line arguments.
	 * @param privateKey private key for DTLS 1.2 device communication.
	 * @param publicKey public key for DTLS 1.2 device communication.
	 */
	public void setupSingleDomainDeviceCredentials(S3ProxyConfig cliArguments, PrivateKey privateKey,
			PublicKey publicKey) {
		ResourceStore<DeviceParser> devices = null;
		if (cliArguments.deviceStore != null) {
			long interval = getConfig().get(DEVICE_CREDENTIALS_RELOAD_INTERVAL, TimeUnit.SECONDS);
			DeviceParser factory = new DeviceParser(true);
			final ResourceStore<DeviceParser> configResource = new ResourceStore<>(factory).setTag("Devices ");
			configResource.loadAndCreateMonitor(cliArguments.deviceStore.file, cliArguments.deviceStore.password64,
					interval > 0);
			monitors.addOptionalMonitor("Devices", interval, TimeUnit.SECONDS, configResource.getMonitor());
			devices = configResource;
			deviceGroupProvider = new DeviceGroupProvider() {

				@Override
				public Set<String> getGroup(String domain, String group) {
					return configResource.getResource().getGroup(group);
				}
			};
		} else {
			deviceGroupProvider = new DeviceGroupProvider() {

				@Override
				public Set<String> getGroup(String domain, String group) {
					return Collections.emptySet();
				}

			};
		}

		createS3Client(cliArguments.mode.single.s3Config);
		deviceCredentials = new DeviceManager(devices, privateKey, publicKey);
	}

	/**
	 * Setup device credentials for multi domain setup.
	 * 
	 * @param cliArguments command line arguments.
	 * @param privateKey private key for DTLS 1.2 device communication.
	 * @param publicKey public key for DTLS 1.2 device communication.
	 */
	public void setupMultiDomainDeviceCredentials(S3ProxyConfig cliArguments, PrivateKey privateKey,
			PublicKey publicKey) {
		ResourceStore<LinuxConfigParser> domainStore = new ResourceStore<>(new LinuxConfigParser(false, false))
				.setTag("Domains ");
		domainStore.loadAndCreateMonitor(cliArguments.mode.domainStore.file, cliArguments.mode.domainStore.password64,
				false);
		LinuxConfigParser configuration = domainStore.getResource();
		domains = new Domains(monitors, configuration, getConfig());
		s3clients = domains;
		DomainDeviceManager deviceManager = domains.loadDevices(getConfig(), privateKey, publicKey);
		deviceGroupProvider = deviceManager;
		deviceCredentials = deviceManager;
	}

	@Override
	public void addResource(ServerConfig cliArguments, ScheduledExecutorService executor) {
		if (s3clients != null) {
			S3ProxyConfig cliS3Arguments = (S3ProxyConfig) cliArguments;
			// add resources to the server
			if (cliArguments.diagnose) {
				add(new Diagnose(this));
			}
			HttpForwardDestinationProvider forward = domains;
			if (forward == null) {
				if (cliS3Arguments.mode.single != null && cliS3Arguments.mode.single.httpForward != null) {
					String forwardDestination = cliS3Arguments.mode.single.httpForward.httpForward;
					if (forwardDestination != null) {
						try {
							final URI destination = new URI(forwardDestination);
							final String authentication = cliS3Arguments.mode.single.httpForward.httpAuthentication;
							final DeviceIdentityMode deviceIdentityMode = cliS3Arguments.mode.single.httpForward.httpDeviceIdentityMode;
							LOGGER.info("http forward {}, {}", destination, deviceIdentityMode);
							forward = new HttpForwardDestinationProvider() {

								@Override
								public URI getDestination(String domain) {
									return destination;
								}

								@Override
								public String getAuthentication(String domain) {
									return authentication;
								}

								@Override
								public DeviceIdentityMode getDeviceIdentityMode(String domain) {
									return deviceIdentityMode;
								}

							};
						} catch (URISyntaxException e) {
							LOGGER.warn("Failed to configure http forward '{}'.", forwardDestination);
						}
					}
				}
			}
			add(new MyContext(MyContext.RESOURCE_NAME, CALIFORNIUM_BUILD_VERSION, false));
			add(new S3Devices(getConfig(), s3clients, forward));
			add(new S3ProxyResource("fw", 0, getConfig(), s3clients));
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
			if (cliSpaArguments != null) {
				if (domains != null) {
					setupMultiDomainHttpService(cliS3Arguments);
				} else {
					setupSingleDomainHttpService(cliS3Arguments);
				}
				Aws4Authorizer aws4 = new Aws4Authorizer(domainUserProvider, S3ProxyClient.DEFAULT_REGION);
				httpService.createContext("/login",
						new S3Login(aws4, s3clients, webAppConfigProvider, deviceGroupProvider));
				S3ProxyClient webClient = cliSpaArguments.s3 ? s3clients.getWebClient() : null;
				SinglePageApplication spa = new SinglePageApplication("CloudCoap", webClient,
						cliSpaArguments.singlePageApplicationCss, cliSpaArguments.singlePageApplicationScript);
				httpService.createContext("/", spa);
				String defaultScheme = cliSpaArguments.s3 ? S3_SCHEME : HTTPS_SCHEME;

				if (SinglePageApplication.getScheme(cliSpaArguments.singlePageApplicationScript, defaultScheme)
						.equals(HTTPS_SCHEME)) {
					httpService.createFileHandler(cliSpaArguments.singlePageApplicationScript,
							"text/javascript; charset=utf-8", cliSpaArguments.singlePageApplicationReload);
				}
				if (SinglePageApplication.getScheme(cliSpaArguments.singlePageApplicationCss, defaultScheme)
						.equals(HTTPS_SCHEME)) {
					httpService.createFileHandler(cliSpaArguments.singlePageApplicationCss, "text/css; charset=utf-8",
							cliSpaArguments.singlePageApplicationReload);
				}
				if (cliArguments.diagnose && !cliArguments.noCoap) {
					AuthorizedCoapProxyHandler proxy = new AuthorizedCoapProxyHandler("proxy", aws4,
							webAppConfigProvider, this, httpService.getExecutor(), "/" + Diagnose.RESOURCE_NAME);
					httpService.createContext("/proxy", proxy);
				}
			} else {
				super.setupHttpService(cliS3Arguments);
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
			return builder.build();
		}
		return null;
	}
}
