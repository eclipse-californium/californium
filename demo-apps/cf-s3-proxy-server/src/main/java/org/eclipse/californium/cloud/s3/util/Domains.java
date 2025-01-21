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
package org.eclipse.californium.cloud.s3.util;

import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.cloud.BaseServer;
import org.eclipse.californium.cloud.s3.S3ProxyServer;
import org.eclipse.californium.cloud.s3.S3ProxyServer.S3ProxyConfig.S3Config;
import org.eclipse.californium.cloud.s3.forward.BasicHttpForwardConfiguration;
import org.eclipse.californium.cloud.s3.forward.HttpForwardConfiguration;
import org.eclipse.californium.cloud.s3.forward.HttpForwardConfigurationProvider;
import org.eclipse.californium.cloud.s3.forward.HttpForwardServiceManager;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClient;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClientProvider;
import org.eclipse.californium.cloud.s3.proxy.S3ResourceStore;
import org.eclipse.californium.cloud.util.DeviceParser;
import org.eclipse.californium.cloud.util.LinuxConfigParser;
import org.eclipse.californium.cloud.util.ResourceStore;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.SslContextUtil.Credentials;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.elements.util.SystemResourceMonitors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Domains.
 * <p>
 * User, configurations and devices grouped in domains.
 * <p>
 * Domains are defined in a file with format:
 * 
 * <pre>
 * {@code # <comment>}
 * {@code \[<domain>.data\]}
 * {@code [bucket = <S3-bucket-name>]}
 * {@code [access_key = <S3-access_key>]}
 * {@code [secret_key = <S3-secret_key>]}
 * {@code [bucket_location = <region>]}
 * {@code [host_base = <S3-host_base>]}
 * {@code [host_bucket = <S3-host_bucket>]}
 * {@code [concurrency = <number-of-clients>]}
 * {@code [redirect = true|false]}
 * {@code [max_devices = <max-number-of-devices>]}
 * 
 * {@code \[<domain>.management\]}
 * {@code [bucket = <S3-bucket-name>]}
 * {@code [access_key = <S3-access-key>]}
 * {@code [secret_key = <S3-secret-key>]}
 * {@code [bucket_location = <region>]}
 * {@code [host_base = <S3-host-base>]}
 * {@code [host_bucket = <S3-host-bucket>]}
 * {@code [concurrency = <number-of-clients>]}
 * {@code [redirect = true|false]}
 * {@code [password64 = <default-store-password-base64>]}
 * {@code [device_store = <device-store>]}
 * {@code [device_store_password64 = <device-store-password-base64>]}
 * {@code [config_store = <config-store>]}
 * {@code [config_store_password64 = <config-store-password-base64>]}
 * {@code [user_store = <user-store>]}
 * {@code [user_store_password64 = <user-store-password-base64>]}
 * {@code [user_store_password64 = <user-store-password-base64>]}
 * {@code [devices_replaced = true|false]}
 * {@code [http_forward = <http forward destination>]}
 * {@code [http_authentication = <http authentication>]}
 * {@code [http_device_identity_mode = NONE|HEADLINE|QUERY_PARAMETER]}
 * {@code [http_response_filter = <regex response filter>]}
 * {@code [http_service_name = <java-http-forwarding-service>]}
 * 
 * With {@code <http authentication>}:
 * {@code Bearer <bearer token>}
 * {@code Header <http-header-name>:<http-header-value>}
 * {@code PreBasic <username>:<password>}
 * {@code <username>:<password>}
 * 
 * </pre>
 * 
 * If auto-provisioning is used, {@code devices_replaced} defines, that only new
 * devices are allowed, or also old ones are replaced.
 * <p>
 * If http forwarding is used and a http authentication is provided, `Bearer`
 * will be converted into an http-header `Authentication: Bearer
 * {@code <bearer token>}`. `Header` will be added as http-header
 * `{@code <http-header-name>:<http-header-value>}`. `PreBasic` will do a basic
 * authentication in preemptive manner, it sends the credentials without prior
 * request. If `{@code <username>:<password>}` is used, the credentials for
 * basic authentication are only sent on request by the server.
 * <p>
 * The response filter for http forwarding is a regular expression, which on
 * match, drops the http response-payload from being forwarded to the device. If
 * no filter is provide or the filter is empty, the http response-payload is
 * always dropped.
 * <p>
 * The web application configuration {@code config_store} is defined using
 * format:
 * 
 * <pre>
 * {@code # <comment>}
 * {@code \[<config-name>.<subsection1>\]}
 * {@code [<name1> = <value1>]}
 * {@code [<name2> = <value2>]}
 * 
 * {@code \[<config-name>.<subsection2>\]}
 * {@code [<name1> = <value1>]}
 * {@code [<name2> = <value2>]}
 * 
 * {@code \[<config-name2>.<subsection>\]}
 * {@code [<name1> = <value1>]}
 * {@code [<name2> = <value2>]}
 * </pre>
 * 
 * For {@code device_store}, see {@link DeviceParser} and for {@code user_store}
 * see {@link WebAppUserParser}.
 * <p>
 * The web application configuration is used in a generic way passing all the
 * sub-section values to the web application on login. The only specific access
 * is using the sub-section {@code <user-config>.config} and accesses the value
 * {@code "diagnose"} in order to enable proxy access to the CoAP-Diagnose
 * resource.
 * <p>
 * The java-script-single-page-application supports these passed configuration
 * values:
 * 
 * <pre>
 * config.diagnose
 * config.configRead
 * config.configWrite
 * config.logo
 * config.period
 * config.signals
 * config.sensors
 * config.average
 * config.minmax
 * config.zoom
 * config.details
 * 
 * {@code defs.<provider1>}
 * {@code defs.<provider2>}
 * ...
 * </pre>
 * 
 * @since 3.12
 */
public class Domains
		implements S3ProxyClientProvider, WebAppUserProvider, WebAppConfigProvider, HttpForwardConfigurationProvider {

	private static final Logger LOGGER = LoggerFactory.getLogger(Domains.class);

	/**
	 * Section suffix for device data section.
	 */
	public static final String DATA_SUFFIX = ".data";
	/**
	 * Section suffix for management section.
	 */
	public static final String MANAGEMENT_SUFFIX = ".management";
	/**
	 * Section for web resources.
	 */
	public static final String WEB_SECTION = "web";
	/**
	 * Section for anonymous clients.
	 */
	public static final String ANONYOUS_SECTION = "anonymous";
	/**
	 * Field name for maximum devices.
	 */
	public static final String FIELD_MAX_DEVICES = "max_devices";

	/**
	 * Domain.
	 */
	private static class Domain {

		/**
		 * S3 client for device data.
		 */
		private S3ProxyClient deviceData;
		/**
		 * S3 client for management data.
		 * <p>
		 * May be {@code null}, if management data is loaded from file-system.
		 */
		private S3ProxyClient managementData;
		/**
		 * User store.
		 */
		private ResourceStore<WebAppUserParser> userStore;
		/**
		 * "Single Page Application" configuration store.
		 */
		private ResourceStore<LinuxConfigParser> configStore;
		/**
		 * Http forwarding configuration.
		 * 
		 * @since 4.0
		 */
		private HttpForwardConfiguration httpForwardingConfiguration;

		/**
		 * Create domain instance.
		 */
		private Domain() {
		}
	}

	/**
	 * Resource monitors for automatic reloading.
	 */
	private final SystemResourceMonitors monitors;
	/**
	 * Configuration of domain.
	 */
	private final LinuxConfigParser configuration;
	/**
	 * Map of domain-names and domains.
	 */
	private final ConcurrentMap<String, Domain> domains = new ConcurrentHashMap<>();
	/**
	 * Domain to load web-resources, e.g. javascript app or ccs.
	 */
	private final Domain webDomain;

	private final HttpForwardConfiguration anonymousHttpForwardingConfiguration;

	/**
	 * Create domains setup.
	 * 
	 * @param monitors monitor to reload resources.
	 * @param domainDefinition domain configuration.
	 * @param config Californium configuration.
	 */
	public Domains(SystemResourceMonitors monitors, LinuxConfigParser domainDefinition, Configuration config) {
		long staleDeviceThreshold = config.get(BaseServer.CACHE_STALE_DEVICE_THRESHOLD, TimeUnit.MINUTES);
		int maxDevices = config.get(BaseServer.CACHE_MAX_DEVICES);
		String web = domainDefinition.get(WEB_SECTION, "domain");
		Domain webDomain = null;
		HttpForwardConfiguration httpForwardingConfiguration = null;

		this.monitors = monitors;
		this.configuration = domainDefinition;

		for (String section : domainDefinition.getSections()) {
			String name = StringUtil.truncateTail(true, section, DATA_SUFFIX);
			if (name != section) {
				String managementSection = name + MANAGEMENT_SUFFIX;
				if (domainDefinition.hasSection(managementSection)) {

					Domain domain = new Domain();
					S3Config s3Config = new S3Config();
					s3Config.concurrency = 200;
					s3Config.apply(domainDefinition, section);
					int max = domainDefinition.getInteger(section, FIELD_MAX_DEVICES, maxDevices);
					domain.deviceData = S3ProxyServer.createS3Client(s3Config, staleDeviceThreshold, max);
					List<String> domainConfigFields = HttpForwardServiceManager.getDomainConfigFields();
					if (domainConfigFields != null) {
						Map<String, String> fields = new HashMap<>();
						for (String field : domainConfigFields) {
							String value = domainDefinition.get(managementSection, field);
							fields.put(field, value);
						}
						try {
							domain.httpForwardingConfiguration = BasicHttpForwardConfiguration.create(fields);
							if (domain.httpForwardingConfiguration != null) {
								LOGGER.info("{}: http forward {}, {}", name,
										domain.httpForwardingConfiguration.getDestination(),
										domain.httpForwardingConfiguration.getDeviceIdentityMode());
							}
						} catch (URISyntaxException e) {
							LOGGER.warn("Failed to configure http forward '{}' for domain {}.", e.getInput(), section);
						}
					}
					s3Config = new S3Config();
					s3Config.concurrency = 5;
					s3Config.apply(domainDefinition, managementSection);
					if (s3Config.accessKey != null) {
						domain.managementData = S3ProxyServer.createS3Client(s3Config, staleDeviceThreshold, 5);
					}
					domains.put(name, domain);
					if (web == null && webDomain == null) {
						webDomain = domain;
					}
				}
			} else if (ANONYOUS_SECTION.equals(section)) {
				List<String> domainConfigFields = HttpForwardServiceManager.getDomainConfigFields();
				if (domainConfigFields != null) {
					Map<String, String> fields = new HashMap<>();
					for (String field : domainConfigFields) {
						String value = domainDefinition.get(section, field);
						fields.put(field, value);
					}
					try {
						httpForwardingConfiguration = BasicHttpForwardConfiguration.create(fields);
						if (httpForwardingConfiguration != null) {
							LOGGER.info("{}: http forward {}, {}", name, httpForwardingConfiguration.getDestination(),
									httpForwardingConfiguration.getDeviceIdentityMode());
						}
					} catch (URISyntaxException e) {
						LOGGER.warn("Failed to configure http forward '{}' for domain {}.", e.getInput(), section);
					}
				}
			}
		}
		if (web != null && webDomain == null) {
			webDomain = domains.get(web);
		}
		this.webDomain = webDomain;
		this.anonymousHttpForwardingConfiguration = httpForwardingConfiguration;
	}

	/**
	 * Load device credentials.
	 * 
	 * @param credentials server's credentials for DTLS 1.2 certificate based
	 *            authentication
	 * @param config Californium configuration.
	 * @return domain device manager
	 */
	public DomainDeviceManager loadDevices(Credentials credentials, Configuration config) {
		long interval = config.get(BaseServer.DEVICE_CREDENTIALS_RELOAD_INTERVAL, TimeUnit.SECONDS);
		long addTimeout = config.get(BaseServer.DEVICE_CREDENTIALS_ADD_TIMEOUT, TimeUnit.MILLISECONDS);
		ConcurrentMap<String, ResourceStore<DeviceParser>> allDevices = new ConcurrentHashMap<>();

		for (Entry<String, Domain> domainEntry : domains.entrySet()) {
			Domain domain = domainEntry.getValue();
			String managementSection = domainEntry.getKey() + MANAGEMENT_SUFFIX;

			String password64 = configuration.get(managementSection, "password64");
			Boolean replace = configuration.getBoolean(managementSection, "devices_replaced", Boolean.FALSE);
			if (replace) {
				LOGGER.info(
						"{}: new device credentials will replace already available ones. Use this only for development!",
						domainEntry.getKey());
			}

			String deviceStore = configuration.getWithDefault(managementSection, "device_store", "devices.txt");
			String deviceStorePw = configuration.getWithDefault(managementSection, "device_store_password64",
					password64);
			DeviceParser deviceParser = new DeviceParser(true, replace,
					HttpForwardServiceManager.getDeviceConfigFields());
			ResourceStore<DeviceParser> devices = domain.managementData != null
					? new S3ResourceStore<>(deviceParser, domain.managementData).setTag("S3 Devices ")
					: new ResourceStore<>(deviceParser).setTag("File Devices ");
			devices.loadAndCreateMonitor(deviceStore, deviceStorePw, interval > 0);
			monitors.addOptionalMonitor(devices.getTag() + domainEntry.getKey(), interval, TimeUnit.SECONDS,
					devices.getMonitor());
			allDevices.put(domainEntry.getKey(), devices);
		}
		return new DomainDeviceManager(allDevices, credentials, addTimeout);
	}

	/**
	 * Load web application users and configurations.
	 * 
	 * @param config Californium configuration.
	 */
	public void loadHttpUsers(Configuration config) {
		long interval = config.get(S3ProxyServer.USER_CREDENTIALS_RELOAD_INTERVAL, TimeUnit.SECONDS);
		LinuxConfigParser configFactory = new LinuxConfigParser(false, false);
		WebAppUserParser userFactory = new WebAppUserParser(false);
		for (Entry<String, Domain> domainEntry : domains.entrySet()) {
			Domain domain = domainEntry.getValue();
			String managementSection = domainEntry.getKey() + MANAGEMENT_SUFFIX;

			String password64 = configuration.get(managementSection, "password64");

			String configStore = configuration.getWithDefault(managementSection, "config_store", "config.txt");
			String configStorePw = configuration.getWithDefault(managementSection, "config_store_password64",
					password64);
			domain.configStore = domain.managementData != null
					? new S3ResourceStore<>(configFactory, domain.managementData).setTag("S3 Configs ")
					: new ResourceStore<>(configFactory).setTag("File Configs ");
			domain.configStore.loadAndCreateMonitor(configStore, configStorePw, interval > 0);
			monitors.addOptionalMonitor(domain.configStore.getTag() + domainEntry.getKey(), interval, TimeUnit.SECONDS,
					domain.configStore.getMonitor());

			String userStore = configuration.getWithDefault(managementSection, "user_store", "users.txt");
			String userStorePw = configuration.getWithDefault(managementSection, "user_store_password64", password64);
			domain.userStore = domain.managementData != null
					? new S3ResourceStore<>(userFactory, domain.managementData).setTag("S3 Users ")
					: new ResourceStore<>(userFactory).setTag("File Users ");
			domain.userStore.loadAndCreateMonitor(userStore, userStorePw, interval > 0);
			monitors.addOptionalMonitor(domain.userStore.getTag() + domainEntry.getKey(), interval, TimeUnit.SECONDS,
					domain.userStore.getMonitor());
		}
	}

	@Override
	public Set<String> getDomains() {
		return domains.keySet();
	}

	@Override
	public S3ProxyClient getProxyClient(String domainName) {
		Domain domain = domains.get(domainName);
		if (domain != null) {
			return domain.deviceData;
		}
		return null;
	}

	@Override
	public S3ProxyClient getWebClient() {
		return webDomain.deviceData;
	}

	@Override
	public WebAppDomainUser getDomainUser(String domainName, String userName) {
		WebAppUser user = null;
		if (domainName != null) {
			Domain domain = domains.get(domainName);
			if (domain != null) {
				user = domain.userStore.getResource().get(userName);
				if (user != null) {
					return new WebAppDomainUser(domainName, user);
				}
			}
		} else {
			for (Entry<String, Domain> domain : domains.entrySet()) {
				WebAppUser match = domain.getValue().userStore.getResource().get(userName);
				if (match != null) {
					if (user == null) {
						user = match;
						domainName = domain.getKey();
					} else {
						// ambiguous
						user = null;
						break;
					}
				}
			}
			if (user != null && domainName != null) {
				return new WebAppDomainUser(domainName, user);
			}
		}
		return null;
	}

	@Override
	public Map<String, Map<String, String>> getSubSections(String domainName, String section) {
		Domain domain = domains.get(domainName);
		if (domain != null) {
			return domain.configStore.getResource().getSubSections(section);
		}
		return null;
	}

	@Override
	public String get(String domainName, String section, String name) {
		Domain domain = domains.get(domainName);
		if (domain != null) {
			return domain.configStore.getResource().get(section, name);
		}
		return null;
	}

	@Override
	public String remove(String domainName, String section, String name) {
		Domain domain = domains.get(domainName);
		if (domain != null) {
			return domain.configStore.getResource().remove(section, name);
		}
		return null;
	}

	@Override
	public HttpForwardConfiguration getConfiguration(DomainPrincipalInfo principalInfo) {
		if (DomainApplicationAnonymous.ANONYMOUS_INFO.equals(principalInfo)
				|| DomainApplicationAnonymous.APPL_AUTH_INFO.equals(principalInfo)) {
			return anonymousHttpForwardingConfiguration;
		}
		Domain domain = domains.get(principalInfo.domain);
		if (domain != null) {
			return domain.httpForwardingConfiguration;
		}
		return null;
	}

}
