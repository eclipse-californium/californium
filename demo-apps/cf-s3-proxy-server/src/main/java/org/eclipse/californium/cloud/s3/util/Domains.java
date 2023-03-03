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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.cloud.BaseServer;
import org.eclipse.californium.cloud.s3.S3ProxyServer;
import org.eclipse.californium.cloud.s3.S3ProxyServer.S3ProxyConfig.S3Config;
import org.eclipse.californium.cloud.s3.proxy.S3ResourceStore;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClient;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClientProvider;
import org.eclipse.californium.cloud.util.ResourceStore;
import org.eclipse.californium.cloud.util.DeviceParser;
import org.eclipse.californium.cloud.util.LinuxConfigParser;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.elements.util.SystemResourceMonitors;

/**
 * Domains.
 * 
 * User, configurations and devices grouped in domains.
 * 
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
 * </pre>
 * 
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
 * 
 * The web application configuration is used in a generic way passing all the
 * sub-section values to the web application on login. The only specific access
 * is using the sub-section {@code <user-config>.config} and accesses the value
 * {@code "diagnose"} in order to enable proxy access to the CoAP-Diagnose
 * resource.
 * 
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
public class Domains implements S3ProxyClientProvider, WebAppUserProvider, WebAppConfigProvider {

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
	 * Domain.
	 */
	private static class Domain {

		/**
		 * S3 client for device data.
		 */
		private S3ProxyClient deviceData;
		/**
		 * S3 client for management data.
		 * 
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

	private final Domain webDomain;

	/**
	 * Create domains setup.
	 * 
	 * @param monitors monitor to reload resources
	 * @param domainDefinition domain configuration
	 * @param config Californium configuration.
	 */
	public Domains(SystemResourceMonitors monitors, LinuxConfigParser domainDefinition, Configuration config) {
		long staleDeviceThreshold = config.get(BaseServer.CACHE_STALE_DEVICE_THRESHOLD, TimeUnit.MINUTES);
		int maxDevices = config.get(BaseServer.CACHE_MAX_DEVICES);
		String web = domainDefinition.get(WEB_SECTION, "domain");
		Domain webDomain = null;

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
					int max = domainDefinition.getInteger(section, "max_devices", maxDevices);
					domain.deviceData = S3ProxyServer.createS3Client(s3Config, staleDeviceThreshold, max);

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
			}
		}
		if (web != null && webDomain == null) {
			webDomain = domains.get(web);
		}
		this.webDomain = webDomain;
	}

	/**
	 * Load device credentials.
	 * 
	 * @param config Californium configuration.
	 * @param privateKey private key for DTLS 1.2 device communication.
	 * @param publicKey public key for DTLS 1.2 device communication.
	 * @return domain device manager
	 */
	public DomainDeviceManager loadDevices(Configuration config, PrivateKey privateKey, PublicKey publicKey) {
		long interval = config.get(BaseServer.DEVICE_CREDENTIALS_RELOAD_INTERVAL, TimeUnit.SECONDS);
		DeviceParser factory = new DeviceParser(true);
		ConcurrentMap<String, ResourceStore<DeviceParser>> allDevices = new ConcurrentHashMap<>();

		for (Entry<String, Domain> domainEntry : domains.entrySet()) {
			Domain domain = domainEntry.getValue();
			String managementSection = domainEntry.getKey() + MANAGEMENT_SUFFIX;

			String password64 = configuration.get(managementSection, "password64");

			String deviceStore = configuration.getWithDefault(managementSection, "device_store", "devices.txt");
			String deviceStorePw = configuration.getWithDefault(managementSection, "device_store_password64",
					password64);

			ResourceStore<DeviceParser> devices = domain.managementData != null
					? new S3ResourceStore<>(factory, domain.managementData).setTag("S3 Devices ")
					: new ResourceStore<>(factory).setTag("File Devices ");
			devices.loadAndCreateMonitor(deviceStore, deviceStorePw, interval > 0);
			monitors.addOptionalMonitor(devices.getTag() + domainEntry.getKey(), interval, TimeUnit.SECONDS,
					devices.getMonitor());
			allDevices.put(domainEntry.getKey(), devices);
		}
		return new DomainDeviceManager(allDevices, privateKey, publicKey);
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
		}
		if (user != null) {
			return new WebAppDomainUser(domainName, user);
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
}
