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
package org.eclipse.californium.cloud.s3.forward;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;

import org.eclipse.californium.elements.util.CounterStatisticManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Http forward service manager.
 * 
 * @since 4.0
 */
public class HttpForwardServiceManager {

	/**
	 * Logger.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(HttpForwardServiceManager.class);

	/**
	 * Map of names to service implementations.
	 */
	private static Map<String, HttpForwardService> httpForwards = new HashMap<>();
	private static final HttpForwardService defaultService;
	private static final List<String> deviceConfigFields = new ArrayList<>();
	private static final List<String> domainConfigFields = new ArrayList<>();

	/**
	 * Loads all available services.
	 */
	static {
		ServiceLoader<HttpForwardService> loader = ServiceLoader.load(HttpForwardService.class);
		loader.forEach((service) -> {
			HttpForwardService previous = httpForwards.putIfAbsent(service.getName(), service);
			if (previous == null) {
				LOGGER.info("HttpForwardService {} loaded!", service.getName());
			} else {
				LOGGER.warn("HttpForwardService {} already loaded {}!", service.getName(),
						service.getClass().getSimpleName());
			}
			addIfAbsent(deviceConfigFields, service.getDeviceConfigFields());
			addIfAbsent(domainConfigFields, service.getDomainConfigFields());
		});
		deviceConfigFields.forEach((name) -> LOGGER.info("Extra-Field : {}", name));
		domainConfigFields.forEach((name) -> LOGGER.info("Extra-Config: {}", name));
		if (httpForwards.isEmpty()) {
			LOGGER.info("No HttpForwardService loaded!");
			defaultService = null;
		} else if (httpForwards.size() == 1) {
			LOGGER.info("HttpForwardService loaded!");
			defaultService = httpForwards.values().iterator().next();
		} else {
			defaultService = httpForwards.get(BasicHttpForwardService.SERVICE_NAME);
			LOGGER.info("{} HttpForwardServices loaded!", httpForwards.size());
		}
	}

	/**
	 * Creates health statistics for all http forward services.
	 * 
	 * @param tag service tag for logging
	 * @param domains set of domains
	 * @return list of health statistics
	 */
	public static List<CounterStatisticManager> createHealthStatistics(String tag, Set<String> domains) {
		List<CounterStatisticManager> healths = new ArrayList<>();
		httpForwards.values().forEach((service) -> {
			CounterStatisticManager health = service.createHealthStatistic(tag, domains);
			if (health != null) {
				healths.add(health);
			}
		});
		return healths;
	}

	/**
	 * Gets default service.
	 * <p>
	 * Either {@link BasicHttpForwardService}, if available, or any loaded
	 * {@link HttpForwardService} implementation, if that's the only one.
	 * 
	 * @return default service, or {@code null}, if not available
	 * @see #getService(String)
	 */
	public static HttpForwardService getDefaultService() {
		return defaultService;
	}

	/**
	 * Gets service by name.
	 * 
	 * @param name name of service. {@code null} for default service
	 * @return service, or {@code null}, if not available
	 * @see #getDefaultService()
	 */
	public static HttpForwardService getService(String name) {
		if (name == null) {
			return getDefaultService();
		} else {
			return httpForwards.get(name);
		}
	}

	/**
	 * Gets additional device configuration fields for http forwarding.
	 * 
	 * @return list of additional device configuration fields
	 */
	public static List<String> getDeviceConfigFields() {
		return deviceConfigFields;
	}

	/**
	 * Gets additional domain configuration fields for http forwarding.
	 * 
	 * @return list of additional domain configuration fields
	 */
	public static List<String> getDomainConfigFields() {
		return domainConfigFields;
	}

	/**
	 * Adds items of list to other list, if absent.
	 * 
	 * @param list list to add items if absent
	 * @param items list of items to add
	 */
	private static void addIfAbsent(List<String> list, List<String> items) {
		for (String item : items) {
			addIfAbsent(list, item);
		}
	}

	/**
	 * Adds items to list, if absent.
	 * 
	 * @param list list to add item if absent
	 * @param item item to add
	 */
	private static void addIfAbsent(List<String> list, String item) {
		if (!list.contains(item)) {
			list.add(item);
		}
	}
}
