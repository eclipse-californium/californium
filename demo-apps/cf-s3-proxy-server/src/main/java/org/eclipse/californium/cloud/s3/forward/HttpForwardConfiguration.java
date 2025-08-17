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

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.eclipse.californium.core.coap.MediaTypeRegistry;

/**
 * Http forward configuration.
 * <p>
 * Includes destination, authentication, {@link DeviceIdentityMode}, and
 * response filter.
 * 
 * @since 4.0
 */
public interface HttpForwardConfiguration {

	/**
	 * Device identity mode.
	 */
	enum DeviceIdentityMode {

		/**
		 * No device identity is forwarded.
		 */
		NONE,
		/**
		 * The device identity is forwarded as headline in the payload. Requires
		 * text/plain content type!
		 */
		HEADLINE,
		/**
		 * The device identity is forwarded as query-parameter "id".
		 */
		QUERY_PARAMETER;

	};

	/**
	 * Gets http forward destination.
	 * 
	 * @return http forward destination.
	 */
	URI getDestination();

	/**
	 * Gets authentication credentials for the http forwarding.
	 * <p>
	 * Four types of authentication credentials are supported.
	 * <dl>
	 * <dt>{@code Bearer <bearer token>}</dt>
	 * <dd>adds an authentication http-header with that bearer token.</dd>
	 * <dt>{@code Header <http-header-name>:<http-header-value>}</dt>
	 * <dd>adds an http-header with that name and value.</dd>
	 * <dt>{@code PreBasic <username>:<password>}</dt>
	 * <dd>enables preemptive http-basic-authentication.</dd>
	 * <dt>{@code <username>:<password>}</dt>
	 * <dd>enables http-basic-authentication on request of server.</dd>
	 * </dl>
	 *
	 * @return authentication credentials, or {@code null}, if no authentication
	 *         is used.
	 */
	String getAuthentication();

	/**
	 * Gets device identity mode.
	 * 
	 * In case the {@link #getAuthentication()} doesn't handle the device
	 * identity, this handles the forwarding of the device identity. If that
	 * also fails to match the http-server's requirement, a custom
	 * implementation of {@link HttpForwardService} may be used.
	 * 
	 * @return device identity mode.
	 */
	DeviceIdentityMode getDeviceIdentityMode();

	/**
	 * Gets response filter for http forwarding.
	 * <p>
	 * Regular expression to filter response payload, {@code null} to not
	 * forward it. Payload matching the filter expression is not forwarded.
	 * <p>
	 * Regular expression requires {@link MediaTypeRegistry#isPrintable(int)}
	 * content type. Other content types are matched by the UTF-8 byte
	 * representation of the filter.
	 * 
	 * @return regular expression to filter response payload, or {@code null},
	 *         if no response payload is forwarded.
	 */
	Pattern getResponseFilter();

	/**
	 * Gets service name.
	 *
	 * @return service name, or {@code null}, to use the default service.
	 */
	String getServiceName();

	/**
	 * Gets extra field.
	 *
	 * @param name name of extra field.
	 * @return extra field, or {@code null}, if not available.
	 */
	String getExtraField(String name);

	/**
	 * Gets extra field also by alternative name.
	 *
	 * @param name name of extra field.
	 * @param alternativeName alternative name of extra field.
	 * @return extra field, or {@code null}, if not available.
	 */
	String getExtraField(String name, String alternativeName);

	/**
	 * Gets map of extra fields values.
	 * 
	 * @return map of extra fields
	 */
	Map<String, String> getExtraFields();

	/**
	 * Checks, if the configuration is valid.
	 * 
	 * @return {@code true}, if the destination and device identity mode is
	 *         available.
	 * @since 4.0 with default implementation
	 */
	default boolean isValid() {
		return getDestination() != null && getDeviceIdentityMode() != null;
	}

	/**
	 * Merge configurations.
	 * <p>
	 * Add fields of provided configuration for fields missing in this one.
	 * 
	 * @param configuration configuration to merge.
	 * @return merged configuration, or this, if no fields has been added
	 */
	default HttpForwardConfiguration merge(HttpForwardConfiguration configuration) {
		if (configuration == null) {
			return this;
		}
		URI destination = getDestination();
		String authentication = getAuthentication();
		DeviceIdentityMode mode = getDeviceIdentityMode();
		Pattern responseFilter = getResponseFilter();
		String serviceName = getServiceName();
		boolean merge = false;
		if (destination == null && configuration.getDestination() != null) {
			destination = configuration.getDestination();
			merge = true;
		}
		if (authentication == null && configuration.getAuthentication() != null) {
			authentication = configuration.getAuthentication();
			merge = true;
		}
		if (mode == null && configuration.getDeviceIdentityMode() != null) {
			mode = configuration.getDeviceIdentityMode();
			merge = true;
		}
		if (responseFilter == null && configuration.getResponseFilter() != null) {
			responseFilter = configuration.getResponseFilter();
			merge = true;
		}
		if (serviceName == null && configuration.getServiceName() != null) {
			serviceName = configuration.getServiceName();
			merge = true;
		}
		final Map<String, String> extraFieldsMerged = new HashMap<>(getExtraFields());
		configuration.getExtraFields().forEach((key, value) -> extraFieldsMerged.putIfAbsent(key, value));
		Map<String, String> extraFields = getExtraFields();
		if (extraFields.size() != extraFieldsMerged.size()) {
			extraFields = extraFieldsMerged;
		}
		if (merge) {
			return new BasicHttpForwardConfiguration(destination, authentication, mode, responseFilter, serviceName,
					extraFields);
		}
		return this;
	}

	/**
	 * Merge to http forward configurations.
	 * <p>
	 * Merges two configuration field by field, preferring the fields of the
	 * first configuration and only use the fields of the second, if the first
	 * doesn't provide that field. If only one configuration is provided, return
	 * that unmodified. And if no configuration is provided return {@code null}.
	 * 
	 * @param configuration1 first configuration with the preferred values
	 * @param configuration2 second configuration with the values to consider,
	 *            if the first doesn't provide the,
	 * @return merged configuration. May be {@code null}, if no configuration is
	 *         provided.
	 */
	static HttpForwardConfiguration merge(HttpForwardConfiguration configuration1,
			HttpForwardConfiguration configuration2) {
		if (configuration1 == null) {
			return configuration2;
		} else if (configuration2 == null) {
			return configuration1;
		}
		return configuration1.merge(configuration2);
	}

	/**
	 * Adds items to copy of list, if not already contained.
	 * 
	 * @param <T> type of times
	 * @param list list of items
	 * @param items items to add
	 * @return copied list with additional items
	 */
	@SafeVarargs
	static <T> List<T> concatIfAbsent(List<T> list, T... items) {
		List<T> newList = new ArrayList<>(list);
		for (T item : items) {
			if (!newList.contains(item)) {
				newList.add(item);
			}
		}
		return newList;
	}
}
