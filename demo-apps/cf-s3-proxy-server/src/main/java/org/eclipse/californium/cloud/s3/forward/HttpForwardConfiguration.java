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
	 * @since 4.0
	 */
	public static HttpForwardConfiguration merge(HttpForwardConfiguration configuration1,
			HttpForwardConfiguration configuration2) {
		if (configuration1 == null) {
			return configuration2;
		} else if (configuration2 == null) {
			return configuration1;
		}
		URI destination = configuration1.getDestination();
		String authentication = configuration1.getAuthentication();
		DeviceIdentityMode mode = configuration1.getDeviceIdentityMode();
		Pattern responseFilter = configuration1.getResponseFilter();
		String serviceName = configuration1.getServiceName();
		boolean merge = false;
		if (destination == null && configuration2.getDestination() != null) {
			destination = configuration2.getDestination();
			merge = true;
		}
		if (authentication == null && configuration2.getAuthentication() != null) {
			authentication = configuration2.getAuthentication();
			merge = true;
		}
		if (mode == null && configuration2.getDeviceIdentityMode() != null) {
			mode = configuration2.getDeviceIdentityMode();
			merge = true;
		}
		if (responseFilter == null && configuration2.getResponseFilter() != null) {
			responseFilter = configuration2.getResponseFilter();
			merge = true;
		}
		if (serviceName == null && configuration2.getServiceName() != null) {
			serviceName = configuration2.getServiceName();
			merge = true;
		}
		if (merge) {
			return new BasicHttpForwardConfiguration(destination, authentication, mode, responseFilter, serviceName);
		}
		return configuration1;
	}

}
