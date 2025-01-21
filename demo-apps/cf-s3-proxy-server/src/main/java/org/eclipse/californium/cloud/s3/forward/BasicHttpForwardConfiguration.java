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
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import org.eclipse.californium.cloud.s3.util.DomainPrincipalInfo;
import org.eclipse.californium.cloud.s3.util.Domains;
import org.eclipse.californium.cloud.util.DeviceParser;

/**
 * Http forward configuration.
 * <p>
 * Contains destination, authentication, {@link DeviceIdentityMode} and response
 * filter.
 * <p>
 * This http forward configuration is currently supported by cli arguments (use
 * {@code -h} as cli argument to see the help), by the {@link Domains} configuration
 * and by the {@link DeviceParser} configuration.
 * <p>
 * {@link Domains} configuration:
 * 
 * <pre>
 * {@code [http_forward = <http forward destination>]}
 * {@code [http_authentication = <http authentication>]}
 * {@code [http_device_identity_mode = NONE|HEADLINE|QUERY_PARAMETER]}
 * {@code [http_response_filter = <regex response filter>]}
 * {@code [http_service_name = <java-http-forwarding-service>]}
 * </pre>
 * 
 * <p>
 * {@link DeviceParser} per-device configuration:
 * 
 * <pre>
 * {@code [[<device-name>].fdest=<http-forward-destination>]}
 * {@code [[<device-name>].fauth=<http-forward-authentication>]}
 * {@code [[<device-name>].fdevid=(NONE,HEADLINE,QUERY_PARAMETER)]}
 * {@code [[<device-name>].fresp=<http-forward-response-filter>]}
 * {@code [[<device-name>].fservice=<java-http-forward-service>]}
 * </pre>
 * 
 * <p>
 * With {@code <http authentication>}:
 * 
 * <pre>
 * {@code Bearer <bearer token>}
 * {@code Header <http-header-name>:<http-header-value>}
 * {@code PreBasic <username>:<password>}
 * {@code <username>:<password>}
 * </pre>
 * 
 * @since 4.0
 */
public class BasicHttpForwardConfiguration implements HttpForwardConfiguration, HttpForwardConfigurationProvider {

	/**
	 * Postfix in field name for http forward destination.
	 */
	public static final String DEVICE_CONFIG_HTTP_FORWARD = ".fdest";
	/**
	 * Postfix in field name for http forward authentication.
	 */
	public static final String DEVICE_CONFIG_HTTP_AUTHENTICATION = ".fauth";
	/**
	 * Postfix in field name for http forward device identity mode.
	 */
	public static final String DEVICE_CONFIG_HTTP_DEVICE_IDENTITY_MODE = ".fdevid";
	/**
	 * Postfix in field name for http forward response regex.
	 */
	public static final String DEVICE_CONFIG_HTTP_RESPONSE_FILTER = ".fresp";
	/**
	 * Postfix in field name for http forward java-service.
	 */
	public static final String DEVICE_CONFIG_HTTP_SERVICE_NAME = ".fservice";

	/**
	 * Custom fields for http forwarding.
	 */
	public static final List<String> CUSTOM_DEVICE_CONFIG_FIELDS = Arrays.asList(DEVICE_CONFIG_HTTP_FORWARD,
			DEVICE_CONFIG_HTTP_AUTHENTICATION, DEVICE_CONFIG_HTTP_DEVICE_IDENTITY_MODE,
			DEVICE_CONFIG_HTTP_RESPONSE_FILTER, DEVICE_CONFIG_HTTP_SERVICE_NAME);

	/**
	 * Field name for http forward destination.
	 */
	public static final String DOMAIN_CONFIG_HTTP_FORWARD = "http_forward";
	/**
	 * Field name for http forward authentication.
	 */
	public static final String DOMAIN_CONFIG_HTTP_AUTHENTICATION = "http_authentication";
	/**
	 * Field name for http device identity mode.
	 */
	public static final String DOMAIN_CONFIG_HTTP_DEVICE_IDENTITY_MODE = "http_device_identity_mode";
	/**
	 * Field name for http response filter.
	 */
	public static final String DOMAIN_CONFIG_HTTP_RESPONSE_FILTER = "http_response_filter";
	/**
	 * Field name for http forward java-service.
	 */
	public static final String DOMAIN_CONFIG_HTTP_SERVICE_NAME = "http_service_name";

	/**
	 * Custom fields for http forwarding.
	 */
	public static final List<String> CUSTOM_DOMAIN_CONFIG_FIELDS = Arrays.asList(DOMAIN_CONFIG_HTTP_FORWARD,
			DOMAIN_CONFIG_HTTP_AUTHENTICATION, DOMAIN_CONFIG_HTTP_DEVICE_IDENTITY_MODE,
			DOMAIN_CONFIG_HTTP_RESPONSE_FILTER, DOMAIN_CONFIG_HTTP_SERVICE_NAME);

	/**
	 * Destination to forward data.
	 */
	private final URI destination;
	/**
	 * Authentication to forward data.
	 */
	private final String authentication;
	/**
	 * Mode to identify device to forward data.
	 */
	private final DeviceIdentityMode identityMode;
	/**
	 * Response filter. Regular expression to forward response payload,
	 * {@code null} to not forward it.
	 */
	private final Pattern responseFilter;
	/**
	 * Service name.
	 */
	private final String serviceName;

	/**
	 * Http forward configuration.
	 * 
	 * @param destination destination to forward data.
	 * @param authentication authentication to forward data.
	 * @param identityMode mode to identify device to forward data.
	 * @param responseFilter regular expression to filter response payload,
	 *            {@code null} to not forward it.
	 * @param serviceName service name, or {@code null} to use the default
	 *            service.
	 * @throws URISyntaxException
	 * @see HttpForwardServiceManager#getDefaultService()
	 * @see HttpForwardServiceManager#getService(String)
	 */
	public BasicHttpForwardConfiguration(String destination, String authentication, DeviceIdentityMode identityMode,
			String responseFilter, String serviceName) throws URISyntaxException {
		this.destination = destination != null ? new URI(destination) : null;
		this.authentication = authentication;
		this.identityMode = identityMode;
		this.responseFilter = responseFilter != null && !responseFilter.isEmpty() ? Pattern.compile(responseFilter)
				: null;
		this.serviceName = serviceName;
	}

	/**
	 * Http forward configuration.
	 * 
	 * @param destination destination to forward data.
	 * @param authentication authentication to forward data.
	 * @param identityMode mode to identify device to forward data.
	 * @param responseFilter regular expression to filter response payload,
	 *            {@code null} to not forward it.
	 * @param serviceName service name, or {@code null} to use the default
	 *            service.
	 * @see HttpForwardServiceManager#getDefaultService()
	 * @see HttpForwardServiceManager#getService(String)
	 */
	public BasicHttpForwardConfiguration(URI destination, String authentication, DeviceIdentityMode identityMode,
			Pattern responseFilter, String serviceName) {
		this.destination = destination;
		this.authentication = authentication;
		this.identityMode = identityMode;
		this.responseFilter = responseFilter;
		this.serviceName = serviceName;
	}

	@Override
	public URI getDestination() {
		return destination;
	}

	@Override
	public String getAuthentication() {
		return authentication;
	}

	@Override
	public DeviceIdentityMode getDeviceIdentityMode() {
		return identityMode;
	}

	@Override
	public Pattern getResponseFilter() {
		return responseFilter;
	}

	@Override
	public String getServiceName() {
		return serviceName;
	}

	@Override
	public boolean isValid() {
		return destination != null && identityMode != null;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Each {@link BasicHttpForwardConfiguration} is also a
	 * {@link HttpForwardConfigurationProvider} providing itself.
	 */
	@Override
	public HttpForwardConfiguration getConfiguration(DomainPrincipalInfo principalInfo) {
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

	/**
	 * Create http forward configuration from custom fields or postfix maps.
	 * 
	 * @param fields custom fields. May be {@code null}.
	 * @return http forward configuration, or {@code null}, if no http forward
	 *         fields are available.
	 */
	public static HttpForwardConfiguration create(Map<String, String> fields) throws URISyntaxException {
		if (fields != null && !fields.isEmpty()) {
			String destination = fields.get(DEVICE_CONFIG_HTTP_FORWARD);
			String authentication = fields.get(DEVICE_CONFIG_HTTP_AUTHENTICATION);
			String identityMode = fields.get(DEVICE_CONFIG_HTTP_DEVICE_IDENTITY_MODE);
			String responseFilter = fields.get(DEVICE_CONFIG_HTTP_RESPONSE_FILTER);
			String serviceName = fields.get(DEVICE_CONFIG_HTTP_SERVICE_NAME);
			if (destination == null && authentication == null && identityMode == null && responseFilter == null
					&& serviceName == null) {
				destination = fields.get(DOMAIN_CONFIG_HTTP_FORWARD);
				authentication = fields.get(DOMAIN_CONFIG_HTTP_AUTHENTICATION);
				identityMode = fields.get(DOMAIN_CONFIG_HTTP_DEVICE_IDENTITY_MODE);
				responseFilter = fields.get(DOMAIN_CONFIG_HTTP_RESPONSE_FILTER);
				serviceName = fields.get(DOMAIN_CONFIG_HTTP_SERVICE_NAME);
			}
			if (destination != null || authentication != null || identityMode != null || responseFilter != null
					|| serviceName != null) {
				DeviceIdentityMode mode = identityMode != null ? DeviceIdentityMode.valueOf(identityMode) : null;
				try {
					return new BasicHttpForwardConfiguration(destination, authentication, mode, responseFilter,
							serviceName);
				} catch (URISyntaxException ex) {

				}
			}
		}
		return null;
	}

}
