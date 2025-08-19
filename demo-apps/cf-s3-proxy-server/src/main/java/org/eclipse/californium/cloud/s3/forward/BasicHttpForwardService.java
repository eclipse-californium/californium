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
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import org.eclipse.californium.cloud.s3.forward.HttpForwardConfiguration.DeviceIdentityMode;
import org.eclipse.californium.cloud.s3.util.DomainPrincipalInfo;
import org.eclipse.californium.cloud.util.PrincipalInfo;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.CounterStatisticManager;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.proxy2.http.Coap2HttpProxy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Http forward configuration.
 * <p>
 * Contains destination, authentication, {@link DeviceIdentityMode} and response
 * filter.
 * 
 * @since 4.0
 */
public class BasicHttpForwardService implements HttpForwardService {

	private static final Logger LOGGER = LoggerFactory.getLogger(BasicHttpForwardService.class);

	public static final String SERVICE_NAME = "basic";

	protected final Coap2HttpProxy httpForward = new Coap2HttpProxy(null);

	protected volatile HttpForwardHealth health;

	public BasicHttpForwardService() {
	}

	@Override
	public String getName() {
		return SERVICE_NAME;
	}

	@Override
	public CounterStatisticManager createHealthStatistic(String tag, Set<String> domains) {
		HttpforwardHealthLogger statistics = new HttpforwardHealthLogger(tag, domains);
		health = statistics;
		return statistics;
	}

	@Override
	public List<String> getDeviceConfigFields() {
		return BasicHttpForwardConfiguration.CUSTOM_DEVICE_CONFIG_FIELDS;
	}

	@Override
	public List<String> getDomainConfigFields() {
		return BasicHttpForwardConfiguration.CUSTOM_DOMAIN_CONFIG_FIELDS;
	}

	@Override
	public void forwardPOST(Request request, DomainPrincipalInfo info, HttpForwardConfiguration configuration,
			Consumer<Response> result) {
		URI httpDestinationUri = getDestination(info, configuration);
		Request outgoing = preparePOST(request, info, configuration);

		LOGGER.info("HTTP-{}: {} => {} {} {} bytes", getName(), info, httpDestinationUri,
				configuration.getDeviceIdentityMode(), outgoing.getPayloadSize());

		httpForward.handleForward(httpDestinationUri, configuration.getAuthentication(), outgoing,
				(forwardResponse) -> {
					HttpForwardHealth health = this.health;
					if (health != null) {
						health.forwarded(info.domain, forwardResponse != null && forwardResponse.isSuccess());
					}
					result.accept(filterResponse(forwardResponse, info, configuration));
				});

	}

	/**
	 * Get destination with additional query parameter.
	 * 
	 * @param uri destination
	 * @param additionalQuery additional query parameter
	 * @return destination with additional query parameter
	 */
	public URI getDestination(URI uri, String additionalQuery) {
		if (additionalQuery != null) {
			String path = uri.getPath();
			String query = uri.getQuery();
			StringBuilder queryBuilder = new StringBuilder();
			if (query != null) {
				queryBuilder.append(query).append('&');
			}
			queryBuilder.append(additionalQuery);
			try {
				uri = uri.resolve(new URI(null, null, null, -1, path, queryBuilder.toString(), null));
			} catch (URISyntaxException e) {
				LOGGER.warn("HTTP-{}: URI: ", getName(), e);
			}
		}
		return uri;
	}

	/**
	 * Get http forward destination.
	 * <p>
	 * If {@link DeviceIdentityMode#QUERY_PARAMETER} is selected, add
	 * {@code id=name} to the query parameter.
	 * 
	 * @param info domain principal information.
	 * @param configuration http forward configuration
	 * @return http forward destination
	 */
	public URI getDestination(DomainPrincipalInfo info, HttpForwardConfiguration configuration) {
		URI httpDestinationUri = configuration.getDestination();
		if (configuration.getDeviceIdentityMode() == DeviceIdentityMode.QUERY_PARAMETER) {
			httpDestinationUri = getDestination(httpDestinationUri, "id=" + info.name);
		}
		return httpDestinationUri;
	}

	/**
	 * Prepare POST request.
	 * <p>
	 * If {@link DeviceIdentityMode#HEADLINE} is selected, add the
	 * {@link PrincipalInfo#name} as headline to the payload.
	 * 
	 * @param request incoming coap-request
	 * @param info domain principal information.
	 * @param configuration http forward configuration
	 * @return prepared request
	 * @throws IllegalArgumentException If {@link DeviceIdentityMode#HEADLINE}
	 *             is selected and the content type is not text/plain.
	 */
	public Request preparePOST(Request request, DomainPrincipalInfo info, HttpForwardConfiguration configuration) {
		if (configuration.getDeviceIdentityMode() == DeviceIdentityMode.HEADLINE) {
			if (request.getOptions().getContentFormat() != MediaTypeRegistry.TEXT_PLAIN) {
				throw new IllegalArgumentException("Only text/plain is supported!");
			}
			Request outgoing = new Request(request.getCode(), request.getType());
			outgoing.setOptions(request.getOptions());
			byte[] payload = request.getPayload();
			byte[] head = (info.name + StringUtil.lineSeparator()).getBytes(StandardCharsets.UTF_8);
			payload = Bytes.concatenate(head, payload);
			outgoing.setPayload(payload);
			return outgoing;
		} else {
			return request;
		}
	}
}
