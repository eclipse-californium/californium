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
import java.util.Arrays;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import org.eclipse.californium.cloud.s3.forward.HttpForwardConfiguration.DeviceIdentityMode;
import org.eclipse.californium.cloud.s3.util.DomainPrincipalInfo;
import org.eclipse.californium.cloud.util.PrincipalInfo;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.util.Bytes;
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

	public BasicHttpForwardService() {
	}

	@Override
	public String getName() {
		return SERVICE_NAME;
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
	 * @param configuration htpp forward configuration
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
	 * @param configuration htpp forward configuration
	 * @return prepared request
	 * @throws IllegalArgumentException if the content type is not text/plain.
	 */
	public Request preparePOST(Request request, DomainPrincipalInfo info, HttpForwardConfiguration configuration) {
		if (request.getOptions().getContentFormat() != MediaTypeRegistry.TEXT_PLAIN) {
			throw new IllegalArgumentException("Only text/plain is supported!");
		}
		if (configuration.getDeviceIdentityMode() == DeviceIdentityMode.HEADLINE) {
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

	/**
	 * Filter response.
	 * <p>
	 * For {@link MediaTypeRegistry#isPrintable(int)} content types, apply
	 * regular expression {@link HttpForwardConfiguration#getResponseFilter()}
	 * and on match, drop the payload to prevent forwarding that to the device.
	 * For other content types, the filter is converted into the UTF-8 byte
	 * representation and that bytes are compared with the bytes of the payload.
	 * On match, the payload is dropped as well. If no
	 * {@link HttpForwardConfiguration#getResponseFilter()} is given, all
	 * content will be removed.
	 * 
	 * @param response response from http forward request
	 * @param info domain principal information.
	 * @param configuration htpp forward configuration
	 * @return response, if dropped without payload
	 */
	public Response filterResponse(Response response, DomainPrincipalInfo info,
			HttpForwardConfiguration configuration) {
		if (response != null && response.isSuccess() && response.getPayloadSize() > 0) {
			Pattern filter = configuration.getResponseFilter();
			boolean drop = false;
			if (filter == null) {
				LOGGER.info("HTTP-{}: {} => drop {} bytes, no response-filter.", getName(), info,
						response.getPayloadSize());
				drop = true;
			} else {
				int contentForward = response.getOptions().getContentFormat();
				if (MediaTypeRegistry.isPrintable(contentForward)) {
					LOGGER.debug("HTTP-{}: {} => response-filter '{}'", getName(), info, filter);
					String responsePayload = response.getPayloadString();
					drop = filter.matcher(responsePayload).matches();
					if (drop) {
						final int maxSize = 32;
						if (responsePayload.length() > maxSize) {
							responsePayload = responsePayload.substring(0, maxSize - 3) + "...";
						}
						LOGGER.info("HTTP-{}: {} => drop '{}' {} bytes", getName(), info, responsePayload,
								response.getPayloadSize());
					} else {
						LOGGER.info("HTTP-{}: {} => respond '{}' {} bytes", getName(), info, responsePayload,
								response.getPayloadSize());
					}
				} else {
					byte[] bytes = filter.pattern().getBytes(StandardCharsets.UTF_8);
					drop = Arrays.equals(bytes, response.getPayload());
					if (drop) {
						LOGGER.info("HTTP-{}: {} => drop {} bytes", getName(), info, response.getPayloadSize());
					} else {
						LOGGER.info("HTTP-{}: {} => respond {} bytes", getName(), info, response.getPayloadSize());
					}
				}
			}
			if (drop) {
				// remove payload prevents forwarding
				response.setPayload(Bytes.EMPTY);
			}
		}
		return response;
	}

}
