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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import org.eclipse.californium.cloud.s3.util.DomainPrincipalInfo;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.CounterStatisticManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Http forward service.
 * 
 * @since 4.0
 */
public interface HttpForwardService {

	/**
	 * Gets name of service.
	 * 
	 * @return name of service
	 */
	String getName();

	/**
	 * Creates health statistics for http forward services.
	 * 
	 * @param tag service tag for logging
	 * @param domains set of domains
	 * @return health statistics
	 */
	default CounterStatisticManager createHealthStatistic(String tag, Set<String> domains) {
		return null;
	}

	/**
	 * Gets list with device configuration fields.
	 * 
	 * @return list with device configuration fields
	 */
	default List<String> getDeviceConfigFields() {
		return Collections.emptyList();
	}

	/**
	 * Gets list with domain configuration fields.
	 * 
	 * @return list with domain configuration fields
	 */
	default List<String> getDomainConfigFields() {
		return Collections.emptyList();
	}

	/**
	 * Forwards coap-request to http destination.
	 * 
	 * @param request coap-request to forward.
	 * @param info principal information including the domain.
	 * @param configuration configuration for http forwarding
	 * @param respond consumer for response
	 */
	void forwardPOST(Request request, DomainPrincipalInfo info, HttpForwardConfiguration configuration,
			Consumer<Response> respond);

	/**
	 * Filters response.
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
	 * @param configuration http forward configuration
	 * @return response, if dropped without payload
	 */
	default Response filterResponse(Response response, DomainPrincipalInfo info,
			HttpForwardConfiguration configuration) {
		if (response != null && response.isSuccess() && response.getPayloadSize() > 0) {
			final Logger LOGGER = LoggerFactory.getLogger(HttpForwardService.class);
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
