/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations GmbH - initial implementation
 *                                      (fix GitHub issue #104)
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.util.FilteredLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * EndpointContext utility.
 */
public class EndpointContextUtil {

	private static final Logger LOGGER = LoggerFactory.getLogger(EndpointContextUtil.class);

	private static final FilteredLogger WARN_FILTER = new FilteredLogger(LOGGER.getName(), 3, TimeUnit.SECONDS.toNanos(10));

	/**
	 * Match endpoint contexts based on a set of definitions.
	 * 
	 * @param name name of matcher for logging.
	 * @param definitions set of definitions to be matched.
	 * @param context1 endpoint context to be compared
	 * @param context2 endpoint context to be compared
	 * @return true, if all values in the endpoint contexts of the provided keys
	 *         are equal, false, if not.
	 * @since 3.0 (changed Set to Definitions)
	 */
	public static boolean match(String name, Definitions<Definition<?>> definitions, EndpointContext context1,
			EndpointContext context2) {
		boolean warn = LOGGER.isWarnEnabled();
		boolean trace = LOGGER.isTraceEnabled();
		boolean matchAll = true;
		for (Definition<?> key : definitions) {
			Object value1 = context1.get(key);
			Object value2 = context2.get(key);
			boolean match = (value1 == value2) || (null != value1 && value1.equals(value2));
			if (!match && !warn) {
				/* no warnings => fast return */
				return false;
			}
			if (!match) {
				/* logging differences with warning level */
				WARN_FILTER.warn("{}, {}: \"{}\" != \"{}\"", name, key, value1, value2);
			} else if (trace) {
				/* logging matches with finest level */
				LOGGER.trace("{}, {}: \"{}\" == \"{}\"", name, key, value1, value2);
			}
			matchAll = matchAll && match;
		}
		return matchAll;
	}

	/**
	 * Get follow-up endpoint context.
	 * 
	 * Using {@link DtlsEndpointContext#KEY_HANDSHAKE_MODE} requires to adjust
	 * the reuse of the endpoint context in case of blockwise transfers or
	 * retransmissions.
	 * 
	 * @param messageContext messages's endpoint context.
	 * @param connectionContext the connection's endpoint context. Either
	 *            reported with
	 *            {@link RawData#onContextEstablished(EndpointContext)} or
	 *            contained in a received message.
	 * @return endpoint context to be used for follow-up messages.
	 * @since 2.3
	 */
	public static EndpointContext getFollowUpEndpointContext(EndpointContext messageContext,
			EndpointContext connectionContext) {
		EndpointContext followUpEndpointContext;
		String mode = messageContext.getString(DtlsEndpointContext.KEY_HANDSHAKE_MODE);
		if (mode != null && mode.equals(DtlsEndpointContext.HANDSHAKE_MODE_NONE)) {
			// restore handshake-mode "none"
			followUpEndpointContext = MapBasedEndpointContext.addEntries(connectionContext,
					DtlsEndpointContext.ATTRIBUTE_HANDSHAKE_MODE_NONE);
		} else {
			followUpEndpointContext = connectionContext;
		}
		return followUpEndpointContext;
	}
}
