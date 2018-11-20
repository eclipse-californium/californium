/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations GmbH - initial implementation
 *                                      (fix GitHub issue #104)
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * EndpointContext utility.
 */
public class EndpointContextUtil {

	private static final Logger LOGGER = LoggerFactory.getLogger(EndpointContextUtil.class.getName());

	/**
	 * Match endpoint contexts based on a set of keys.
	 * 
	 * @param name name of matcher for logging.
	 * @param keys set of keys to be matched.
	 * @param context1 endpoint context to be compared
	 * @param context2 endpoint context to be compared
	 * @return true, if all values in the endpoint contexts of the provided
	 *         keys are equal, false, if not.
	 */
	public static boolean match(String name, Set<String> keys, EndpointContext context1, EndpointContext context2) {
		boolean warn = LOGGER.isWarnEnabled();
		boolean trace = LOGGER.isTraceEnabled();
		boolean matchAll = true;
		for (String key : keys) {
			String value1 = context1.get(key);
			String value2 = context2.get(key);
			boolean match = (value1 == value2) || (null != value1 && value1.equals(value2));
			if (!match && !warn) {
				/* no warnings => fast return */
				return false;
			}
			if (!match) {
				/* logging differences with warning level */
				LOGGER.warn("{}, {}: \"{}\" != \"{}\"",  name, key, value1, value2);
			} else if (trace) {
				/* logging matches with finest level */
				LOGGER.trace("{}, {}: \"{}\" == \"{}\"", name, key, value1, value2);
			}
			matchAll = matchAll && match;
		}
		return matchAll;
	}
}
