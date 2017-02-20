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
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * CorrelationContext utility.
 */
public class CorrelationContextUtil {

	private static final Logger LOGGER = Logger.getLogger(CorrelationContextUtil.class.getName());

	/**
	 * Match correlation contexts based on a set of keys.
	 * 
	 * @param name name of matcher for logging.
	 * @param keys set of keys to be matched.
	 * @param context1 CorrelationContext to be compared
	 * @param context2 CorrelationContext to be compared
	 * @return true, if all values in the CorrelationContexts of the provided
	 *         keys are equal, false, if not.
	 */
	public static boolean match(String name, Set<String> keys, CorrelationContext context1, CorrelationContext context2) {
		boolean warn = LOGGER.isLoggable(Level.WARNING);
		boolean info = LOGGER.isLoggable(Level.FINEST);
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
				LOGGER.log(Level.WARNING, "{0}, {1}: \"{2}\" != \"{3}\"", new Object[] { name, key, value1, value2 });
			} else if (info) {
				/* logging matches with finest level */
				LOGGER.log(Level.FINEST, "{0}, {1}: \"{2}\" == \"{3}\"", new Object[] { name, key, value1, value2 });
			}
			matchAll = matchAll && match;
		}
		return matchAll;
	}
}
