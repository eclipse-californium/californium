/*******************************************************************************
 * Copyright (c) 2016, 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - add support for correlation context to provide
 *                                      additional information to application layer for
 *                                      matching messages (fix GitHub issue #1)
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.util.Map;
import java.util.Set;

/**
 * A container for storing transport specific information about the context in
 * which a message has been sent or received.
 */
public interface CorrelationContext {

	/**
	 * Gets a value from this context.
	 * 
	 * @param key the key to retrieve the value for.
	 * @return the value or <code>null</code> if this context does not contain a
	 *         value for the given key.
	 */
	Object get(String key);

	/**
	 * Gets a value from this context.
	 * 
	 * @param key The key to retrieve the value for.
	 * @param type The expected value type.
	 * @return The value or <code>null</code> if this context does not contain a
	 *         value for the given key or the value does not match the expected type.
	 */
	<T> T get(String key, Class<T> type);

	/**
	 * Gets a Set of a Map.Entry which contains the key-value pair of the CorrelationContext.
	 *
	 * @return A set of a map entry containing the key value pair.
	 */
	Set<Map.Entry<String, Object>> entrySet();
}
