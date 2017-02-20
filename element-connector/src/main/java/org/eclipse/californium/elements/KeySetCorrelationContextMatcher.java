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
 *    Bosch Software Innovations GmbH - add flexible correlation context matching
 *                                      (fix GitHub issue #104)
 *    Achim Kraus (Bosch Software Innovations GmbH) - add isToBeSent to control
 *                                                    outgoing messages
 *                                                    (fix GitHub issue #104)
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * Key set based correlation context matcher.
 */
public class KeySetCorrelationContextMatcher implements CorrelationContextMatcher {

	/**
	 * Name of matcher. Used for logging.
	 */
	private final String name;
	/**
	 * Key set to be used for matching.
	 * 
	 * @see CorrelationContextUtil#match(String, Set, CorrelationContext,
	 *      CorrelationContext)
	 */
	private final Set<String> keys;

	/**
	 * Create new instance of key set based correlation context matcher.
	 * 
	 * @param name name (used for logging).
	 * @param keys key set.
	 */
	public KeySetCorrelationContextMatcher(String name, String keys[]) {
		this.name = name;
		this.keys = createKeySet(keys);
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public boolean isResponseRelatedToRequest(CorrelationContext requestContext, CorrelationContext responseContext) {
		return internalMatch(requestContext, responseContext);
	}

	@Override
	public boolean isToBeSent(CorrelationContext messageContext, CorrelationContext connectorContext) {
		return internalMatch(messageContext, connectorContext);
	}

	private final boolean internalMatch(CorrelationContext requestedContext, CorrelationContext availableContext) {
		if (null == requestedContext) {
			return true;
		} else if (null == availableContext) {
			return false;
		}
		return CorrelationContextUtil.match(getName(), keys, requestedContext, availableContext);
	}

	/**
	 * Create key set from keys.
	 * 
	 * @param keys keys
	 * @return key set
	 */
	public static Set<String> createKeySet(String... keys) {
		return Collections.unmodifiableSet(new CopyOnWriteArraySet<String>(Arrays.asList(keys)));
	}

}
