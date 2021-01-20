/*******************************************************************************
 * Copyright (c) 2017, 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - add flexible correlation context matching
 *                                      (fix GitHub issue #104)
 *    Achim Kraus (Bosch Software Innovations GmbH) - add isToBeSent to control
 *                                                    outgoing messages
 *                                                    (fix GitHub issue #104)
 *    Achim Kraus (Bosch Software Innovations GmbH) - use inhibitNewConnection 
 *                                                    for isToBeSent.
 *    Bosch Software Innovations GmbH - support matching of virtual host name
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

import org.eclipse.californium.elements.util.StringUtil;

/**
 * Key set based endpoint context matcher.
 */
public abstract class KeySetEndpointContextMatcher implements EndpointContextMatcher {

	/**
	 * Name of matcher. Used for logging.
	 */
	private final String name;
	private final String sendTag;
	private final String recvTag;
	/**
	 * Key set to be used for matching.
	 * 
	 * @see EndpointContextUtil#match(String, Set, EndpointContext,
	 *      EndpointContext)
	 */
	private final Set<String> keys;
	private final boolean compareHostname;

	/**
	 * Creates a matcher for a set of keys to compare.
	 * <p>
	 * The new matcher will not compare the virtual host names of contexts.
	 * 
	 * @param name name (used for logging).
	 * @param keys the names of the keys whose values will be compared when matching contexts.
	 */
	public KeySetEndpointContextMatcher(String name, String keys[]) {
		this(name, keys, false);
	}

	/**
	 * Creates a matcher for a set of keys to compare.
	 * 
	 * @param name name (used for logging).
	 * @param keys the names of the keys whose values will be compared when matching contexts.
	 * @param compareHostname {@code true} if the matcher should also
	 *                 {@linkplain #isSameVirtualHost(EndpointContext, EndpointContext) compare
	 *                 virtual host names} when matching contexts.
	 */
	public KeySetEndpointContextMatcher(String name, String keys[], boolean compareHostname) {
		this.name = name;
		this.sendTag = name + " sending";
		this.recvTag = name + " receiving";
		this.keys = createKeySet(keys);
		this.compareHostname = compareHostname;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public Object getEndpointIdentity(EndpointContext context) {
		InetSocketAddress address = context.getPeerAddress();
		if (address.isUnresolved()) {
			throw new IllegalArgumentException(StringUtil.toDisplayString(address) + " must be resolved!");
		}
		return address;
	}

	@Override
	public boolean isResponseRelatedToRequest(EndpointContext requestContext, EndpointContext responseContext) {

		boolean result = compareHostname ? isSameVirtualHost(requestContext, responseContext) : true;
		return result && internalMatch(recvTag, requestContext, responseContext);
	}

	@Override
	public boolean isToBeSent(EndpointContext messageContext, EndpointContext connectionContext) {
		if (null == connectionContext) {
			return !messageContext.hasCriticalEntries();
		}
		boolean result = compareHostname ? isSameVirtualHost(messageContext, connectionContext) : true;
		return result && internalMatch(sendTag, messageContext, connectionContext);
	}

	private final boolean internalMatch(String tag, EndpointContext requestedContext, EndpointContext availableContext) {
		if (!requestedContext.hasCriticalEntries()) {
			return true;
		}
		return EndpointContextUtil.match(tag, keys, requestedContext, availableContext);
	}

	@Override
	public String toRelevantState(EndpointContext context) {
		if (context == null) {
			return "n.a.";
		} else {
			return context.toString();
		}
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


	/**
	 * Checks if two endpoint contexts have the same virtual host property value.
	 * 
	 * @param firstContext The first context.
	 * @param secondContext The second context.
	 * @return {@code true} if the second context is {@code null} of if both contexts'
	 *         virtualHost properties have the same value.
	 * @throws NullPointerException if the first context is {@code null}.
	 */
	public static final boolean isSameVirtualHost(EndpointContext firstContext, EndpointContext secondContext) {

		if (firstContext == null) {
			throw new NullPointerException("first context must not be null");
		} else if (secondContext == null) {
			return true;
		} else {
			String firstVirtualHost = firstContext.getVirtualHost();
			String otherVirtualHost = secondContext.getVirtualHost();

			return firstVirtualHost == otherVirtualHost ||
					(firstVirtualHost != null && firstVirtualHost.equals(otherVirtualHost));
		}
	}
}
