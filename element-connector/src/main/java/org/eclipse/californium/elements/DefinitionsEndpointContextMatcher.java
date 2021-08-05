/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - derived from KeySetEndpointContextMatcher
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.net.InetSocketAddress;

import org.eclipse.californium.elements.util.StringUtil;

/**
 * Definitions based endpoint context matcher.
 * 
 * @since 3.0 (derived from KeySetEndpointContextMatcher)
 */
public abstract class DefinitionsEndpointContextMatcher implements EndpointContextMatcher {

	/**
	 * Name of matcher. Used for logging.
	 */
	private final String sendTag;
	private final String recvTag;
	/**
	 * Definitions to be used for matching.
	 * 
	 * @see EndpointContextUtil#match(String, Definitions, EndpointContext,
	 *      EndpointContext)
	 */
	private final Definitions<Definition<?>> definitions;
	private final boolean compareHostname;

	/**
	 * Creates a matcher for a set of definitions to compare.
	 * <p>
	 * The new matcher will not compare the virtual host names of contexts.
	 * 
	 * @param definitions the definitions whose values will be compared when
	 *            matching contexts.
	 * @throws NullPointerException if definitions is {@code null}
	 */
	public DefinitionsEndpointContextMatcher(Definitions<Definition<?>> definitions) {
		this(definitions, false);
	}

	/**
	 * Creates a matcher for a set of definitions to compare.
	 * 
	 * @param definitions the definitions whose values will be compared when
	 *            matching contexts.
	 * @param compareHostname {@code true} if the matcher should also
	 *            {@linkplain #isSameVirtualHost(EndpointContext, EndpointContext)
	 *            compare virtual host names} when matching contexts.
	 * @throws NullPointerException if definitions is {@code null}
	 */
	public DefinitionsEndpointContextMatcher(Definitions<Definition<?>> definitions, boolean compareHostname) {
		if (definitions == null) {
			throw new NullPointerException("Definitions must not be null!");
		}
		this.sendTag = definitions.getName() + " sending";
		this.recvTag = definitions.getName() + " receiving";
		this.definitions = definitions;
		this.compareHostname = compareHostname;
	}

	@Override
	public String getName() {
		return definitions.getName();
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

	private final boolean internalMatch(String tag, EndpointContext requestedContext,
			EndpointContext availableContext) {
		if (!requestedContext.hasCriticalEntries()) {
			return true;
		}
		return EndpointContextUtil.match(tag, definitions, requestedContext, availableContext);
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
	 * Checks if two endpoint contexts have the same virtual host property
	 * value.
	 * 
	 * @param firstContext The first context.
	 * @param secondContext The second context.
	 * @return {@code true} if the second context is {@code null} of if both
	 *         contexts' virtualHost properties have the same value.
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

			return firstVirtualHost == otherVirtualHost
					|| (firstVirtualHost != null && firstVirtualHost.equals(otherVirtualHost));
		}
	}
}
