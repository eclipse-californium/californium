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
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.security.Principal;

/**
 * Principal based endpoint context matcher.
 * 
 * Matches DTLS based on the used principal. Requires unique and stable credentials.
 */
public class PrincipalEndpointContextMatcher implements EndpointContextMatcher {

	private final boolean usePrincipalAsIdentity;

	public PrincipalEndpointContextMatcher() {
		this(false);
	}

	public PrincipalEndpointContextMatcher(boolean usePrincipalAsIdentity) {
		this.usePrincipalAsIdentity = usePrincipalAsIdentity;
	}

	@Override
	public String getName() {
		return "principal correlation";
	}

	@Override
	public Object getEndpointIdentity(EndpointContext context) {
		if (usePrincipalAsIdentity) {
			Principal identity = context.getPeerIdentity();
			if (identity == null) {
				throw new IllegalArgumentException("Principal identity missing in provided endpoint context!");
			}
			return identity;
		} else {
			return context.getPeerAddress();
		}
	}

	@Override
	public boolean isResponseRelatedToRequest(EndpointContext requestContext, EndpointContext responseContext) {
		return internalMatch(requestContext, responseContext);
	}

	@Override
	public boolean isToBeSent(EndpointContext messageContext, EndpointContext connectorContext) {
		if (null == connectorContext) {
			return true;
		}
		return internalMatch(messageContext, connectorContext);
	}

	private final boolean internalMatch(EndpointContext requestedContext, EndpointContext availableContext) {
		if (requestedContext.getPeerIdentity() != null) {
			if (availableContext.getPeerIdentity() == null) {
				return false;
			}
			if (!matchPrincipals(requestedContext.getPeerIdentity(), availableContext.getPeerIdentity())) {
				return false;
			}
		}
		String cipher = requestedContext.getString(DtlsEndpointContext.KEY_CIPHER);
		if (cipher != null) {
			if (!cipher.equals(availableContext.getString(DtlsEndpointContext.KEY_CIPHER))) {
				return false;
			}
		}
		return true;
	}

	@Override
	public String toRelevantState(EndpointContext context) {
		if (context == null) {
			return "n.a.";
		} else {
			StringBuilder builder = new StringBuilder();
			builder.append("[");
			builder.append(context.getPeerIdentity());
			String cipher = context.getString(DtlsEndpointContext.KEY_CIPHER);
			if (cipher != null) {
				builder.append(",").append(cipher);
			}
			builder.append("]");
			return builder.toString();
		}
	}

	/**
	 * Match principals.
	 * 
	 * Intended to be overwritten, when asymmetric principal implementations are
	 * used, and {@link #equals(Object)} doesn't work.
	 * 
	 * @param requestedPrincipal requested principal from requested endpoint
	 *            context.
	 * @param availablePrincipal available principal from available endpoint
	 *            context
	 * @return {@code true}, if the principals are matching, {@code false},
	 *         otherwise.
	 */
	protected boolean matchPrincipals(Principal requestedPrincipal, Principal availablePrincipal) {
		return requestedPrincipal.equals(availablePrincipal);
	}
}
