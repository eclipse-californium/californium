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
 *    Achim Kraus (Bosch Software Innovations GmbH) - support UserInfo principal
 *                                                    comparing the names only
 *    Achim Kraus (Bosch Software Innovations GmbH) - user principal name as
 *                                                    endpoint identifier
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.security.Principal;

/**
 * Principal based endpoint context matcher.
 * 
 * Matches DTLS based on the used principal. Requires unique and stable credentials.
 */
public class PrincipalEndpointContextMatcher implements EndpointContextMatcher {

	public PrincipalEndpointContextMatcher() {
	}

	@Override
	public String getName() {
		return "principal correlation";
	}

	@Override
        public byte[] getEndpointIdentifier(EndpointContext endpointContext) {
                Principal principal = endpointContext.getPeerIdentity();
                if (principal == null) {
                        throw new IllegalArgumentException("principal must be provided!");
                }
                return principal.getName().getBytes();
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
		String cipher = requestedContext.get(DtlsEndpointContext.KEY_CIPHER);
		if (cipher != null) {
			if (!cipher.equals(availableContext.get(DtlsEndpointContext.KEY_CIPHER))) {
				return false;
			}
		}
		return true;
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
		if (requestedPrincipal.equals(availablePrincipal)) {
			return true;
		}
		if (requestedPrincipal instanceof UserInfo) {
			// if the UserInfo is provided in the URI, check only the names
			return requestedPrincipal.getName().equals(availablePrincipal.getName());
		}
		return false;
	}
}
