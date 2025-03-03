/********************************************************************************
 * Copyright (c) 2025 Contributors to the Eclipse Foundation
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
package org.eclipse.californium.elements;

import java.security.Principal;

import org.eclipse.californium.elements.auth.ExtensiblePrincipal;
import org.eclipse.californium.elements.util.Bytes;

/**
 * Principal based endpoint context matcher.
 * <p>
 * Matches DTLS based on the used principal or the session ID, if the principal
 * is anonymous. Requires unique and stable credentials.
 * 
 * @since 4.0
 */
public class PrincipalAndAnonymousEndpointContextMatcher implements EndpointContextMatcher {

	public PrincipalAndAnonymousEndpointContextMatcher() {
	}

	@Override
	public String getName() {
		return "principal and anonymous correlation";
	}

	/**
	 * Gets identity from endpoint context.
	 * <p>
	 * Use the {@link Principal} if available and not
	 * {@link ExtensiblePrincipal#isAnonymous()}. Otherwise use the DTLS session
	 * ID.
	 * 
	 * @param context endpoint context
	 * @return identity, or {@code null}, if none is available.
	 */
	private Object getIdentity(EndpointContext context) {
		Principal identity = context.getPeerIdentity();
		if (identity instanceof ExtensiblePrincipal<?>) {
			if (((ExtensiblePrincipal<?>) identity).isAnonymous()) {
				// anonymous principals don't have an identity.
				identity = null;
			}
		}
		if (identity != null) {
			return identity;
		}
		Bytes id = context.get(DtlsEndpointContext.KEY_SESSION_ID);
		if (Bytes.hasBytes(id)) {
			return id;
		}
		return null;
	}

	@Override
	public Object getEndpointIdentity(EndpointContext context) {
		Object identity = getIdentity(context);
		if (identity == null) {
			throw new IllegalArgumentException(
					"Principal identity and session id are missing in provided endpoint context!");
		}
		return identity;
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

		Object identity = getIdentity(requestedContext);
		if (identity != null) {
			return identity.equals(getIdentity(availableContext));
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
			builder.append(getIdentity(context));
			String cipher = context.getString(DtlsEndpointContext.KEY_CIPHER);
			if (cipher != null) {
				builder.append(",").append(cipher);
			}
			builder.append("]");
			return builder.toString();
		}
	}
}
