/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
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
package org.eclipse.californium.cloud.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.FORBIDDEN;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.UNAUTHORIZED;

import java.security.Principal;
import java.util.Arrays;

import org.eclipse.californium.cloud.util.PrincipalInfo;
import org.eclipse.californium.cloud.util.PrincipalInfo.Type;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Protected coap resource.
 * <p>
 * Calls {@link #checkPermission(Exchange)} to check, if principal has
 * permission for this resource.
 * <p>
 * The check is only a basic one, more specific permission rules may be applied
 * by overriding the
 * {@link #checkOperationPermission(PrincipalInfo, Exchange, boolean)}.
 * 
 * @since 4.0
 */
public abstract class ProtectedCoapResource extends CoapResource {

	private static final Logger LOGGER = LoggerFactory.getLogger(ProtectedCoapResource.class);

	/**
	 * Allowed types.
	 * 
	 * @see #checkPermission(Exchange)
	 */
	private final Type[] allowed;
	/**
	 * Allowed types as text for logging.
	 */
	private final String allowedAsText;

	/**
	 * Get allowed types as string for debug logging.
	 * 
	 * @param allowed allowed types
	 * @return provided allowed types as string, if
	 *         {@link Logger#isDebugEnabled()} is {@code true}. Otherwise
	 *         {@code null}.
	 */
	private static String getAllowedAsText(Type[] allowed) {
		return LOGGER.isDebugEnabled() ? Arrays.asList(allowed).toString() : null;
	}

	/**
	 * Create protected coap resource for {@link Type#DEVICE} only.
	 * 
	 * @param name resource name
	 */
	public ProtectedCoapResource(String name) {
		super(name);
		allowed = new Type[] { Type.DEVICE };
		allowedAsText = getAllowedAsText(allowed);
	}

	/**
	 * Create protected coap resource for {@link Type#DEVICE} only.
	 * 
	 * @param name resource name
	 * @param visible if the resource is visible
	 */
	public ProtectedCoapResource(String name, boolean visible) {
		super(name, visible);
		allowed = new Type[] { Type.DEVICE };
		allowedAsText = getAllowedAsText(allowed);
	}

	/**
	 * Create protected coap resource.
	 * 
	 * @param name resource name
	 * @param allowed list of allowed principal info types.
	 */
	public ProtectedCoapResource(String name, Type... allowed) {
		super(name);
		this.allowed = allowed;
		this.allowedAsText = getAllowedAsText(allowed);
	}

	/**
	 * Create protected coap resource.
	 * 
	 * @param name resource name
	 * @param visible if the resource is visible
	 * @param allowed list of allowed principal info types.
	 */
	public ProtectedCoapResource(String name, boolean visible, Type... allowed) {
		super(name, visible);
		this.allowed = allowed;
		this.allowedAsText = getAllowedAsText(allowed);
	}

	@Override
	public void handleRequest(final Exchange exchange) {
		ResponseCode code = checkPermission(exchange);
		if (code != null) {
			exchange.sendResponse(new Response(code));
		} else {
			super.handleRequest(exchange);
		}
	}

	/**
	 * Checks, if authentication type is allowed.
	 * 
	 * @param type authentication type to check.
	 * @return {@code true}, if operation is allowed.
	 */
	protected boolean allowed(final Type type) {
		for (Type permission : allowed) {
			if (type == permission) {
				return true;
			}
		}
		if (allowedAsText != null) {
			LOGGER.debug("{} is not in {}", type, allowedAsText);
		}
		return false;
	}

	/**
	 * Checks permission.
	 * <p>
	 * Checks permission based on the {@link PrincipalInfo}.
	 * 
	 * @param exchange exchange to check.
	 * @return error response code, if permission is denied, {@code null}, if
	 *         granted.
	 * @see #allowed
	 * @see #checkOperationPermission(PrincipalInfo, Exchange, boolean)
	 */
	protected ResponseCode checkPermission(Exchange exchange) {
		final PrincipalInfo info = getPrincipalInfo(exchange);
		if (info == null) {
			return UNAUTHORIZED;
		} else if (!allowed(info.type)) {
			if (info.type == Type.ANONYMOUS_DEVICE) {
				return UNAUTHORIZED;
			} else {
				return FORBIDDEN;
			}
		}
		return checkOperationPermission(info, exchange, exchange.getRequest().getCode().write);
	}

	/**
	 * Check permission for operation.
	 * <p>
	 * Intended to be override, if more customizable check is required.
	 * 
	 * @param info principal info
	 * @param exchange exchange to check.
	 * @param write {@code true} for write operation, {@code false} for read
	 *            operation.
	 * @return error response code, if permission is denied, {@code null}, if
	 *         granted.
	 */
	protected ResponseCode checkOperationPermission(PrincipalInfo info, Exchange exchange, boolean write) {
		return null;
	}

	/**
	 * Gets principal info from {@link Exchange}.
	 * 
	 * @param exchange exchange to get the principal info for.
	 * @return the principal info of the exchange, or {@code null}, if not
	 *         available.
	 */
	protected PrincipalInfo getPrincipalInfo(final Exchange exchange) {
		Principal principal = exchange.getRequest().getSourceContext().getPeerIdentity();
		return PrincipalInfo.getPrincipalInfo(principal);
	}

	/**
	 * Gets principal info from {@link CoapExchange}.
	 * 
	 * @param exchange exchange to get the principal info for.
	 * @return the principal info of the exchange, or {@code null}, if not
	 *         available.
	 */
	protected PrincipalInfo getPrincipalInfo(final CoapExchange exchange) {
		return getPrincipalInfo(exchange.advanced());
	}

	/**
	 * Gets principal from {@link Exchange}.
	 * 
	 * @param exchange exchange to get the principal for.
	 * @return the principal of the exchange, or {@code null}, if not available.
	 */
	protected Principal getPrincipal(final Exchange exchange) {
		return exchange.getRequest().getSourceContext().getPeerIdentity();
	}

	/**
	 * Gets principal from {@link CoapExchange}.
	 * 
	 * @param exchange exchange to get the principal for.
	 * @return the principal of the exchange, or {@code null}, if not available.
	 */
	protected Principal getPrincipal(final CoapExchange exchange) {
		return getPrincipal(exchange.advanced());
	}

}
