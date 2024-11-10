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

import org.eclipse.californium.cloud.util.PrincipalInfo;
import org.eclipse.californium.cloud.util.PrincipalInfo.Type;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.resources.CoapExchange;

/**
 * Protected coap resource.
 * 
 * Calls {@link #checkPermission(Exchange)} to check, if principal has
 * permission for this resource.
 * 
 * The check is only a basic one, more specific permission rules may be applied
 * by overriding the {@link #checkPermission(Exchange)}.
 * 
 * @since 4.0
 */
public abstract class ProtectedCoapResource extends CoapResource {

	/**
	 * Allowed types.
	 * 
	 * @see #checkPermission(Exchange)
	 */
	private final Type[] allowed;

	/**
	 * Create protected coap resource for {@link Type#DEVICE} only.
	 * 
	 * @param name resource name
	 */
	public ProtectedCoapResource(String name) {
		super(name);
		allowed = new Type[] { Type.DEVICE };
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

	protected boolean allowed(final Type type) {
		for (Type permission : allowed) {
			if (type == permission) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Check permission.
	 * 
	 * Checks permission based on the {@link PrincipalInfo}.
	 * 
	 * @param exchange exchange to check.
	 * @return error response code, if permission is denied, {@code null}, if
	 *         granted.
	 */
	protected ResponseCode checkPermission(Exchange exchange) {
		final PrincipalInfo info = getPrincipalInfo(exchange);
		if (info == null) {
			return UNAUTHORIZED;
		}
		if (!allowed(info.type)) {
			return FORBIDDEN;
		}
		return checkOperationPermission(info, exchange, exchange.getRequest().getCode().write);
	}

	/**
	 * Check permission for operation.
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

	protected PrincipalInfo getPrincipalInfo(final Exchange exchange) {
		Principal principal = exchange.getRequest().getSourceContext().getPeerIdentity();
		return PrincipalInfo.getPrincipalInfo(principal);
	}

	protected PrincipalInfo getPrincipalInfo(final CoapExchange exchange) {
		return getPrincipalInfo(exchange.advanced());
	}

	protected Principal getPrincipal(final Exchange exchange) {
		return exchange.getRequest().getSourceContext().getPeerIdentity();
	}

	protected Principal getPrincipal(final CoapExchange exchange) {
		return getPrincipal(exchange.advanced());
	}

}
