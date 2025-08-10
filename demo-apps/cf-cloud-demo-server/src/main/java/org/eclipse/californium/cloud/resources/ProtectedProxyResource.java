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
package org.eclipse.californium.cloud.resources;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.resources.Resource;

/**
 * The protected proxy for a {@link Resource}.
 * <p>
 * Protects {@link Resource} from access by unauthorized clients.
 * <p>
 * <code>
 * Resource parent = ...;
 * Resource unprotected = parent.getChild(name);
 * Resource protectedResource = new ProtectedProxyResource(unprotected);
 * parent.add(protectedResource);
 * </code>
 * 
 * The {@link Resource} to protect must not have child resources.
 * 
 * @since 4.0
 */
public class ProtectedProxyResource extends ProtectedCoapResource {

	/** The unprotected resource */
	private final Resource resource;

	/**
	 * Create a new protected proxy resource.
	 *
	 * @param resource the unprotected resource of the server
	 */
	public ProtectedProxyResource(Resource resource) {
		super(resource.getName());
		setVisible(resource.isVisible());
		addSupportedContentFormats(resource.getSupportedContentFormats());
		this.resource = resource;
	}

	@Override
	public void handleRequest(final Exchange exchange) {
		ResponseCode code = checkPermission(exchange);
		if (code != null) {
			exchange.sendResponse(new Response(code));
		} else {
			resource.handleRequest(exchange);
		}
	}
}
