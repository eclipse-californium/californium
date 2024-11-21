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
package org.eclipse.californium.cloud.s3.forward;

import java.util.function.Consumer;

import org.eclipse.californium.cloud.s3.util.DomainPrincipalInfo;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;

/**
 * Http forward service.
 * 
 * @since 4.0
 */
public interface HttpForwardService {

	/**
	 * Gets name of service.
	 * 
	 * @return name of service
	 */
	String getName();

	/**
	 * Forwards coap-request to http destination.
	 * 
	 * @param request coap-request to forward.
	 * @param info principal information including the domain.
	 * @param configuration configuration for http forwarding
	 * @param respond consumer for response
	 */
	void forwardPOST(Request request, DomainPrincipalInfo info, HttpForwardConfiguration configuration,
			Consumer<Response> respond);
}
