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

import java.util.Set;
import java.util.function.Consumer;

import org.eclipse.californium.cloud.s3.util.DomainPrincipalInfo;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.util.CounterStatisticManager;

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
	 * Creates health statistics for http forward services.
	 * 
	 * @param tag service tag for logging
	 * @param domains set of domains
	 * @return health statistics
	 */
	default CounterStatisticManager createHealthStatistic(String tag, Set<String> domains) {
		return null;
	}

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
