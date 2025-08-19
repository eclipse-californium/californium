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
package org.eclipse.californium.cloud.s3.forward;

import java.util.Set;

import org.eclipse.californium.cloud.s3.util.DomainStatisticManager;
import org.eclipse.californium.elements.util.SimpleCounterStatistic;

/**
 * S3 processor health manager.
 * 
 * @since 4.0
 */
public class HttpforwardHealthLogger extends DomainStatisticManager implements HttpForwardHealth {

	private static final String SUCCESS = "forward-succeeds";
	private static final String FAILURE = "forward-failures";

	/**
	 * Creates a S3 processor health logger.
	 * 
	 * @param tag tag for associated counter statistic
	 * @param domains set of domain names
	 */
	public HttpforwardHealthLogger(String tag, Set<String> domains) {
		super(tag, "http-forward-statistic", true, BasicHttpForwardService.class.getName() + ".health");
		for (String domain : domains) {
			String head = domain + "-";
			add(head, new SimpleCounterStatistic(SUCCESS));
			add(head, new SimpleCounterStatistic(FAILURE));
		}
	}

	@Override
	public void forwarded(String domain, boolean success) {
		String name = success ? SUCCESS : FAILURE;
		increment(domain, name);
	}
}
