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
package org.eclipse.californium.core.coap;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.network.Exchange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Test resource to handles junit asserts of the scopes of other thread.
 * 
 * Intended to use assert with {@link #handleRequest(Exchange)} execution.
 * 
 * @since 3.11
 */
public class TestResource extends CoapResource {

	private static final Logger LOGGER = LoggerFactory.getLogger(TestResource.class);

	private List<Error> errors = new ArrayList<>();

	public TestResource(String name) {
		super(name);
	}

	@Override
	public void handleRequest(final Exchange exchange) {
		try {
			super.handleRequest(exchange);
		} catch (Error e) {
			LOGGER.warn("{}", e.getMessage(), e);
			errors.add(e);
		}
	}

	/**
	 * Report errors catched during execution of
	 * {@link #handleRequest(Exchange)}.
	 * 
	 * @throw Errors if occurred execution {@link #handleRequest(Exchange)}
	 */
	public void report() {
		if (!errors.isEmpty()) {
			throw errors.get(0);
		}
	}
}
