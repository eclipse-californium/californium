/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial implementation
 ******************************************************************************/
package org.eclipse.californium.rule;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.TestResource;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.test.lockstep.LockstepEndpoint;
import org.eclipse.californium.elements.rule.ThreadsRule;

/**
 * Threads rule for coap junit tests.
 * <p>
 * Calls {@link EndpointManager#reset()} before checking, that all new threads
 * are terminated.
 */
public class CoapThreadsRule extends ThreadsRule {

	/**
	 * Create a threads rule.
	 */
	public CoapThreadsRule() {
		super();
	}

	public void add(Endpoint endpoint) {
		add(() -> endpoint.destroy());
	}

	public void add(CoapClient client) {
		add(() -> client.shutdown());
	}

	public void add(CoapServer server) {
		add(() -> server.destroy());
	}

	public void add(LockstepEndpoint endpoint) {
		add(() -> endpoint.destroy());
	}

	public void add(TestResource resource) {
		add(() -> resource.report());
	}

	@Override
	protected void shutdown() {
		super.shutdown();
		EndpointManager.reset();
	}
}
