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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.TestResource;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.test.lockstep.LockstepEndpoint;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.rule.ThreadsRule;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Threads rule for coap junit tests.
 * 
 * Calls {@link EndpointManager#reset()} before checking, that all new threads
 * are terminated.
 */
public class CoapThreadsRule extends ThreadsRule {

	public static final Logger LOGGER = LoggerFactory.getLogger(CoapThreadsRule.class);

	/**
	 * List of resource objects to cleanup.
	 */
	private final List<Object> cleanup = new ArrayList<Object>();

	/**
	 * Create a threads rule.
	 */
	public CoapThreadsRule() {
		super();
	}

	public void add(Connector connector) {
		cleanup.add(connector);
	}

	public void add(Endpoint endpoint) {
		cleanup.add(endpoint);
	}

	public void add(CoapClient client) {
		cleanup.add(client);
	}

	public void add(CoapServer server) {
		cleanup.add(server);
	}

	public void add(ExecutorService service) {
		cleanup.add(service);
	}

	public void add(LockstepEndpoint endpoint) {
		cleanup.add(endpoint);
	}

	public void add(TestResource resource) {
		cleanup.add(resource);
	}

	@Override
	protected void shutdown() {
		for (Object resource : cleanup) {
			try {
				LOGGER.debug("shutdown");
				if (resource instanceof Endpoint) {
					((Endpoint) resource).destroy();
				} else if (resource instanceof CoapClient) {
					((CoapClient) resource).shutdown();
				} else if (resource instanceof CoapServer) {
					((CoapServer) resource).destroy();
				} else if (resource instanceof ExecutorService) {
					ExecutorsUtil.shutdownExecutorGracefully(1000, (ExecutorService) resource);
				} else if (resource instanceof LockstepEndpoint) {
					((LockstepEndpoint) resource).destroy();
				} else if (resource instanceof Connector) {
					((Connector) resource).destroy();
				} else if (resource instanceof TestResource) {
					((TestResource) resource).report();
				}
			} catch (RuntimeException ex) {
				LOGGER.warn("shutdown failed!", ex);
			}
		}
		EndpointManager.reset();
	}
}
