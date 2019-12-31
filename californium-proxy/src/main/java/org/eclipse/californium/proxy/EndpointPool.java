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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.proxy;

import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Queue;
import java.util.concurrent.ScheduledExecutorService;

/**
 * A pool of Endpoints to avoid concurrency issues across concurrent requests.
 */
public class EndpointPool {
	private static final Logger LOGGER = LoggerFactory.getLogger(EndpointPool.class);

	private final int size;
	private final Queue<Endpoint> pool;
	private final ScheduledExecutorService mainExecutor;
	private final ScheduledExecutorService secondaryExecutor;

	public EndpointPool(int size, int init, ScheduledExecutorService mainExecutor,
			ScheduledExecutorService secondaryExecutor) {
		this.size = size;
		this.pool = new ArrayDeque<>(size);
		this.mainExecutor = mainExecutor;
		this.secondaryExecutor = secondaryExecutor;
		if (init > size) {
			init = size;
		}
		try {
			for (int i = 0; i < init; i++) {
				pool.add(createEndpoint());
			}
		} catch (IOException ex) {
			LOGGER.warn("endpoint pool could not be filled!", ex);
		}
	}

	/**
	 * @return An Endpoint that is not in use.
	 * @throws IOException
	 */
	public Endpoint getEndpoint() throws IOException {
		synchronized (pool) {
			if (pool.size() > 0) {
				return pool.remove();
			}
		}

		LOGGER.warn("Out of endpoints, creating more");

		return createEndpoint();
	}

	private Endpoint createEndpoint() throws IOException {
		Endpoint endpoint = new CoapEndpoint.Builder().build();
		endpoint.setExecutors(mainExecutor, secondaryExecutor);
		endpoint.start();
		return endpoint;
	}

	/**
	 * Release a Endpoint so that other requests can use it.
	 * 
	 * @param endpoint Endpoint to free.
	 */
	public void release(final Endpoint endpoint) {
		if (endpoint == null) {
			return;
		}
		synchronized (pool) {
			if (pool.size() < size) {
				pool.add(endpoint);
				return;
			}
		}
		endpoint.destroy();
	}

	public void destroy() {
		synchronized (pool) {
			for (Endpoint endpoint : pool) {
				endpoint.destroy();
			}
		}
	}
}
