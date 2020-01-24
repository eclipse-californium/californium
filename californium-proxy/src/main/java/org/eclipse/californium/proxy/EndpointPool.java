/*******************************************************************************
 * Copyright (c) 2019 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.proxy;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Queue;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.util.DaemonThreadFactory;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A pool of Endpoints.
 */
public class EndpointPool {

	private static final Logger LOGGER = LoggerFactory.getLogger(EndpointPool.class);

	/**
	 * Shutdown executors on {@link #destroy()}
	 */
	private final boolean shutdown;
	/**
	 * Size of pool.
	 */
	private final int size;
	/**
	 * Network configuration for new endpoints.
	 */
	protected final NetworkConfig config;
	/**
	 * Scheme of endpoints.
	 */
	private final String scheme;
	/**
	 * Pool of endpoints.
	 */
	private final Queue<Endpoint> pool;
	/**
	 * Main executor for endpoints.
	 * 
	 * @see Endpoint#setExecutors(ScheduledExecutorService,
	 *      ScheduledExecutorService)
	 */
	protected final ScheduledExecutorService mainExecutor;
	/**
	 * Secondary executor for endpoints.
	 * 
	 * @see Endpoint#setExecutors(ScheduledExecutorService,
	 *      ScheduledExecutorService)
	 */
	protected final ScheduledExecutorService secondaryExecutor;

	/**
	 * Create default endpoint pool.
	 */
	public EndpointPool() {
		this.shutdown = true;
		this.size = 128;
		this.config = new NetworkConfig(NetworkConfig.getStandard());
		int threads = this.config.getInt(NetworkConfig.Keys.PROTOCOL_STAGE_THREAD_COUNT);
		this.config.setInt(NetworkConfig.Keys.NETWORK_STAGE_RECEIVER_THREAD_COUNT, 1);
		this.config.setInt(NetworkConfig.Keys.NETWORK_STAGE_SENDER_THREAD_COUNT, 1);
		this.mainExecutor = ExecutorsUtil.newScheduledThreadPool(threads, new DaemonThreadFactory("Proxy#"));
		this.secondaryExecutor = ExecutorsUtil.newDefaultSecondaryScheduler("ProxyTimer#");
		this.pool = new ArrayDeque<>(size);
		this.scheme = init(size);
	}

	/**
	 * Create endpoint pool with specific network configuration and executors.
	 * 
	 * @param size size of pool
	 * @param init initial size of pool
	 * @param config network configuration to create endpoints.
	 * @param mainExecutor main executor for endpoints
	 * @param secondaryExecutor secondary executor for endpoints
	 */
	public EndpointPool(int size, int init, NetworkConfig config, ScheduledExecutorService mainExecutor,
			ScheduledExecutorService secondaryExecutor) {
		this.shutdown = false;
		this.size = size;
		this.pool = new ArrayDeque<>(size);
		this.config = config;
		this.mainExecutor = mainExecutor;
		this.secondaryExecutor = secondaryExecutor;
		if (init > size) {
			init = size;
		}
		this.scheme = init(init);
	}

	/**
	 * Initialize pool with endpoints.
	 * 
	 * @param init number of initial endpoints.
	 * @return scheme of endpoints
	 */
	private String init(int init) {
		String scheme = null;
		try {
			Endpoint endpoint = createEndpoint();
			scheme = endpoint.getUri().getScheme();
			pool.add(endpoint);
			for (int i = 1; i < init; i++) {
				pool.add(createEndpoint());
			}
		} catch (IOException ex) {
			LOGGER.warn("endpoint pool could not be filled!", ex);
		}
		return scheme;
	}

	/**
	 * Returns scheme of endpoint.
	 * 
	 * @return scheme of endpoint
	 */
	public String getScheme() {
		return scheme;
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

	/**
	 * Create new endpoint.
	 * 
	 * Maybe overriden to create endpoints using other schemes and protocols.
	 * 
	 * @return new created endpoint.
	 * @throws IOException
	 */
	protected Endpoint createEndpoint() throws IOException {
		Endpoint endpoint = new CoapEndpoint.Builder().setNetworkConfig(config).build();
		endpoint.setExecutors(mainExecutor, secondaryExecutor);
		try {
			endpoint.start();
			return endpoint;
		} catch (IOException e) {
			endpoint.destroy();
			throw e;
		}
	}

	/**
	 * Release a Endpoint so that other requests can use it.
	 * 
	 * @param endpoint Endpoint to free. {@code null} will return without
	 *            releasing it.
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

	/**
	 * Destroy endpoints in pool.
	 * 
	 * Shutdown executor, if not passed in as argument.
	 */
	public void destroy() {
		synchronized (pool) {
			for (Endpoint endpoint : pool) {
				endpoint.destroy();
			}
		}
		if (shutdown) {
			ExecutorsUtil.shutdownExecutorGracefully(1000, mainExecutor);
			ExecutorsUtil.shutdownExecutorGracefully(1000, secondaryExecutor);
		}
	}
}
