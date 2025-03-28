/*******************************************************************************
 * Copyright (c) 2020 Bosch IO GmbH and others.
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
package org.eclipse.californium.proxy2;

import java.io.IOException;
import java.util.Queue;
import java.util.concurrent.ArrayBlockingQueue;

import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.ProtocolScheduledExecutorService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A pool of Endpoints.
 */
public class EndpointPool implements ClientEndpoints {

	private static final Logger LOGGER = LoggerFactory.getLogger(EndpointPool.class);

	/**
	 * Size of pool.
	 */
	protected final int size;
	/**
	 * Configuration for new endpoints.
	 */
	protected final Configuration config;
	/**
	 * Pool of endpoints.
	 */
	protected final Queue<Endpoint> pool;
	/**
	 * Executor for endpoints.
	 * 
	 * @see Endpoint#setExecutor(ProtocolScheduledExecutorService)
	 */
	protected final ProtocolScheduledExecutorService executor;
	/**
	 * Scheme of endpoints.
	 */
	protected String scheme;

	/**
	 * Create endpoint pool with specific configuration and executors
	 * and initializes the pool.
	 * 
	 * @param size size of pool
	 * @param init initial size of pool
	 * @param config configuration to create endpoints.
	 * @param executor executor for endpoints
	 * @since 4.0 (changed to single executor)
	 */
	public EndpointPool(int size, int init, Configuration config, ProtocolScheduledExecutorService executor) {
		this(size, config, executor);
		this.scheme = init(init);
	}

	/**
	 * Create endpoint pool with specific configuration and executors.
	 * 
	 * Requires extra initialization of the pool calling {@link #init(int)}.
	 * 
	 * @param size size of pool
	 * @param config configuration to create endpoints.
	 * @param executor executor for endpoints
	 * @since 4.0 (changed to single executor)
	 */
	protected EndpointPool(int size, Configuration config, ProtocolScheduledExecutorService executor) {
		this.size = size;
		this.pool = new ArrayBlockingQueue<>(size);
		this.config = config;
		this.executor = executor;
	}

	/**
	 * Initialize pool with endpoints.
	 * 
	 * @param init number of initial endpoints.
	 * @return scheme of endpoints
	 */
	protected String init(int init) {
		if (init > size) {
			init = size;
		}
		String scheme = null;
		try {
			Endpoint endpoint = createEndpoint();
			scheme = endpoint.getUri().getScheme();
			release(endpoint);
			for (int i = 1; i < init; i++) {
				release(createEndpoint());
			}
		} catch (IOException ex) {
			LOGGER.warn("endpoint pool could not be filled!", ex);
		}
		return scheme;
	}

	@Override
	public String getScheme() {
		return scheme;
	}

	@Override
	public void sendRequest(Request outgoingRequest) throws IOException {
		Endpoint endpoint = getEndpoint();
		outgoingRequest.addMessageObserver(new PoolMessageObserver(endpoint));
		endpoint.sendRequest(outgoingRequest);
	}

	/**
	 * Get endpoint from pool.
	 * 
	 * @return An Endpoint that is not in use.
	 * @throws IOException if an i/o error occurs creating a new endpoint.
	 */
	protected Endpoint getEndpoint() throws IOException {
		Endpoint endpoint = pool.poll();
		if (endpoint == null) {
			LOGGER.warn("Out of endpoints, creating more");
			endpoint = createEndpoint();
		}
		return endpoint;
	}

	/**
	 * Create new endpoint.
	 * 
	 * Maybe overridden to create endpoints using other schemes and protocols.
	 * 
	 * @return new created endpoint.
	 * @throws IOException if the endpoint could not be started, e.g. because
	 *             the endpoint's port is already in use.
	 */
	protected Endpoint createEndpoint() throws IOException {
		Endpoint endpoint = new CoapEndpoint.Builder().setConfiguration(config).build();
		endpoint.setExecutor(executor);
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
	protected void release(Endpoint endpoint) {
		if (endpoint == null) {
			return;
		}
		if (isFull() || !pool.offer(endpoint)) {
			endpoint.destroy();
		}
	}

	/**
	 * Check, if pool has reached its size limit.
	 * 
	 * @return {@code true}, if limit is reached, {@code false}, otherwise.
	 */
	protected boolean isFull() {
		return pool.size() >= size;
	}

	@Override
	public void destroy() {
		Endpoint endpoint;
		while ((endpoint = pool.poll()) != null) {
			endpoint.destroy();
		}
	}

	private class PoolMessageObserver extends MessageObserverAdapter {

		private final Endpoint outgoingEndpoint;

		private PoolMessageObserver(Endpoint outgoingEndpoint) {
			this.outgoingEndpoint = outgoingEndpoint;
		}

		@Override
		public void onResponse(Response incomingResponse) {
			release(outgoingEndpoint);
		}

		@Override
		public void onCancel() {
			release(outgoingEndpoint);
		}

		@Override
		protected void failed() {
			release(outgoingEndpoint);
		}
	}
}
