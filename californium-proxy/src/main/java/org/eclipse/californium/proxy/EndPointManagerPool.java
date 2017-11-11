/*******************************************************************************
 * Copyright (c) 2017 NTNU Gjøvik and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 *
 * Contributors:
 *    Martin Storø Nyfløtt (NTNU Gjøvik) - performance improvements to HTTP cross-proxy
 ******************************************************************************/
package org.eclipse.californium.proxy;

import org.eclipse.californium.core.network.EndpointManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayDeque;
import java.util.Queue;

/**
 * A pool of EndpointManagers to avoid concurrency issues across concurrent requests.
 */
public class EndPointManagerPool {
	private static final int INIT_SIZE = 10;
	private static final Queue<EndpointManager> managers = initManagerPool(INIT_SIZE);

	 private static final Logger LOGGER = LoggerFactory.getLogger(EndPointManagerPool.class);

	private static Queue<EndpointManager> initManagerPool(final int size) {
		final Queue<EndpointManager> clients = new ArrayDeque<>(size);

		for (int i = 0; i < size; i++) {
			clients.add(createManager());
		}

		return clients;
	}

    /**
     * @return An EndpointManager that is not in use.
     */
	public static EndpointManager getManager() {
		synchronized (managers) {
			if (managers.size() > 0) {
				return managers.remove();
			}
		}

		LOGGER.warn("Out of endpoint managers, creating more");

		return createManager();
	}

	private static EndpointManager createManager() {
		return new EndpointManager();
	}

    /**
     * Puts back and EndpointManager so that other clients can use it.
     * @param manager Manager to free.
     */
	public static void putClient(final EndpointManager manager) {
		if (manager == null) return;
		synchronized (managers) {
			if (managers.size() >= INIT_SIZE) {
				manager.getDefaultEndpoint().destroy();
			} else {
				managers.add(manager);
			}
		}
	}
}
