package org.eclipse.californium.proxy;

import org.eclipse.californium.core.network.EndpointManager;

import java.util.ArrayDeque;
import java.util.Queue;
import java.util.logging.Logger;

/**
 * A pool of EndpointManagers to avoid concurrency issues across concurrent requests.
 */
public class EndPointManagerPool {
	private static final int INIT_SIZE = 10;
	private static final Queue<EndpointManager> managers = initManagerPool(INIT_SIZE);

	private static final Logger LOGGER = Logger.getLogger(EndPointManagerPool.class.getName());

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

		LOGGER.warning("Out of endpoint managers, creating more");

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