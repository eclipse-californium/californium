/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use Logger's message formatting instead of
 *                                                    explicit String concatenation
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove duplicated
 *                                                    endpoints destroy
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - use executors util and
 *                                                    add a detached executor
 ******************************************************************************/
package org.eclipse.californium.core;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.MulticastReceivers;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.core.server.ServerInterface;
import org.eclipse.californium.core.server.ServerMessageDeliverer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.DiscoveryResource;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * An execution environment for CoAP {@link Resource}s.
 * 
 * A server hosts a tree of {@link Resource}s which are exposed to clients by
 * means of one or more {@link Endpoint}s which are bound to a network interface.
 * 
 * A server can be started and stopped. When the server stops the endpoint
 * frees the port it is listening on, but keeps the executors running to resume.
 * <p>
 * The following code snippet provides an example of a server with a resource
 * that responds with a <em>"hello world"</em> to any incoming GET request.
 * <pre>
 *   CoapServer server = new CoapServer(port);
 *   server.add(new CoapResource(&quot;hello-world&quot;) {
 * 	   public void handleGET(CoapExchange exchange) {
 * 	  	 exchange.respond(ResponseCode.CONTENT, &quot;hello world&quot;);
 * 	   }
 *   });
 *   server.start();
 * </pre>
 * 
 * The following figure shows the server's basic architecture.
 * 
 * <pre>
 * +------------------------------------- CoapServer --------------------------------------+
 * |                                                                                       |
 * |                               +-----------------------+                               |
 * |                               |    MessageDeliverer   +--&gt; (Resource Tree)            |
 * |                               +---------A-A-A---------+                               |
 * |                                         | | |                                         |
 * |                                         | | |                                         |
 * |                 .--------&gt;&gt;&gt;------------' | '--------&lt;&lt;&lt;------------.                 |
 * |                /                          |                          \                |
 * |               |                           |                           |               |
 * |             * A                         * A                         * A               |
 * | +-----------------------+   +-----------------------+   +-----------------------+     |
 * | |        Endpoint       |   |        Endpoint       |   |      Endpoint         |     |
 * | +-----------------------+   +-----------------------+   +-----------------------+     |
 * +------------v-A--------------------------v-A-------------------------v-A---------------+
 *              v A                          v A                         v A            
 *              v A                          v A                         v A         
 *           (Network)                    (Network)                   (Network)
 * </pre>
 * 
 * @see MessageDeliverer
 * @see Endpoint
 **/
public class CoapServer implements ServerInterface {

	/** The logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(CoapServer.class);

	/** The root resource. */
	private final Resource root;

	/** The network configuration used by this server. */
	private final NetworkConfig config;

	/** The message deliverer. */
	private MessageDeliverer deliverer;

	/** The list of endpoints the server connects to the network. */
	private final List<Endpoint> endpoints;

	/** The executor of the server for its endpoints (can be null). */
	private ScheduledExecutorService executor;

	/** Scheduled executor intended to be used for rare executing timers (e.g. cleanup tasks). */
	private ScheduledExecutorService secondaryExecutor;
	/**
	 * Indicate, it the server-specific executor service is detached, or
	 * shutdown with this server.
	 */
	private boolean detachExecutor;

	private boolean running;

	/**
	 * Constructs a default server. The server starts after the method
	 * {@link #start()} is called. If a server starts and has no specific ports
	 * assigned, it will bind to CoAP's default port 5683.
	 */
	public CoapServer() {
		this(NetworkConfig.getStandard());
	}

	/**
	 * Constructs a server that listens to the specified port(s) after method
	 * {@link #start()} is called.
	 * 
	 * @param ports the ports to bind to. If empty or {@code null} and no
	 *            endpoints are added with {@link #addEndpoint(Endpoint)}, it
	 *            will bind to CoAP's default port 5683 on {@link #start()}.
	 */
	public CoapServer(final int... ports) {
		this(NetworkConfig.getStandard(), ports);
	}

	/**
	 * Constructs a server with the specified configuration that listens to the
	 * specified ports after method {@link #start()} is called.
	 *
	 * @param config the configuration, if {@code null} the configuration
	 *            returned by {@link NetworkConfig#getStandard()} is used.
	 * @param ports the ports to bind to. If empty or {@code null} and no
	 *            endpoints are added with {@link #addEndpoint(Endpoint)}, it
	 *            will bind to CoAP's default port 5683 on {@link #start()}.
	 */
	public CoapServer(final NetworkConfig config, final int... ports) {
		// global configuration that is passed down (can be observed for changes)
		if (config != null) {
			this.config = config;
		} else {
			this.config = NetworkConfig.getStandard();
		}

		// resources
		this.root = createRoot();
		this.deliverer = new ServerMessageDeliverer(root);

		CoapResource wellKnown = new CoapResource(".well-known");
		wellKnown.setVisible(false);
		wellKnown.add(new DiscoveryResource(root));
		root.add(wellKnown);

		// endpoints
		this.endpoints = new ArrayList<>();
		// create endpoint for each port
		if (ports != null) {
			for (int port : ports) {
				CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
				builder.setPort(port);
				builder.setNetworkConfig(config);
				addEndpoint(builder.build());
			}
		}
	}

	public synchronized void setExecutors(final ScheduledExecutorService mainExecutor,
			final ScheduledExecutorService secondaryExecutor, final boolean detach) {
		if (mainExecutor == null || secondaryExecutor == null) {
			throw new NullPointerException("executors must not be null");
		}
		if (this.executor == mainExecutor && this.secondaryExecutor == secondaryExecutor) {
			return;
		}
		if (running) {
			throw new IllegalStateException("executor service can not be set on running server");
		}

		if (!this.detachExecutor) {
			if (this.executor != null) {
				this.executor.shutdownNow();
			}
			if (this.secondaryExecutor != null) {
				this.secondaryExecutor.shutdownNow();
			}
		}
		this.executor = mainExecutor;
		this.secondaryExecutor = secondaryExecutor;
		this.detachExecutor = detach;
		for (Endpoint ep : endpoints) {
			ep.setExecutors(this.executor, this.secondaryExecutor);
		}
	}

	/**
	 * Starts the server by starting all endpoints this server is assigned to.
	 * Each endpoint binds to its port. If no endpoint is assigned to the
	 * server, an endpoint is started on the port defined in the config.
	 */
	@Override
	public synchronized void start() {

		if (running) {
			return;
		}

		LOGGER.info("Starting server");

		if (executor == null) {
			// sets the central thread pool for the protocol stage over all
			// endpoints
			setExecutors(ExecutorsUtil.newScheduledThreadPool(//
					this.config.getInt(NetworkConfig.Keys.PROTOCOL_STAGE_THREAD_COUNT),
					new NamedThreadFactory("CoapServer(main)#")), //$NON-NLS-1$
					ExecutorsUtil.newDefaultSecondaryScheduler("CoapServer(secondary)#"), false);
		}

		if (endpoints.isEmpty()) {
			// servers should bind to the configured port (while clients should use an ephemeral port through the default endpoint)
			int port = config.getInt(NetworkConfig.Keys.COAP_PORT);
			LOGGER.info("no endpoints have been defined for server, setting up server endpoint on default port {}", port);
			CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
			builder.setPort(port);
			builder.setNetworkConfig(config);
			addEndpoint(builder.build());
		}

		int started = 0;
		for (Endpoint ep : endpoints) {
			if (ep instanceof MulticastReceivers) {
				try {
					((MulticastReceivers)ep).startMulticastReceivers();
				} catch (IOException e) {
					LOGGER.error("cannot start server multicast receiver [{}]", ep.getAddress(), e);
				}
			}
		}
		for (Endpoint ep : endpoints) {
			try {
				ep.start();
				// only reached on success
				++started;
			} catch (IOException e) {
				LOGGER.error("cannot start server endpoint [{}]", ep.getAddress(), e);
			}
		}
		if (started == 0) {
			throw new IllegalStateException("None of the server endpoints could be started");
		} else {
			running = true;
		}
	}

	/**
	 * Stops the server, i.e., unbinds it from all ports. Frees as much system
	 * resources as possible to still be able to be re-started with the previous binds.
	 * To free all system resources {@link #destroy()} must be called!
	 */
	@Override
	public synchronized void stop() {

		if (running) {
			LOGGER.info("Stopping server");
			for (Endpoint ep : endpoints) {
				ep.stop();
			}
			running = false;
		}
	}

	/**
	 * Destroys the server, i.e., unbinds from all ports and frees all system resources.
	 */
	@Override
	public synchronized void destroy() {
		LOGGER.info("Destroying server");
		// prevent new tasks from being submitted
		try {
			if (!detachExecutor)
				if (running) {
					ExecutorsUtil.shutdownExecutorGracefully(2000, executor, secondaryExecutor);
				} else {
					if (executor !=null) {
						executor.shutdownNow();
					}
					if (secondaryExecutor != null) {
						secondaryExecutor.shutdownNow();
					}
				}
		} finally {
			for (Endpoint ep : endpoints) {
				ep.destroy();
			}
			LOGGER.info("CoAP server has been destroyed");
			running = false;
		}
	}

	/**
	 * Sets the message deliverer.
	 *
	 * @param deliverer the new message deliverer
	 */
	public void setMessageDeliverer(final MessageDeliverer deliverer) {
		this.deliverer = deliverer;
		for (Endpoint endpoint : endpoints) {
			endpoint.setMessageDeliverer(deliverer);
		}
	}

	/**
	 * Gets the message deliverer.
	 *
	 * @return the message deliverer
	 */
	public MessageDeliverer getMessageDeliverer() {
		return deliverer;
	}

	/**
	 * Adds an Endpoint to the server. WARNING: It automatically configures the
	 * default executor of the server. Endpoints that should use their own
	 * executor (e.g., to prioritize or balance request handling) either set it
	 * afterwards before starting the server or override the setExecutor()
	 * method of the special Endpoint.
	 * 
	 * @param endpoint the endpoint to add
	 */
	@Override
	public void addEndpoint(final Endpoint endpoint) {
		endpoint.setMessageDeliverer(deliverer);
		if (executor != null && secondaryExecutor != null) {
			endpoint.setExecutors(executor, secondaryExecutor);
		}
		endpoints.add(endpoint);
	}

	/**
	 * Gets the list of endpoints this server is connected to.
	 *
	 * @return the endpoints
	 */
	@Override
	public List<Endpoint> getEndpoints() {
		return endpoints;
	}

	/**
	 * Returns the endpoint with a specific port.
	 * @param port the port
	 * @return the endpoint 
	 */
	@Override
	public Endpoint getEndpoint(int port) {
		Endpoint endpoint = null;

		for (Endpoint ep : endpoints) {
			if (ep.getAddress().getPort() == port) {
				endpoint = ep;
			}
		}
		return endpoint;
	}

	/**
	 * Returns the endpoint with a specific socket address.
	 * @param address the socket address
	 * @return the endpoint 
	 */
	@Override
	public Endpoint getEndpoint(InetSocketAddress address) {
		Endpoint endpoint = null;

		for (Endpoint ep : endpoints) {
			if (ep.getAddress().equals(address)) {
				endpoint = ep;
				break;
			}
		}

		return endpoint;
	}

	/**
	 * Add a resource to the server.
	 * @param resources the resource(s)
	 * @return the server
	 */
	@Override
	public CoapServer add(Resource... resources) {
		for (Resource r:resources)
			root.add(r);
		return this;
	}

	@Override
	public boolean remove(Resource resource) {
		return root.delete(resource);
	}

	/**
	 * Gets the root of this server.
	 *
	 * @return the root
	 */
	public Resource getRoot() {
		return root;
	}

	/**
	 * Get the network configuration of this server.
	 * 
	 * @return the network configuration
	 * @since 2.1
	 */
	public NetworkConfig getConfig() {
		return config;
	}

	/**
	 * Creates a root for this server. Can be overridden to create another root.
	 *
	 * @return the resource
	 */
	protected Resource createRoot() {
		return new RootResource();
	}

	/**
	 * Represents the root of a resource tree.
	 */
	private class RootResource extends CoapResource {

		// get version from Maven package
		private final String msg;

		public RootResource() {
			super("");
			String nodeId = config.getString(NetworkConfig.Keys.DTLS_CONNECTION_ID_NODE_ID);
			String title = "CoAP RFC 7252";
			if (StringUtil.CALIFORNIUM_VERSION != null) {
				String version = "Cf " + StringUtil.CALIFORNIUM_VERSION;
				title = String.format("%s %50s", title, version);
			}
			StringBuilder builder = new StringBuilder()
					.append("****************************************************************\n")
					.append(title).append("\n")
					.append("****************************************************************\n")
					.append("This server is using the Eclipse Californium (Cf) CoAP framework\n")
					.append("published under EPL+EDL: http://www.eclipse.org/californium/\n\n");
			if (nodeId != null && !nodeId.isEmpty()) {
				builder.append("node id = ").append(nodeId).append("\n\n");
			}
			builder.append("(c) 2014-2020 Institute for Pervasive Computing, ETH Zurich and others\n");
			String master = StringUtil.getConfiguration("COAP_ROOT_RESOURCE_FOOTER");
			if (master != null) {
				builder.append(master).append("\n");
			}
			builder.append("****************************************************************");
			msg = builder.toString();
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			exchange.respond(ResponseCode.CONTENT, msg);
		}

		@Override
		public List<Endpoint> getEndpoints() {
			return CoapServer.this.getEndpoints();
		}
	}
}
