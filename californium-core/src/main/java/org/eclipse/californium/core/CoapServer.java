/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use Logger's message formatting instead of
 *                                                    explicit String concatenation
 ******************************************************************************/
package org.eclipse.californium.core;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.core.server.ServerInterface;
import org.eclipse.californium.core.server.ServerMessageDeliverer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.DiscoveryResource;
import org.eclipse.californium.core.server.resources.Resource;

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
	private static final Logger LOGGER = Logger.getLogger(CoapServer.class.getName());

	/** The root resource. */
	private final Resource root;

	private final NetworkConfig config;

	/** The message deliverer. */
	private MessageDeliverer deliverer;

	/** The list of endpoints the server connects to the network. */
	private final List<Endpoint> endpoints;

	/** The executor of the server for its endpoints (can be null). */
	private ScheduledExecutorService executor;

	private boolean running;

	/**
	 * Constructs a default server. The server starts after the method
	 * {@link #start()} is called. If a server starts and has no specific ports
	 * assigned, it will bind to CoAp's default port 5683.
	 */
	public CoapServer() {
		this(NetworkConfig.getStandard());
	}
	
	/**
	 * Constructs a server that listens to the specified port(s) after method
	 * {@link #start()} is called.
	 * 
	 * @param ports the ports to bind to
	 */
	public CoapServer(final int... ports) {
		this(NetworkConfig.getStandard(), ports);
	}

	/**
	 * Constructs a server with the specified configuration that listens to the
	 * specified ports after method {@link #start()} is called.
	 *
	 * @param config the configuration, if <code>null</code> the configuration returned by
	 * {@link NetworkConfig#getStandard()} is used.
	 * @param ports the ports to bind to
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
		// sets the central thread pool for the protocol stage over all endpoints
		this.executor = Executors.newScheduledThreadPool(//
				config.getInt(NetworkConfig.Keys.PROTOCOL_STAGE_THREAD_COUNT), //
				new Utils.NamedThreadFactory("CoapServer#")); //$NON-NLS-1$
		// create endpoint for each port
		for (int port : ports) {
			addEndpoint(new CoapEndpoint(port, this.config));
		}
	}

	/**
	 * Sets the executor service to use for running tasks in the protocol stage.
	 * 
	 * @param executor The thread pool to use.
	 * @throws IllegalStateException if this server is running.
	 */
	public synchronized void setExecutor(final ScheduledExecutorService executor) {

		if (running) {
			throw new IllegalStateException("executor service can not be set on running server");
		} else {
			this.executor = executor;
			for (Endpoint ep : endpoints) {
				ep.setExecutor(executor);
			}
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

		if (endpoints.isEmpty()) {
			// servers should bind to the configured port (while clients should use an ephemeral port through the default endpoint)
			int port = config.getInt(NetworkConfig.Keys.COAP_PORT);
			LOGGER.log(Level.INFO, "No endpoints have been defined for server, setting up server endpoint on default port {0}", port);
			addEndpoint(new CoapEndpoint(port, this.config));
		}

		int started = 0;
		for (Endpoint ep : endpoints) {
			try {
				ep.start();
				// only reached on success
				++started;
			} catch (IOException e) {
				LOGGER.log(Level.SEVERE, "Cannot start server endpoint [" + ep.getAddress() + "]", e);
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
		executor.shutdown(); // cannot be started again
		try {
			// wait for currently executing tasks to complete
			if (!executor.awaitTermination(1, TimeUnit.SECONDS)) {
				// cancel still executing tasks
				// and ignore all remaining tasks scheduled for later
				List<Runnable> runningTasks = executor.shutdownNow();
				if (runningTasks.size() > 0) {
					// this is e.g. the case if we have performed an incomplete blockwise transfer
					// and the BlockwiseLayer has scheduled a pending BlockCleanupTask for tidying up
					LOGGER.log(Level.FINE, "Ignoring remaining {0} scheduled task(s)", runningTasks.size());
				}
				// wait for executing tasks to respond to being cancelled
				executor.awaitTermination(1, TimeUnit.SECONDS);
			}
		} catch (InterruptedException e) {
			executor.shutdownNow();
			Thread.currentThread().interrupt();
		} finally {
			for (Endpoint ep : endpoints) {
				ep.destroy();
			}
			LOGGER.log(Level.INFO, "CoAP server has been destroyed");
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
		endpoint.setExecutor(executor);
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
		private static final String SPACE = "                                               "; // 47 until line end
		private final String VERSION = CoapServer.class.getPackage().getImplementationVersion()!=null ?
				"Cf "+CoapServer.class.getPackage().getImplementationVersion() : SPACE;
		private final String msg = new StringBuilder()
			.append("************************************************************\n")
			.append("CoAP RFC 7252").append(SPACE.substring(VERSION.length())).append(VERSION).append("\n")
			.append("************************************************************\n")
			.append("This server is using the Eclipse Californium (Cf) CoAP framework\n")
			.append("published under EPL+EDL: http://www.eclipse.org/californium/\n")
			.append("\n")
			.append("(c) 2014, 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others\n")
			.append("************************************************************")
			.toString();

		public RootResource() {
			super("");
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			exchange.respond(ResponseCode.CONTENT, msg);
		}

		public List<Endpoint> getEndpoints() {
			return CoapServer.this.getEndpoints();
		}
	}
}
