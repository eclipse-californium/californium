/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.core.server;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoAPEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigDefaults;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.DiscoveryResource;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.core.server.resources.ResourceBase;

/**
 * An execution environment for CoAP {@link Resource}s.
 * 
 * A server hosts a tree of {@link Resource}s which are exposed to clients by
 * means of one or more {@link Endpoint}s which are bound to a network interface.
 * 
 * A server can be started and stopped, when the server stops the endpoint should
 * free the port it is listening on.
 * <p>
 * The following code snippet provides an example of a server with a resource
 * that responds with a <em>"hello world"</em> to any incoming GET request.
 * <pre>
 *   Server server = new Server(port);
 *   server.add(new ResourceBase(&quot;hello-world&quot;) {
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
 * +--------------------------------------- Server ----------------------------------------+
 * |                                                                                       |
 * |                               +-----------------------+                               |
 * |                               |    MessageDeliverer   +--> (Resource Tree)            |
 * |                               +---------A-A-A---------+                               |
 * |                                         | | |                                         |
 * |                                         | | |                                         |
 * |                 .-------->>>------------' | '--------<<<------------.                 |
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
public class Server implements ServerInterface {

	/** The logger. */
	private final static Logger LOGGER = Logger.getLogger(Server.class.getCanonicalName());

	/** The root resource. */
	private final Resource root;
	
	/** The message deliverer. */
	private MessageDeliverer deliverer;
	
	/** The list of endpoints the server connects to the network. */
	private final List<Endpoint> endpoints;
	
	/** The executor of the server for its endpoints (can be null). */
	private ScheduledExecutorService executor;
	
	private NetworkConfig config;
	
	/**
	 * Constructs a default server. The server starts after the method
	 * {@link #start()} is called. If a server starts and has no specific ports
	 * assigned, it will bind to CoAp's default port 5683.
	 */
	public Server() {
		this(NetworkConfig.getStandard());
	}
	
	/**
	 * Constructs a server that listens to the specified port(s) after method
	 * {@link #start()} is called.
	 * 
	 * @param ports the ports to bind to
	 */
	public Server(int... ports) {
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
	public Server(NetworkConfig config, int... ports) {
		this.root = createRoot();
		this.endpoints = new ArrayList<Endpoint>();
		if (config != null) {
			this.config = config;
		} else {
			this.config = NetworkConfig.getStandard();
		}
		this.executor = Executors.newScheduledThreadPool(
				config.getInt(NetworkConfigDefaults.SERVER_THRESD_NUMER));
		this.deliverer = new ServerMessageDeliverer(root);
		
		ResourceBase well_known = new ResourceBase(".well-known");
		well_known.setVisible(false);
		well_known.add(new DiscoveryResource(root));
		root.add(well_known);
		
		for (int port:ports)
			bind(port);
	}
	
	/**
	 * Binds the server to the specified port.
	 *
	 * @param port the port
	 */
	private void bind(int port) {
		//TODO Martin: That didn't work out well :-/
//		if (port == EndpointManager.DEFAULT_PORT) {
//			for (Endpoint ep:EndpointManager.getEndpointManager().getDefaultEndpointsFromAllInterfaces())
//					addEndpoint(ep);
//		} else if (port == EndpointManager.DEFAULT_DTLS_PORT) {
//			for (Endpoint ep:EndpointManager.getEndpointManager().getDefaultSecureEndpointsFromAllInterfaces())
//					addEndpoint(ep);
//		} else {
//			for (InetAddress addr:EndpointManager.getEndpointManager().getNetworkInterfaces()) {
//				addEndpoint(new Endpoint(new InetSocketAddress(addr, port)));
//			}
//		}
//		addEndpoint(new Endpoint(port));
		
		// This endpoint binds to all interfaces. But there is no way (in Java)
		// of knowing to which interface address the packet actually has been
		// sent.
		bind(new InetSocketAddress((InetAddress) null, port));
	}

	/**
	 * Binds the server to a ephemeral port on the specified address.
	 *
	 * @param address the address
	 */
	private void bind(InetSocketAddress address) {
		Endpoint endpoint = new CoAPEndpoint(address, this.config);
		addEndpoint(endpoint);
	}
	
	public void setExecutor(ScheduledExecutorService executor) {
		this.executor = executor;
		for (Endpoint ep:endpoints)
			ep.setExecutor(executor);
	}
	
	/**
	 * Starts the server by starting all endpoints this server is assigned to.
	 * Each endpoint binds to its port. If no endpoint is assigned to the
	 * server, the server binds to CoAP0's default port 5683.
	 */
	@Override
	public void start() {
		LOGGER.info("Starting server");
		if (endpoints.isEmpty()) {
			int port = config.getInt(NetworkConfigDefaults.DEFAULT_COAP_PORT);
			LOGGER.info("No endpoints have been defined for server, setting up default endpoint at port " + port);
			bind(port);
		}
		int started = 0;
		for (Endpoint ep:endpoints) {
			try {
				ep.start();
				++started;
			} catch (IOException e) {
				LOGGER.log(Level.SEVERE, "Could not start endpoint", e);
			}
		}
		if (started==0) {
			throw new IllegalStateException("None of the server's endpoints could be started");
		}
	}
	
	/**
	 * Stops the server, i.e. unbinds it from all ports. Frees as much system
	 * resources as possible to still be able to be started.
	 */
	@Override
	public void stop() {
		LOGGER.info("Stopping server");
		for (Endpoint ep:endpoints)
			ep.stop();
	}
	
	/**
	 * Destroys the server, i.e. unbinds from all ports and frees all system
	 * resources.
	 */
	@Override
	public void destroy() {
		LOGGER.info("Destroy server");
		for (Endpoint ep:endpoints)
			ep.destroy();
		executor.shutdown(); // cannot be started again
		try {
			boolean succ = executor.awaitTermination(5, TimeUnit.SECONDS);
			if (!succ)
				LOGGER.warning("Stack executor did not shutdown in time");
		} catch (InterruptedException e) {
			LOGGER.log(Level.WARNING, "Exception while terminating stack executor", e);
		}
	}
	
	/**
	 * Sets the message deliverer.
	 *
	 * @param deliverer the new message deliverer
	 */
	public void setMessageDeliverer(MessageDeliverer deliverer) {
		this.deliverer = deliverer;
		for (Endpoint endpoint:endpoints)
			endpoint.setMessageDeliverer(deliverer);
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
	public void addEndpoint(Endpoint endpoint) {
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
	 * Add a resource to the server.
	 * @param resource the resource
	 * @return the server
	 */
	@Override
	public Server add(Resource... resources) {
		for (Resource r:resources)
			root.add(r);
		return this;
	}
	
	@Override
	public boolean remove(Resource resource) {
		return root.remove(resource);
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
	private class RootResource extends ResourceBase {

		// get version from Maven package
		private static final String SPACE = "                                "; // 32 until line end
		private final String VERSION = Server.class.getPackage().getImplementationVersion()!=null ?
				"Cf "+Server.class.getPackage().getImplementationVersion() : SPACE;
		private final String msg = new StringBuilder()
			.append("************************************************************\n")
			.append("I-D: draft-ietf-core-coap-18").append(SPACE.substring(VERSION.length())).append(VERSION).append("\n")
			.append("************************************************************\n")
			.append("This server is using the Californium (Cf) CoAP framework\n")
			.append("published by the Eclipse Foundation under EPL+EDL:\n")
			.append("http://www.eclipse.org/californium/\n")
			.append("\n")
			.append("(c) 2014, Institute for Pervasive Computing, ETH Zurich\n")
			.append("Contact: Matthias Kovatsch <kovatsch@inf.ethz.ch>\n")
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
			return Server.this.getEndpoints();
		}
	}

}
