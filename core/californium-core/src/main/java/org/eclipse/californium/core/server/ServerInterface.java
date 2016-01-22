/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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

import java.net.InetSocketAddress;
import java.util.List;

import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.server.resources.Resource;

/**
 * An execution environment for CoAP {@link Resource}s.
 * 
 * A server hosts a tree of {@link Resource}s which are exposed to clients by
 * means of one or more {@link Endpoint}s which are bound to a network interface.
 * 
 * Resources can be added and removed from the server dynamically during runtime.
 * The server starts to process incoming CoAP requests after its {@link #start()}
 * method has been invoked and does so until it is stopped again via its {@link #stop()}
 * method.
 */
public interface ServerInterface {

	// be a server
	
	/**
	 * Starts the server by starting all endpoints this server is assigned to.
	 * Each endpoint binds to its port. If no endpoint is assigned to the
	 * server, the server binds to CoAP's default port 5683.
	 * 
	 * Implementations should start all registered endpoints as part of this method.
	 * @throws IllegalStateException if the server could not be started properly,
	 * e.g. because none of its endpoints could be bound to their respective
	 * ports
	 */
	void start();

	/**
	 * Stops the server, i.e. unbinds it from all ports.
	 * 
	 * Frees as much system resources as possible while still being able to
	 * be started again.
	 * Implementations should stop all registered endpoints as part of this method.
	 */
	void stop();
	
	/**
	 * Destroys the server, i.e. unbinds from all ports and frees all system
	 * resources.
	 * 
	 * The server instance is not expected to be able to be started again once
	 * this method has been invoked.
	 */
	void destroy();
	
	/**
	 * Adds one or more resources to the server.
	 * 
	 * @param resources the resources
	 * @return the server
	 */
	ServerInterface add(Resource... resources);
	
	/**
	 * Removes a resource from the server.
	 * 
	 * @param resource the resource to be removed
	 * @return <code>true</code> if the resource has been removed successfully
	 */
	boolean remove(Resource resource);
	
	/**
	 * Adds an endpoint for receive and sending CoAP messages on.
	 *  
	 * @param endpoint the endpoint
	 * @throws NullPointerException if the endpoint is <code>null</code>
	 */
	void addEndpoint(Endpoint endpoint);
	
	/**
	 * Gets the endpoints this server is bound to.
	 * 
	 * @return the endpoints
	 */
	List<Endpoint> getEndpoints();

	/**
	 * Gets the endpoint bound to a particular address.
	 * 
	 * @param address the address
	 * @return the endpoint or <code>null</code> if none of the
	 * server's endpoints is bound to the given address
	 */
	Endpoint getEndpoint(InetSocketAddress address);
	
	/**
	 * Gets an endpoint bound to a particular port.
	 * 
	 * If the server has multiple endpoints on different network interfaces
	 * bound to the same port, an implementation may return any of those endpoints.  
	 * 
	 * @param port the port
	 * @return the endpoint or <code>null</code> if none of the
	 * server's endpoints is bound to the given port on any of its
	 * network interfaces
	 */
	Endpoint getEndpoint(int port);
	
}
