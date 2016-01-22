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
package org.eclipse.californium.core.server.resources;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.observe.ObserveRelation;
import org.eclipse.californium.core.server.ServerMessageDeliverer;

/**
 * A resource is an element on the resource tree of a server. Resources are the
 * main building bricks to develop a CoAP server. A resource can have further
 * child resources that again can have children resulting in a tree data
 * structure. A resource must have a name and its URI is defined by the path to
 * the root of the server plus the name. Note that a resource's name is not part
 * of its path. Instead it holds that the URI is defined by
 * <tt>URI = path + name</tt> where the path is the concatenation of the names
 * of all parents separated and ended with a slash. Assume the following
 * resource tree
 * 
 * <pre>
 * Root
 *  |
 *  |-- foo
 *  |    `-- bar
 *  |         `-- bal
 * </pre>
 * 
 * For resource <tt>bal</tt> it holds that
 * 
 * <pre>
 *  bal.getName() equals "bal"
 *  bal.getPath() equals "/foo/bar/"
 *  bal.getURI()  equals "/foo/bar/bal"
 * </pre>
 * 
 * <p>
 * A resource is able to respond to CoAP requests. The requests are contained in
 * an instance of type {@link Exchange} that contains additional information
 * about the current exchange. The request will always be a complete request and
 * not only a block as defined in the CoAP draft (<a
 * href="http://tools.ietf.org/html/draft-ietf-core-block-12">
 * http://tools.ietf.org/html/draft-ietf-core-block-12</a>)
 * </p><p>
 * When a request arrives at the server, the {@link ServerMessageDeliverer}
 * searches in the resource tree for the destination resource. It travels down
 * the resource tree by looking for one element of the destination URI after
 * another and by calling the method {@link #getChild(String)} on each element.
 * It is allowed to override this method and to return an arbitrary resource.
 * This allows for instance to serve URIs with wildcards or delegate requests to
 * any sub-URI to the same resource.
 * </p><p>
 * A resource can have its own {@link Executor}. If a resource has such an
 * executor, all requests will be handled by it. Otherwise, the request will
 * be executed on the executor of the parent or transitively the first ancestor
 * that defines its own executor. If no resource up to the root defines its own
 * executor, the currently executing thread will handle the request. A class
 * that implements this interface can export further methods to allow the
 * execution of code on the resource's executor. See {@link CoapResource} for an
 * example.
 * </p>
 */
public interface Resource {
	
	/**
	 * Handles the request from the specified exchange.
	 *
	 * @param exchange the exchange with the request
	 */
	public void handleRequest(Exchange exchange);
	
	/**
	 * Gets the name of the resource.
	 *
	 * @return the name
	 */
	public String getName();
	
	/**
	 * Sets the name of the resource. Note that changing the name of a resource
	 * changes the path and URI of all children. Note that the parent of this
	 * resource must be notified that the name has changed so that it finds the
	 * resource under the correct new URI when another request arrives. The
	 * easiest way to achieve this is by removing the resource before changing
	 * the name and adding it again after the name change.
	 * 
	 * @param name the new name
	 */
	public void setName(String name);
	
	/**
	 * Gets the path to the resource which is equal to the URI of its parent
	 * plus a slash. Note that that the name of a resource is not part of its
	 * path but instead it holds that getURI().equals(getPath() + getName()).
	 * 
	 * @return the path
	 */
	public String getPath();
	
	/**
	 * Sets the path of the resource. Note that changing the path of a resource
	 * also changes the path of all its children.
	 * 
	 * @param path the new path
	 */
	public void setPath(String path);
	
	/**
	 * Gets the URI of the resource.
	 *
	 * @return the uri
	 */
	public String getURI();
	
	/**
	 * Checks if the resource is visible to remote CoAP clients.
	 *
	 * @return true, if the resource is visible
	 */
	public boolean isVisible();
	
	/**
	 * Checks if is the URI of the resource can be cached. If another request
	 * with the same destination URI arrives, it can be forwarded to this
	 * resource right away instead of traveling through the resource tree
	 * looking for it.
	 * 
	 * @return true, if this resource's URI is cachable
	 */
	public boolean isCachable();
	
	/**
	 * Checks if this resource is observable by remote CoAP clients.
	 *
	 * @return true, if this resource is observable
	 */
	public boolean isObservable();
	
	/**
	 * Gets the attributes of this resource.
	 *
	 * @return the attributes
	 */
	public ResourceAttributes getAttributes();
	
	/**
	 * Adds the specified resource as child. Note that the resource should set
	 * the correct path of the child when added.
	 * 
	 * @param child the child
	 */
	public void add(Resource child);
	
	/**
	 * Removes the the specified child. Note that an implementation should set
	 * the path of the child to null.
	 * 
	 * @param child
	 *            the child
	 * @return true, if the child was found
	 */
	public boolean delete(Resource child);
	
	/**
	 * Gets all child resources.
	 *
	 * @return the children
	 */
	public Collection<Resource> getChildren();
	
	/**
	 * Gets the child with the specified name. Note that a resource is allowed
	 * to return any resource that it likes to associate with that name. This
	 * allows to support URIs containing wildcards for example.
	 * 
	 * @param name the name
	 * @return the child
	 */
	public Resource getChild(String name);
	
	/**
	 * Gets the parent of this resource.
	 *
	 * @return the parent
	 */
	public Resource getParent();
	
	/**
	 * Sets the parent of this resource.
	 *
	 * @param parent the new parent
	 */
	public void setParent(Resource parent);
	
	/**
	 * Adds the specified ResourceObserver. Note that ResourceObserver have
	 * nothing to do with CoAP's observe relations (@see
	 * {@link #addObserveRelation(ObserveRelation)}. ResourceObserver simply is
	 * the observer pattern used in Java to observe a certain object.
	 * 
	 * @param observer the observer
	 */
	public void addObserver(ResourceObserver observer);
	
	/**
	 * Removes the the specified observer.
	 *
	 * @param observer the observer
	 */
	public void removeObserver(ResourceObserver observer);
	
	/**
	 * Adds the specified CoAP observe relation. If this resource's state
	 * changes, all observer should be notified with a new response.
	 * 
	 * @param relation the relation
	 */
	public void addObserveRelation(ObserveRelation relation);
	
	/**
	 * Removes the specified CoAP observe relation.
	 *
	 * @param relation the relation
	 */
	public void removeObserveRelation(ObserveRelation relation);
	
	/**
	 * Gets the executor of this resource.
	 *
	 * @return the executor
	 */
	public ExecutorService getExecutor();
	
	/**
	 * Gets the endpoints this resource is bound to. As long as a resource is
	 * not added to a server, it should return an empty list. After a resource
	 * is added, it should return the endpoint list of its parent. The root of
	 * the server will than return the actual list of endpoints.
	 * 
	 * @return the endpoints
	 */
	public List<Endpoint> getEndpoints();
}
