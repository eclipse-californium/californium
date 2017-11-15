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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add nextObserveNumber 
 *                                                    (for use by subclasses)
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace nextObserveNumber
 *                                                    by ObserveRelationFilter
 *                                                    (for use by subclasses)
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use Logger's message formatting instead of
 *                                                    explicit String concatenation
 ******************************************************************************/
package org.eclipse.californium.core;

import java.net.URI;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Semaphore;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.observe.ObserveNotificationOrderer;
import org.eclipse.californium.core.observe.ObserveRelation;
import org.eclipse.californium.core.observe.ObserveRelationContainer;
import org.eclipse.californium.core.observe.ObserveRelationFilter;
import org.eclipse.californium.core.server.ServerMessageDeliverer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.core.server.resources.ResourceAttributes;
import org.eclipse.californium.core.server.resources.ResourceObserver;

/**
 * CoapResource is a basic implementation of a resource. Extend this class to
 * write your own resources. Instances of type or subtype of CoapResource can be
 * built up to a tree very easily, see {@link #add(CoapResource)}.
 * <p>
 * CoapResource uses four distinct methods to handle requests:
 * <tt>handleGET()</tt>, <tt>handlePOST()</tt>, <tt>handlePUT()</tt> and
 * <tt>handleDELETE()</tt>. Each method has a default implementation that
 * responds with a 4.05 (Method Not Allowed). Each method exists twice but with
 * a different parameter: <tt>handleGET(Exchange)</tt> and
 * <tt>handleGET(CoAPExchange)</tt> for instance. The class {@link Exchange} is
 * used internally in Californium to keep the state of an exchange of CoAP
 * messages. Only override this version of the method if you need to access
 * detailed information of an exchange. Most developer should rather override
 * the latter version. CoAPExchange provides a save and user-friendlier API that
 * can be used to respond to a request.
 * <p>
 * The following example override the four handle-method.
 * <pre>
 * public class CoAPResourceExample extends CoapResource {
 * 
 *   public CoAPResourceExample(String name) {
 *     super(name);
 *   }
 * 
 *   public void handleGET(CoapExchange exchange) {
 *     exchange.respond("hello world");
 *   }
 * 
 *   public void handlePOST(CoapExchange exchange) {
 *     exchange.accept();
 * 
 *     List&lt;String&gt; queries = exchange.getRequestOptions().getURIQueries();
 *     // ...
 *     exchange.respond(ResponseCode.CREATED);
 *   }
 * 
 *   public void handlePUT(CoapExchange exchange) {
 *     // ...
 *     exchange.respond(ResponseCode.CHANGED);
 *     changed(); // notify all observers
 *   }
 * 
 *   public void handleDELETE(CoapExchange exchange) {
 *     delete();
 *     exchange.respond(ResponseCode.DELETED);
 *   }
 * }
 * </pre>
 * <p>
 * Each resource is allowed to define its own executor. When a request arrives,
 * the request will be handled by the resource's executor. If a resource does
 * not define its own executor, the executor of its parent or transitively an
 * ancestor will be used. If no ancestor up to the root defines its own
 * executor, the thread that delivers the request will invoke the handling
 * method.
 * <p>
 * CoapResource supports CoAP's observe mechanism. Enable a CoapResource to be
 * observable by a CoAP client by marking it as observable with
 * {@link #setObservable(boolean)}. Notify all CoAP observers by calling
 * {@link #changed()}. The method changed() reprocesses the requests from the
 * observing clients that have originally established the observe relation. If
 * the resource or one of its ancestors define an executor, the reprocessing is
 * done on the executor. A CoAP observe relation between this resource and a
 * CoAP client is represented by an instance of {@link ObserveRelation}.
 * <p>
 * In contrast the class {@link ResourceObserver} has nothing to do with CoAP's
 * observe mechanism but is an implementation of the general observe-pattern. A
 * ResourceObserver is invoked whenever the name or path of a resource changes,
 * when a child resource is added or removed or when a CoAP observe relation is
 * added or canceled.
 * // TODO: make example with createClient().get() 
 */
public  class CoapResource implements Resource {

	/** The logger. */
	protected final static Logger LOGGER = Logger.getLogger(CoapResource.class.getCanonicalName());
	
	/* The attributes of this resource. */
	private final ResourceAttributes attributes;
	
	/* The resource name. */
	private String name;
	
	/* The resource path. */
	private String path;
	
	/* Indicates whether this resource is visible to clients. */
	private boolean visible;
	
	/* Indicates whether this resource is observable by clients. */
	private boolean observable;
	
	/* The child resources.
	 * We need a ConcurrentHashMap to have stronger guarantees in a
	 * multi-threaded environment (e.g. for discovery to work properly).
	 */
	private ConcurrentHashMap<String, Resource> children;
	
	/* The parent of this resource. */
	private Resource parent;
	
	/* The type used for notifications (no change when set to null) */
	private Type observeType = null;
	
	/* The list of observers (not CoAP observer). */
	private List<ResourceObserver> observers;

	/* The the list of CoAP observe relations. */
	private ObserveRelationContainer observeRelations;
	
	/* The notification orderer. */
	private ObserveNotificationOrderer notificationOrderer;
	
	/**
	 * Constructs a new resource with the specified name.
	 *
	 * @param name the name
	 */
	public CoapResource(String name) {
		this(name, true);
	}
	
	/**
	 * Constructs a new resource with the specified name and makes it visible to
	 * clients if the flag is true.
	 * 
	 * @param name the name
	 * @param visible if the resource is visible
	 */
	public CoapResource(String name, boolean visible) {
		this.name = name;
		this.path = "";
		this.setVisible(visible);
		
		this.attributes = new ResourceAttributes();
		this.children = new ConcurrentHashMap<String, Resource>();
		this.observers = new CopyOnWriteArrayList<ResourceObserver>();
		this.observeRelations = new ObserveRelationContainer();
		this.notificationOrderer = new ObserveNotificationOrderer();
	}
	

	/**
	 * Handles any request in the given exchange. By default it responds
	 * with a 4.05 (Method Not Allowed). Override this method if your
	 * resource handler requires advanced access to the internal Exchange class. 
	 * Most developer should be better off with overriding the called methods
	 * {@link #handleGET(CoapExchange)}, {@link #handlePOST(CoapExchange)},
	 * {@link #handlePUT(CoapExchange)}, and {@link #handleDELETE(CoapExchange)},
	 * which provide a better API through the {@link CoapExchange} class.
	 * 
	 * @param exchange the exchange with the request
	 */
	@Override
	public void handleRequest(final Exchange exchange) {
		Code code = exchange.getRequest().getCode();
		switch (code) {
			case GET:	handleGET(new CoapExchange(exchange, this)); break;
			case POST:	handlePOST(new CoapExchange(exchange, this)); break;
			case PUT:	handlePUT(new CoapExchange(exchange, this)); break;
			case DELETE: handleDELETE(new CoapExchange(exchange, this)); break;
		}
	}
	
	/**
	 * Handles the GET request in the given CoAPExchange. By default it responds
	 * with a 4.05 (Method Not Allowed). Override this method to respond
	 * differently to GET requests. Possible response codes for GET requests are
	 * Content (2.05) and Valid (2.03).
	 * 
	 * @param exchange the CoapExchange for the simple API
	 */
	public void handleGET(CoapExchange exchange) {
		exchange.respond(ResponseCode.METHOD_NOT_ALLOWED);
	}
	
	/**
	 * Handles the POST request in the given CoAPExchange. By default it
	 * responds with a 4.05 (Method Not Allowed). Override this method to
	 * respond differently to POST requests. Possible response codes for POST
	 * requests are Created (2.01), Changed (2.04), and Deleted (2.02).
	 *
	 * @param exchange the CoapExchange for the simple API
	 */
	public void handlePOST(CoapExchange exchange) {
		exchange.respond(ResponseCode.METHOD_NOT_ALLOWED);
	}
	
	/**
	 * Handles the PUT request in the given CoAPExchange. By default it responds
	 * with a 4.05 (Method Not Allowed). Override this method to respond
	 * differently to PUT requests. Possible response codes for PUT requests are
	 * Created (2.01) and Changed (2.04).
	 *
	 * @param exchange the CoapExchange for the simple API
	 */
	public void handlePUT(CoapExchange exchange) {
		exchange.respond(ResponseCode.METHOD_NOT_ALLOWED);
	}
	
	/**
	 * Handles the DELETE request in the given CoAPExchange. By default it
	 * responds with a 4.05 (Method Not Allowed). Override this method to
	 * respond differently to DELETE requests. The response code to a DELETE
	 * request should be a Deleted (2.02).
	 *
	 * @param exchange the CoapExchange for the simple API
	 */
	public void handleDELETE(CoapExchange exchange) {
		exchange.respond(ResponseCode.METHOD_NOT_ALLOWED);
	}
	
	/**
	 * This method is used to apply resource-specific knowledge on the exchange.
	 * If the request was successful, it sets the Observe option for the
	 * response. It is important to use the notificationOrderer of the resource
	 * here. Further down the layer, race conditions could cause local
	 * reordering of notifications. If the response has an error code, no
	 * observe relation can be established and if there was one previously it is
	 * canceled. When this resource allows to be observed by clients and the
	 * request is a GET request with an observe option, the
	 * {@link ServerMessageDeliverer} already created the relation, as it
	 * manages the observing endpoints globally.
	 * 
	 * @param exchange the exchange
	 * @param response the response
	 */
	public void checkObserveRelation(Exchange exchange, Response response) {
		/*
		 * If the request for the specified exchange tries to establish an observer
		 * relation, then the ServerMessageDeliverer must have created such a relation
		 * and added to the exchange. Otherwise, there is no such relation.
		 * Remember that different paths might lead to this resource.
		 */
		
		ObserveRelation relation = exchange.getRelation();
		if (relation == null) return; // because request did not try to establish a relation
		
		if (CoAP.ResponseCode.isSuccess(response.getCode())) {
			response.getOptions().setObserve(notificationOrderer.getCurrent());
			
			if (!relation.isEstablished()) {
				relation.setEstablished(true);
				addObserveRelation(relation);
			} else if (observeType != null) {
				// The resource can control the message type of the notification
				response.setType(observeType);
			}
		} // ObserveLayer takes care of the else case
	}
	
	/**
	 * Creates a {@link CoapClient} that uses the same executor as this resource
	 * and one of the endpoints that this resource belongs to. If no executor is
	 * defined by this resource or any parent, the client will not have an
	 * executor (it still works). If this resource is not yet added to a server
	 * or the server has no endpoints, the client has no specific endpoint and
	 * will use Californium's default endpoint.
	 * 
	 * @return the CoAP client
	 */
	public CoapClient createClient() {
		CoapClient client = new CoapClient();
		client.setExecutor(getExecutor());
		List<Endpoint> endpoints = getEndpoints();
		if (!endpoints.isEmpty())
			client.setEndpoint(endpoints.get(0));
		return client;
	}
	
	/**
	 * Creates a {@link CoapClient} that uses the same executor as this resource
	 * and one of the endpoints that this resource belongs to. If no executor is
	 * defined by this resource or any parent, the client will not have an
	 * executor (it still works). If this resource is not yet added to a server
	 * or the server has no endpoints, the client has no specific endpoint and
	 * will use Californium's default endpoint.
	 * 
	 * @param uri the uri
	 * @return the CoAP client
	 */
	public CoapClient createClient(URI uri) {
		return createClient().setURI(uri.toString());
	}
	
	/**
	 * Creates a {@link CoapClient} that uses the same executor as this resource
	 * and one of the endpoints that this resource belongs to. If no executor is
	 * defined by this resource or any parent, the client will not have an
	 * executor (it still works). If this resource is not yet added to a server
	 * or the server has no endpoints, the client has no specific endpoint and
	 * will use Californium's default endpoint.
	 *
	 * @param uri the URI string
	 * @return the CoAP client
	 */
	public CoapClient createClient(String uri) {
		return createClient().setURI(uri);
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.Resource#add(org.eclipse.californium.core.server.resources.Resource)
	 */
	@Override
	public synchronized void add(Resource child) {
		if (child.getName() == null)
			throw new NullPointerException("Child must have a name");
		if (child.getParent() != null)
			child.getParent().delete(child);
		children.put(child.getName(), child);
		child.setParent(this);
		for (ResourceObserver obs:observers)
			obs.addedChild(child);
	}
	
	/**
	 * Adds the specified resource as child. This method is syntactic sugar to
	 * have a fluent-interface when adding resources to a tree. For instance,
	 * consider the following example:
	 * 
	 * <pre>
	 * server.add(
	 *   new CoapResource("foo")
	 *     .add(new CoapResource("a")
	 *       .add(new CoapResource("a1"))
	 *       .add(new CoapResource("a2"))
	 *       .add(new CoapResource("a3"))
	 *       .add(new CoapResource("a4"))
	 *     )
	 *     .add(new CoapResource("b")
	 *       .add(new CoapResource("b1")
	 *     )
	 *   )
	 * );
	 * </pre>
	 * 
	 * @param child the child to add
	 * @return this
	 */
	public synchronized CoapResource add(CoapResource child) {
		add( (Resource) child);
		return this;
	}
	
	/**
	 * Adds the specified resource as child. This method is syntactic sugar to
	 * have a fluent-interface when adding resources to a tree. For instance,
	 * consider the following example:
	 * 
	 * <pre>
	 * server.add(
	 *   new CoapResource("foo").add(
	 *     new CoapResource("a").add(
	 *       new CoapResource("a1"),
	 *       new CoapResource("a2"),
	 *       new CoapResource("a3"),
	 *       new CoapResource("a4")
	 *     ),
	 *     new CoapResource("b").add(
	 *       new CoapResource("b1")
	 *     )
	 *   )
	 * );
	 * </pre>
	 * 
	 * @param children the child(ren) to add
	 * @return this
	 */
	public synchronized CoapResource add(CoapResource... children) {
		for (CoapResource child:children)
			add(child);
		return this;
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.Resource#delete(org.eclipse.californium.core.server.resources.Resource)
	 */
	@Override
	public synchronized boolean delete(Resource child) {
		Resource deleted = delete(child.getName());
		if (deleted == child) {
			child.setParent(null);
			child.setPath(null);
			for (ResourceObserver obs : observers)
				obs.removedChild(child);
			return true;
		}
		return false;
	}
	
	/**
	 * Removes the child with the specified name and returns it. If no child
	 * with the specified name is found, the return value is null.
	 * 
	 * @param name the name
	 * @return the deleted resource or null
	 */
	public synchronized Resource delete(String name) {
		return children.remove(name);
	}
	
	/**
	 * Delete this resource from its parents and notify all observing CoAP
	 * clients that this resource is no longer accessible.
	 */
	public synchronized void delete() {
		Resource parent = getParent();
		if (parent != null) {
			parent.delete(this);
		}
		
		if (isObservable()) {
			clearAndNotifyObserveRelations(ResponseCode.NOT_FOUND);
		}
	}
	
	/**
	 * Remove all observe relations to CoAP clients and notify them that the
	 * observe relation has been canceled.
	 * 
	 * @param code
	 *            the error code why the relation was terminated
	 *            (e.g., 4.04 after deletion)
	 */
	public void clearAndNotifyObserveRelations(ResponseCode code) {
		/*
		 * draft-ietf-core-observe-08, chapter 3.2 Notification states:
		 * In the event that the resource changes in a way that would cause
		 * a normal GET request at that time to return a non-2.xx response
		 * (for example, when the resource is deleted), the server sends a
		 * notification with a matching response code and removes the client
		 * from the list of observers.
		 * This method is called, when the resource is deleted.
		 */
		for (ObserveRelation relation:observeRelations) {
			relation.cancel();
			relation.getExchange().sendResponse(new Response(code));
		}
	}
	
	/**
	 * Cancel all observe relations to CoAP clients.
	 */
	public void clearObserveRelations() {
		for (ObserveRelation relation:observeRelations) {
			relation.cancel();
		}
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.Resource#getParent()
	 */
	@Override
	public Resource getParent() {
		return parent;
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.Resource#setParent(org.eclipse.californium.core.server.resources.Resource)
	 */
	public void setParent(Resource parent) {
		this.parent = parent;
		if (parent != null)
			this.path = parent.getPath()  + parent.getName() + "/";
		adjustChildrenPath();
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.Resource#getChild(java.lang.String)
	 */
	@Override
	public Resource getChild(String name) {
		return children.get(name);
	}

	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.Resource#addObserver(org.eclipse.californium.core.server.resources.ResourceObserver)
	 */
	@Override
	public synchronized void addObserver(ResourceObserver observer) {
		observers.add(observer);
	}

	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.Resource#removeObserver(org.eclipse.californium.core.server.resources.ResourceObserver)
	 */
	@Override
	public synchronized void removeObserver(ResourceObserver observer) {
		observers.remove(observer);
	}

	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.Resource#getAttributes()
	 */
	@Override
	public ResourceAttributes getAttributes() {
		return attributes;
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.Resource#getName()
	 */
	@Override
	public String getName() {
		return name;
	}

	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.Resource#isCachable()
	 */
	@Override
	public boolean isCachable() {
		return true;
	}

	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.Resource#getPath()
	 */
	@Override
	public String getPath() {
		return path;
	}

	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.Resource#getURI()
	 */
	@Override
	public String getURI() {
		return getPath() + getName();
	}

	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.Resource#setPath(java.lang.String)
	 */
	public synchronized void setPath(String path) {
		String old = this.path;
		this.path = path;
		for (ResourceObserver obs:observers)
			obs.changedPath(old);
		adjustChildrenPath();
	}

	// If the parent already has a child with that name, the behavior is undefined
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.Resource#setName(java.lang.String)
	 */
	public synchronized void setName(String name) {
		if (name == null)
			throw new NullPointerException();
		String old = this.name;
		
		// adjust parent if in tree
		Resource parent = getParent();
		if (parent!=null) {
			synchronized (parent) {
				parent.delete(this);
				this.name = name;
				parent.add(this);
			}
		} else {
			this.name = name;
		}
		adjustChildrenPath();
		
		for (ResourceObserver obs:observers)
			obs.changedName(old);
	}
	
	/**
	 * Adjust the path of all children. This method is invoked when the URI of
	 * this resource has changed, e.g., if its name or the name of an ancestor
	 * has changed.
	 */
	private void adjustChildrenPath() {
		String childpath = path + name + /*since 23.7.2013*/ "/";
		for (Resource child:children.values())
			child.setPath(childpath);
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.Resource#isVisible()
	 */
	@Override
	public boolean isVisible() {
		return visible;
	}
	
	/**
	 * Marks this resource as visible to CoAP clients.
	 *
	 * @param visible true if visible
	 */
	public void setVisible(boolean visible) {
		this.visible = visible;
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.Resource#isObservable()
	 */
	@Override
	public boolean isObservable() {
		return observable;
	}

	/**
	 * Marks this resource as observable by CoAP clients.
	 *
	 * @param observable true if observable
	 */
	public void setObservable(boolean observable) {
		this.observable = observable;
	}
	
	/**
	 * Sets the type of the notifications that will be sent.
	 * If set to null (default) the type matching the request will be used.
	 *
	 * @param type either CON, NON, or null for no changes by the framework
	 * @throws IllegalArgumentException if illegal types for notifications are passed 
	 */
	public void setObserveType(Type type) {
		if (type == Type.ACK || type == Type.RST) throw new IllegalArgumentException("Only CON and NON notifications are allowed or null for no changes by the framework");
		this.observeType = type;
	}

	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.Resource#addObserveRelation(org.eclipse.californium.core.observe.ObserveRelation)
	 */
	@Override
	public void addObserveRelation(ObserveRelation relation) {
		if (observeRelations.add(relation)) {
			LOGGER.log(Level.INFO, "Replacing observe relation between {0} and resource {1}", new Object[]{relation.getKey(), getURI()});
		} else {
			LOGGER.log(Level.INFO, "Successfully established observe relation between {0} and resource {1}", new Object[]{relation.getKey(), getURI()});
		}
		for (ResourceObserver obs:observers)
			obs.addedObserveRelation(relation);
	}

	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.Resource#removeObserveRelation(org.eclipse.californium.core.observe.ObserveRelation)
	 */
	@Override
	public void removeObserveRelation(ObserveRelation relation) {
		observeRelations.remove(relation);
		for (ResourceObserver obs:observers)
			obs.removedObserveRelation(relation);
	}
	
	/**
	 * Returns the number of observe relations that this resource has to CoAP
	 * clients.
	 * 
	 * @return the observer count
	 */
	public int getObserverCount() {
		return observeRelations.getSize();
	}
	
	/**
	 * Notifies all CoAP clients that have established an observe relation with
	 * this resource that the state has changed by reprocessing their original
	 * request that has established the relation. The notification is done by
	 * the executor of this resource or on the executor of its parent or
	 * transitively ancestor. If no ancestor defines its own executor, the
	 * thread that has called this method performs the notification.
	 * 
	 * @see #changed(ObserveRelationFilter)
	 */
	public void changed() {
		changed(null);
	}

	/**
	 * Notifies a filtered set of CoAP clients that have established an observe
	 * relation with this resource that the state has changed by reprocessing
	 * their original request that has established the relation. The notification
	 * is done by the executor of this resource or on the executor of its parent or
	 * transitively ancestor. If no ancestor defines its own executor, the
	 * thread that has called this method performs the notification.
	 * 
	 * @param filter filter to select set of relations. 
	 *               <code>null</code>, if all clients should be notified.
	 * 
	 * @see #changed()
	 */
	public void changed(final ObserveRelationFilter filter) {
		Executor executor = getExecutor();
		// use thread from the protocol stage
		if (executor == null) notifyObserverRelations(filter);
		// use thread from the resource pool
		else executor.execute(new Runnable() {
			public void run() {
				notifyObserverRelations(filter);
			}});
	}
	
	/**
	 * Notifies all CoAP clients that have established an observe relation with
	 * this resource that the state has changed by reprocessing their original
	 * request that has established the relation.
	 * 
	 * @param filter filter to select set of relations. 
	 *               <code>null</code>, if all clients should be notified.
	 */
	protected void notifyObserverRelations(final ObserveRelationFilter filter) {
		notificationOrderer.getNextObserveNumber();
		for (ObserveRelation relation:observeRelations) {
			if (null == filter || filter.accept(relation)) relation.notifyObservers();
		}
	}

	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.Resource#getChildren()
	 */
	@Override // should be used for read-only
	public Collection<Resource> getChildren() {
		return children.values();
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.Resource#getExecutor()
	 */
	public ExecutorService getExecutor() {
		return parent != null ? parent.getExecutor() : null;
	}
	
	/**
	 * Execute an arbitrary task on the executor of this resource or the first
	 * parent that defines its own executor. If no parent defines an executor,
	 * the thread that calls this method executes the specified task.
	 * 
	 * @param task the task
	 */
	public void execute(Runnable task) {
		Executor executor = getExecutor();
		// use thread from the protocol stage
		if (executor == null) task.run();
		// use thread from the resource pool
		else executor.execute(task);
	}
	
	/**
	 * Execute an arbitrary task on the executor of this resource or the first
	 * parent that defines its own executor and wait until it the task is
	 * completed. If no parent defines an executor, the thread that calls this
	 * method executes the specified task.
	 * 
	 * @param task the task
	 * @throws InterruptedException the interrupted exception
	 */
	public void executeAndWait(final Runnable task) throws InterruptedException {
		final Semaphore semaphore = new Semaphore(0);
		execute(new Runnable() {
			public void run() {
				task.run();
				semaphore.release();
			}
		});
		semaphore.acquire();
	}
	
	/* (non-Javadoc)
	 * @see org.eclipse.californium.core.server.resources.Resource#getEndpoints()
	 */
	public List<Endpoint> getEndpoints() {
		if (parent == null)
			return Collections.emptyList();
		else return parent.getEndpoints();
	}
}
