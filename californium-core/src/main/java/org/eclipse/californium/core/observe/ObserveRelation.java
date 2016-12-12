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
package org.eclipse.californium.core.observe;

import java.net.InetSocketAddress;
import java.util.Iterator;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.Resource;


/**
 * The ObserveRelation is a server-side control structure. It represents a
 * relation between a client endpoint and a resource on this server.
 */
public class ObserveRelation {

	/** The logger. */
	private final static Logger LOGGER = Logger.getLogger(ObserveRelation.class.getCanonicalName());
	
	private final long CHECK_INTERVAL_TIME = NetworkConfig.getStandard().getLong(NetworkConfig.Keys.NOTIFICATION_CHECK_INTERVAL_TIME);
	private final int CHECK_INTERVAL_COUNT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.NOTIFICATION_CHECK_INTERVAL_COUNT);
	
	private final ObservingEndpoint endpoint;

	/** The resource that is observed */
	private final Resource resource;
	
	/** The exchange that has established the observe relationship */
	private final Exchange exchange;
	
	private Response recentControlNotification;
	private Response nextControlNotification;
	
	private String key = null;

	/*
	 * This value is false at first and must be set to true by the resource if
	 * it accepts the observe relation (the response code must be successful).
	 */
	/** Indicates if the relation is established */
	private boolean established;
	
	private long interestCheckTimer = System.currentTimeMillis();
	private int interestCheckCounter = 1;

	/** The notifications that have been sent, so they can be removed from the Matcher */
	private ConcurrentLinkedQueue<Response> notifications = new ConcurrentLinkedQueue<Response>();
	
	/**
	 * Constructs a new observe relation.
	 * 
	 * @param endpoint the observing endpoint
	 * @param resource the observed resource
	 * @param exchange the exchange that tries to establish the observe relation
	 */
	public ObserveRelation(ObservingEndpoint endpoint, Resource resource, Exchange exchange) {
		if (endpoint == null)
			throw new NullPointerException();
		if (resource == null)
			throw new NullPointerException();
		if (exchange == null)
			throw new NullPointerException();
		this.endpoint = endpoint;
		this.resource = resource;
		this.exchange = exchange;
		this.established = false;
		
		this.key = getSource().toString() + "#" + exchange.getRequest().getTokenString();
	}
	
	/**
	 * Returns true if this relation has been established.
	 * @return true if this relation has been established
	 */
	public boolean isEstablished() {
		return established;
	}
	
	/**
	 * Sets the established field.
	 *
	 * @param established true if the relation has been established
	 */
	public void setEstablished(boolean established) {
		this.established = established;
	}
	
	/**
	 * Cancel this observe relation. This methods invokes the cancel methods of
	 * the resource and the endpoint.
	 */
	public void cancel() {
		LOGGER.log(Level.FINE, "Canceling observe relation {0} with {1}", new Object[]{getKey(), resource.getURI()});
		// stop ongoing retransmissions
		if (exchange.getResponse()!=null) exchange.getResponse().cancel();
		setEstablished(false);
		resource.removeObserveRelation(this);
		endpoint.removeObserveRelation(this);
		exchange.setComplete();
	}
	
	/**
	 * Cancel all observer relations that this server has established with this'
	 * realtion's endpoint.
	 */
	public void cancelAll() {
		endpoint.cancelAll();
	}
	
	/**
	 * Notifies the observing endpoint that the resource has been changed. This
	 * method makes the resource process the same request again.
	 */
	public void notifyObservers() {
		resource.handleRequest(exchange);
	}
	
	/**
	 * Gets the resource.
	 *
	 * @return the resource
	 */
	public Resource getResource() {
		return resource;
	}

	/**
	 * Gets the exchange.
	 *
	 * @return the exchange
	 */
	public Exchange getExchange() {
		return exchange;
	}

	/**
	 * Gets the source address of the observing endpoint.
	 *
	 * @return the source address
	 */
	public InetSocketAddress getSource() {
		return endpoint.getAddress();
	}

	public boolean check() {
		boolean check = false;
		check |= this.interestCheckTimer + CHECK_INTERVAL_TIME < System.currentTimeMillis();
		check |= (++interestCheckCounter >= CHECK_INTERVAL_COUNT);
		if (check) {
			this.interestCheckTimer = System.currentTimeMillis();
			this.interestCheckCounter = 0;
		}
		return check;
	}

	public Response getCurrentControlNotification() {
		return recentControlNotification;
	}

	public void setCurrentControlNotification(Response recentControlNotification) {
		this.recentControlNotification = recentControlNotification;
	}

	public Response getNextControlNotification() {
		return nextControlNotification;
	}

	public void setNextControlNotification(Response nextControlNotification) {
		this.nextControlNotification = nextControlNotification;
	}
	
	public void addNotification(Response notification) {
		notifications.add(notification);
	}
	
	public Iterator<Response> getNotificationIterator() {
		return notifications.iterator();
	}
	
	public String getKey() {
		return this.key;
	}
}
