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
package org.eclipse.californium.core;

import org.eclipse.californium.core.coap.MessageObserver;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.Endpoint;

/**
 * A CoapObserveRelation represents a CoAP observe relation between a CoAP
 * client and a resource on a server. CoapObserveRelation provides a simple API
 * to check whether a relation has successfully established and to cancel or
 * refresh the relation.
 */
public class CoapObserveRelation {

	/** The request. */
	private Request request;
	
	/** Indicates whether the relation has been canceled. */
	private boolean canceled = false;
	
	/** The current notification. */
	private CoapResponse current = null;
	
	/** The endpoint. */
	private Endpoint endpoint;
	
	/**
	 * Constructs a new CoapObserveRelation with the specified request.
	 *
	 * @param request the request
	 * @param endpoint the endpoint
	 */
	protected CoapObserveRelation(Request request, Endpoint endpoint) {
		this.request = request;
		this.endpoint = endpoint;
	}
	
	/**
	 * Proactive Observe cancellation:
	 * Cancel the observe relation by sending a GET with Observe=1.
	 */
	public void proactiveCancel() {
		Request cancel = Request.newGet();
		// copy options, but set Observe to cancel
		cancel.setOptions(request.getOptions());
		cancel.setObserveCancel();
		// use same Token
		cancel.setToken(request.getToken());
		cancel.setDestination(request.getDestination());
		cancel.setDestinationPort(request.getDestinationPort());
		// dispatch final response to the same message observers
		for (MessageObserver mo: request.getMessageObservers())
			cancel.addMessageObserver(mo);
		endpoint.sendRequest(cancel);
		// cancel old ongoing request
		request.cancel();
		this.canceled = true;
	}
	
	/**
	 * Reactive Observe cancellation:
	 * Cancel the observe relation by forgetting, which will trigger a RST.
	 */
	public void reactiveCancel() {
		request.cancel();
		this.canceled = true;
	}
	
	/**
	 * Checks if the relation has been canceled.
	 *
	 * @return true, if the relation has been canceled
	 */
	public boolean isCanceled() {
		return canceled;
	}
	
	/**
	 * Gets the current notification or null if none has arrived yet.
	 *
	 * @return the current notification
	 */
	public CoapResponse getCurrent() {
		return current;
	}
	
	/**
	 * Marks this relation as canceled.
	 *
	 * @param canceled true if this relation has been canceled
	 */
	protected void setCanceled(boolean canceled) {
		this.canceled = canceled;
	}
	
	/**
	 * Sets the current notification.
	 *
	 * @param current the new current
	 */
	protected void setCurrent(CoapResponse current) {
		this.current = current;
	}
	
}
