/*******************************************************************************
 * Copyright (c) 2022 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.core.server.resources;

import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.observe.ObserveNotificationOrderer;
import org.eclipse.californium.core.observe.ObserveRelation;

/**
 * Extension for a {@link Resource} supporting observe notify.
 * 
 * @since 3.6
 */
public interface ObservableResource {

	/**
	 * Gets the URI of the resource.
	 *
	 * @return the uri
	 */
	String getURI();

	/**
	 * Get the type of the notifications that will be sent.
	 * 
	 * @return the type of the notifications, or {@code null}, if the matching
	 *         type of the request is to be used.
	 */
	Type getObserveType();

	/**
	 * Returns the current notification number.
	 * 
	 * @return the current notification number
	 * @see ObserveNotificationOrderer#getCurrent()
	 */
	int getNotificationSequenceNumber();

	/**
	 * Checks if this resource is observable by remote CoAP clients.
	 *
	 * @return {@code true}, if this resource is observable
	 */
	boolean isObservable();

	/**
	 * Adds the specified CoAP observe relation.
	 * 
	 * If this resource's state changes, all observer should be notified with a
	 * new response.
	 * 
	 * @param relation the relation
	 */
	void addObserveRelation(ObserveRelation relation);

	/**
	 * Removes the specified CoAP observe relation.
	 *
	 * @param relation the relation
	 */
	void removeObserveRelation(ObserveRelation relation);

	/**
	 * Returns the number of observe relations that this resource has to CoAP
	 * clients.
	 * 
	 * @return the observer count
	 */
	int getObserverCount();

}
