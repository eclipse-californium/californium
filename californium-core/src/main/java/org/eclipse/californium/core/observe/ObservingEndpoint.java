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
package org.eclipse.californium.core.observe;

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * This class represents an observing endpoint. It holds all observe relations
 * that the endpoint has to this server. If a confirmable notification timeouts
 * for the maximum times allowed the server assumes the client is no longer
 * reachable and cancels all relations that it has established to resources.
 */
public class ObservingEndpoint {
	
	/** The endpoint's address */
	private final InetSocketAddress address;

	/** The list of relations the endpoint has established with this server */
	private final List<ObserveRelation> relations;
	
	/**
	 * Constructs a new ObservingEndpoint.
	 * @param address the endpoint's address
	 */
	public ObservingEndpoint(InetSocketAddress address) {
		this.address = address;
		this.relations = new CopyOnWriteArrayList<ObserveRelation>();
	}
	
	/**
	 * Adds the specified observe relation.
	 * @param relation the relation
	 */
	public void addObserveRelation(ObserveRelation relation) {
		relations.add(relation);
	}
	
	/**
	 * Removes the specified observe relations.
	 * @param relation the relation
	 */
	public void removeObserveRelation(ObserveRelation relation) {
		relations.remove(relation);
	}
	
	/**
	 * Cancels all observe relations that this endpoint has established with
	 * resources from this server.
	 */
	public void cancelAll() {
		for (ObserveRelation relation:relations)
			relation.cancel();
	}

	/**
	 * Returns the address of this endpoint-
	 * @return the address
	 */
	public InetSocketAddress getAddress() {
		return address;
	}

	public ObserveRelation getObserveRelation(byte[] token) {
		for (ObserveRelation relation:relations) {
			if (Arrays.equals(relation.getExchange().getRequest().getToken(), token)) {
				return relation;
			}
		}
		return null;
	}
}
