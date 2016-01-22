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
package org.eclipse.californium.core.network;


/**
 * An EndpointObserver registers on an endpoint to be notified when the endpoint
 * starts, stops or destroys itself.
 */
public interface EndpointObserver {

	/**
	 * This method is called when the endpoint starts.
	 *
	 * @param endpoint the endpoint
	 */
	public void started(Endpoint endpoint);
	
	/**
	 * This method is called when the endpoint stops.
	 *
	 * @param endpoint the endpoint
	 */
	public void stopped(Endpoint endpoint);
	
	/**
	 * This method is called when the endpoint is being destroyed.
	 *
	 * @param endpoint the endpoint
	 */
	public void destroyed(Endpoint endpoint);
	
}
