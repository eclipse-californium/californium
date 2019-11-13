/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements;

/**
 * Interface for resolving the endpoint identity from an endpoint context.
 */
public interface EndpointIdentityResolver {

	/**
	 * Return resolver name. Used for logging.
	 * 
	 * @return name of resolver.
	 */
	String getName();

	/**
	 * Get the endpoint identity object.
	 * 
	 * @param context endpoint context
	 * @return endpoint identity object.
	 */
	Object getEndpointIdentity(EndpointContext context);

}
