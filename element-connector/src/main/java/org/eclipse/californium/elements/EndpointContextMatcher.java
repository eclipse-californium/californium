/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - add flexible correlation context matching
 *                                      (fix GitHub issue #104)
 *    Achim Kraus (Bosch Software Innovations GmbH) - add isToBeSent to control
 *                                                    outgoing messages
 *                                                    (fix GitHub issue #104)
 *    Achim Kraus (Bosch Software Innovations GmbH) - add getEndpointIdentifier
 ******************************************************************************/
package org.eclipse.californium.elements;

/**
 * Interface for endpoint context processing.
 * 
 * Enable implementor to flexible decide on endpoint context information.
 */
public interface EndpointContextMatcher {

	/**
	 * Return matcher name. Used for logging.
	 * 
	 * @return name of strategy.
	 */
	String getName();

	/**
	 * Get endpoint identifier to be used for this matcher implementation.
	 * 
	 * Returning {@code null} or an empty array cause the token to be unique on
	 * its own.
	 * 
	 * @param endpointContext endpoint context to get identity
	 * @return endpoint identifier as byte array, or {@code null}, if matcher
	 *         doesn't support a identity.
	 * @throws IllegalArgumentException, if endpoint context doesn't contain the
	 *             required endpoint information
	 */
	byte[] getEndpointIdentifier(EndpointContext endpointContext);

	/**
	 * Check, if responses is related to the request.
	 * 
	 * @param requestContext endpoint context of request
	 * @param responseContext endpoint context of response
	 * @return true, if response is related to the request, false, if response
	 *         should not be considered for this request.
	 */
	boolean isResponseRelatedToRequest(EndpointContext requestContext, EndpointContext responseContext);

	/**
	 * Check, if message should be sent out using the current endpoint context
	 * of the connector.
	 * 
	 * @param messageContext endpoint context of message
	 * @param connectionContext endpoint context of connection
	 * @return true, if message should be sent, false, if message should not be
	 *         sent.
	 */
	boolean isToBeSent(EndpointContext messageContext, EndpointContext connectionContext);

}
