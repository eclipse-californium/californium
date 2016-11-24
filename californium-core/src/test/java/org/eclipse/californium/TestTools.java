/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium;

import org.eclipse.californium.core.network.Endpoint;

/**
 * A collection of utility methods for implementing tests.
 */
public final class TestTools {

	private static final String URI_TEMPLATE = "coap://%s:%d/%s";

	private TestTools() {
		// prevent instantiation
	}

	/**
	 * Creates a URI string for a resource hosted on an endpoint.
	 * 
	 * @param endpoint The endpoint the resource is hosted on.
	 * @param path The path of the resource on the endpoint.
	 * @return The URI string.
	 */
	public static String getUri(final Endpoint endpoint, final String path) {
		return String.format(URI_TEMPLATE, endpoint.getAddress().getHostString(), endpoint.getAddress().getPort(), path);
	}
}
