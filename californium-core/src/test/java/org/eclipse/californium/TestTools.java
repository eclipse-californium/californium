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

import java.net.InetSocketAddress;
import java.util.Random;

import org.eclipse.californium.core.network.Endpoint;

/**
 * A collection of utility methods for implementing tests.
 */
public final class TestTools {

	private static final Random RAND = new Random();
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
		return getUri(endpoint.getAddress(), path);
	}

	/**
	 * Creates a URI string for a resource hosted on an endpoint.
	 * 
	 * @param address The address of the endpoint that the resource is hosted on.
	 * @param path The path of the resource on the endpoint.
	 * @return The URI string.
	 */
	public static String getUri(final InetSocketAddress address, final String path) {
		return String.format(URI_TEMPLATE, address.getHostString(), address.getPort(), path);
	}

	/**
	 * Creates a random string of numbers of a given length.
	 * 
	 * @param length The length of the string to create.
	 * @return The string.
	 */
	public static String generateRandomPayload(int length) {
		StringBuffer buffer = new StringBuffer();
		while(buffer.length() < length) {
			buffer.append(RAND.nextInt());
		}
		return buffer.substring(0, length);
	}

	/**
	 * Creates a string of ascending single digit numbers of a given length.
	 * 
	 * @param length The length of the string to create.
	 * @return The string.
	 */
	public static String generatePayload(int length) {
		StringBuffer buffer = new StringBuffer();
		int n = 1;
		while(buffer.length() < length) {
			buffer.append(n++);
		}
		return buffer.substring(0, length);
	}
}
