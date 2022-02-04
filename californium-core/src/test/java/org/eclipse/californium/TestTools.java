/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add waitForCondition
 *    Achim Kraus (Bosch Software Innovations GmbH) - add inRange
 ******************************************************************************/
package org.eclipse.californium;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Random;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageObserver;
import org.eclipse.californium.core.network.Endpoint;

/**
 * A collection of utility methods for implementing tests.
 */
public final class TestTools {

	public static final String URI_SEPARATOR = "/";
	private static final Random RAND = new Random();
	private static final String URI_TEMPLATE = "coap://%s:%d%s";
	public static final InetSocketAddress LOCALHOST_EPHEMERAL = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);

	private TestTools() {
		// prevent instantiation
	}

	/**
	 * Normalize relative URI path.
	 * 
	 * The values {@code null}, {@code ""}, or {@value #URI_SEPARATOR} are
	 * normalized to {@code null}. For all other values, the returned value is
	 * normalized to start with {@value #URI_SEPARATOR}.
	 * 
	 * @param relativePath path to be normalized
	 * @return normalized path
	 */
	public static String normalizeRelativePath(final String relativePath) {
		if (relativePath != null && !relativePath.isEmpty() && !relativePath.equals(URI_SEPARATOR)) {
			if (relativePath.startsWith(URI_SEPARATOR)) {
				return relativePath;
			} else {
				return URI_SEPARATOR + relativePath;
			}
		} else {
			return "";
		}
	}

	/**
	 * Creates a URI string for a resource hosted on an endpoint.
	 * 
	 * @param endpoint The endpoint the resource is hosted on.
	 * @param path The path of the resource on the endpoint. The value is
	 *            {@link #normalizeRelativePath(String)}.
	 * @return The URI string.
	 */
	public static String getUri(final Endpoint endpoint, final String path) {
		URI uri = endpoint.getUri();
		String resourcePath = normalizeRelativePath(path);
		if (!resourcePath.isEmpty()) {
			try {
				uri = new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(), uri.getPort(),
						uri.getPath() + resourcePath, uri.getQuery(), uri.getFragment());
			} catch (URISyntaxException e) {
			}
		}
		return uri.toASCIIString();
	}

	/**
	 * Creates a URI string for a resource hosted on an endpoint.
	 * 
	 * @param address The address of the endpoint that the resource is hosted
	 *            on.
	 * @param path The path of the resource on the endpoint.
	 * @return The URI string.
	 */
	public static String getUri(final InetSocketAddress address, final String path) {
		String resourcePath = normalizeRelativePath(path);
		return String.format(URI_TEMPLATE, address.getHostString(), address.getPort(), resourcePath);
	}

	/**
	 * Creates a URI string for a resource hosted on an endpoint.
	 * 
	 * @param address The address of the endpoint that the resource is hosted
	 *            on.
	 * @param port The port of the endpoint that the resource is hosted on.
	 * @param path The path of the resource on the endpoint.
	 * @return The URI string.
	 */
	public static String getUri(final InetAddress address, final int port, final String path) {
		String resourcePath = normalizeRelativePath(path);
		return String.format(URI_TEMPLATE, address.getHostAddress(), port, resourcePath);
	}

	/**
	 * Creates a string of random single digit numbers of a given length.
	 * 
	 * @param length The length of the string to create.
	 * @return The string.
	 */
	public static String generateRandomPayload(final int length) {
		StringBuilder buffer = new StringBuilder();
		int counter = 0;
		while (counter < length) {
			buffer.append(Character.forDigit(RAND.nextInt(10), 10));
			counter++;
		}
		return buffer.toString();
	}

	/**
	 * Creates a string of ascending single digit numbers of a given length.
	 * 
	 * @param length The length of the string to create.
	 * @return The string.
	 */
	public static String generatePayload(final int length) {
		StringBuilder buffer = new StringBuilder();
		int n = 0;
		while (buffer.length() < length) {
			buffer.append(Integer.toString(n % 10));
			n++;
		}
		return buffer.toString();
	}

	/**
	 * Remove all observer of the provided type from the message.
	 * 
	 * Cleanup for retransmitted messages.
	 * 
	 * @param message message to remove observer
	 * @param clz type of observer to remove.
	 */
	public static void removeMessageObservers(Message message, Class<?> clz) {
		List<MessageObserver> list = message.getMessageObservers();
		for (MessageObserver observer : list) {
			if (clz.isInstance(observer)) {
				message.removeMessageObserver(observer);
			}
		}
	}

}
