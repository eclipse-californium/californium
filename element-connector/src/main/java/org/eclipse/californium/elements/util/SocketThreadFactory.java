/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.elements.util;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.ThreadFactory;

/**
 * The socket thread factory.
 * <p>
 * Intended to create threads for handling sockets.
 * 
 * @since 4.0
 */
public class SocketThreadFactory {

	/**
	 * Create socket thread factory.
	 * 
	 * @param prefix prefix for thread names
	 * @param count number of threads to create. {@code -1} to create a single
	 *            virtual thread, {@code > 1} to append numbers to thread name.
	 * @param group thread group. Not used for virtual threads
	 * @return thread factory, or {@code null}, if {@code 0} was provided as
	 *         count.
	 * @since 4.0
	 */
	public static ThreadFactory create(String prefix, int count, ThreadGroup group) {
		if (count == 0) {
			return null;
		}
		Long start = null;
		NamedThreadFactory.Type type = NamedThreadFactory.Type.VIRTUAL;
		if (count > 0) {
			type = NamedThreadFactory.Type.DAEMON;
			if (count > 1) {
				start = 0L;
			}
		}
		return NamedThreadFactory.create(prefix, start, group, type);
	}

	/**
	 * Convert local address to thread name.
	 * 
	 * @param localAddress local address
	 * @return thread name
	 */
	public static String toName(InetSocketAddress localAddress) {
		StringBuilder builder = new StringBuilder();
		builder.append('-');
		InetAddress address = localAddress.getAddress();
		boolean bracket = address instanceof Inet6Address;
		if (bracket) {
			builder.append('[');
		}
		builder.append(address.getHostAddress());
		if (bracket) {
			builder.append(']');
		}
		builder.append(':').append(localAddress.getPort());
		return builder.toString();
	}

}
