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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.concurrent.ThreadFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Thread factory for virtual threads.
 * <p>
 * Java 21 introduces the new virtual threads, which are very useful for
 * emulating multiple clients within one JVM. Though Californium supports java 8
 * as minimum requirement, the {@link ThreadFactory} for virtual threads are
 * created via reflection.
 * 
 * @since 4.0
 */
public class VirtualThreadFactory {

	/** The logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(VirtualThreadFactory.class);

	private static final Method ofVirtual;
	private static final Method name1;
	private static final Method name2;
	private static final Method factory;

	static {
		Method virtual = null;
		Method n1 = null;
		Method n2 = null;
		Method f = null;
		try {
			virtual = Thread.class.getMethod("ofVirtual");
			Class<?> clz = Class.forName(Thread.class.getName() + "$Builder");
			n1 = clz.getMethod("name", String.class);
			n2 = clz.getMethod("name", String.class, long.class);
			f = clz.getMethod("factory");
			LOGGER.info("Virtual threads available.");
		} catch (ClassNotFoundException e) {
			LOGGER.info("Missing class {}, virtual threads are not available.", e.getMessage());
		} catch (NoSuchMethodException e) {
			LOGGER.info("Missing method {}, virtual threads are not available", e.getMessage());
		} catch (SecurityException e) {
			LOGGER.info("{}, virtual threads are not available", e.getMessage());
		}
		ofVirtual = virtual;
		name1 = n1;
		name2 = n2;
		factory = f;
	}

	/**
	 * Checks, if virtual thread factory is available.
	 * <p>
	 * Only JVM 21 or newer supports virtual threads.
	 * 
	 * @return {@code true} if virtual threads are supported.
	 */
	public static boolean isAvailable() {
		return factory != null;
	}

	/**
	 * Create thread factory for virtual threads.
	 * 
	 * @param prefix prefix for thread name. {@code "V-"} will be added that the
	 *            head.
	 * @param start starting number for the name. {@code null} to use name
	 *            without counter.
	 * @return thread factory for virtual threads.
	 * @throws IllegalStateException if virtual threads are not available
	 * @throws IllegalArgumentException if creating the thread factory failed
	 */
	public static ThreadFactory create(String prefix, Long start) {
		if (!isAvailable()) {
			throw new IllegalStateException("Reflection thread factory not available!");
		}
		try {
			Object builder = ofVirtual.invoke(null);
			prefix = "V-" + prefix;
			if (start != null) {
				name2.invoke(builder, prefix, start);
			} else {
				name1.invoke(builder, prefix);
			}
			return (ThreadFactory) factory.invoke(builder);
		} catch (IllegalAccessException | InvocationTargetException e) {
			throw new IllegalArgumentException("virtual thread factory failed!");
		}
	}
}
