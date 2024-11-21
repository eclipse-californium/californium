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
package org.eclipse.californium.cloud.s3.util;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import org.eclipse.californium.cloud.s3.resources.S3Devices;

/**
 * Multi-consumer.
 * <p>
 * Map of names and consumer.
 * 
 * @param <T> the type of the input to the operation
 * @since 4.0 (moved from {@link S3Devices})
 */
public abstract class MultiConsumer<T> {

	/**
	 * Indicates, that all consumers have been created.
	 */
	private boolean created;
	/**
	 * Map of results.
	 */
	private Map<String, T> results = new HashMap<>();

	/**
	 * Create consumer.
	 * 
	 * @param name tag of consumer
	 * @return created consumer
	 */
	public Consumer<T> create(final String name) {
		synchronized (results) {
			if (results.containsKey(name)) {
				throw new IllegalArgumentException(name + " already used!");
			}
			results.put(name, null);
		}
		return new Consumer<T>() {

			@Override
			public void accept(T t) {
				boolean ready = false;
				synchronized (results) {
					if (t == null) {
						results.remove(name);
					} else {
						results.put(name, t);
					}
					ready = created && !results.containsValue(null);
				}
				if (ready) {
					complete(results);
				}
			}
		};
	}

	/**
	 * Indicate, that all consumer has been created.
	 * 
	 * @return {@code false}, if no consumer has been created before,
	 *         {@code true}, otherwise.
	 */
	public boolean created() {
		boolean ready = false;
		synchronized (results) {
			if (results.isEmpty()) {
				return false;
			}
			created = true;
			ready = !results.containsValue(null);
		}
		if (ready) {
			complete(results);
		}
		return true;
	}

	/**
	 * Called, when all created consumer received their value to accept.
	 * 
	 * @param results map with accepted results.
	 */
	abstract public void complete(Map<String, T> results);
}
