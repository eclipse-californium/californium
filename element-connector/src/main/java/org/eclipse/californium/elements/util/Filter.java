/********************************************************************************
 * Copyright (c) 2023 Contributors to the Eclipse Foundation
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

/**
 * A predicate to be applied.
 *
 * @param <V> The type of value the predicate can be evaluated on.
 * @since 3.10
 */
public interface Filter<V> {

	/**
	 * Applies the predicate to a value.
	 * 
	 * @param value The value to evaluate the predicate for.
	 * @return {@code true} if the value is matching.
	 */
	boolean accept(V value);
}
