/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Utility class to create a unmodifiable "ordered set" as {@link List}.
 */
public class ListUtils {

	/**
	 * Initialize ordered values, testing for contained item duplicates.
	 * 
	 * @param <T> element type of list
	 * @param values list of values. May be {@code null}.
	 * @return unmodifiable list with unique items, or {@code null}, if values
	 *         is {@code null}.
	 * @throws IllegalArgumentException if duplicate items are contained
	 */
	public static <T> List<T> init(List<T> values) {
		return init(values, false);
	}

	/**
	 * Initialize ordered values, testing for contained item duplicates.
	 * 
	 * @param <T> element type of list
	 * @param values list of values. May be {@code null}.
	 * @param remove {@code true} remove duplicates, {@code false} throw
	 *            IllegalArgumentException
	 * @return unmodifiable list with unique items, or {@code null}, if values
	 *         is {@code null}.
	 * @throws IllegalArgumentException if duplicate items are contained and
	 *             remove is {@code false}.
	 * @since 3.8
	 */
	public static <T> List<T> init(List<T> values, boolean remove) {
		if (values == null) {
			return null;
		}
		if (values.isEmpty()) {
			return Collections.emptyList();
		}
		List<T> result = new ArrayList<>(values.size());
		result.add(values.get(0));
		if (values.size() > 1) {
			for (int index = 1; index < values.size(); ++index) {
				T item = values.get(index);
				int first = result.indexOf(item);
				if (first < 0) {
					result.add(item);
				} else if (!remove) {
					throw new IllegalArgumentException(
							"Item " + item + "[" + index + "] is already contained at index [" + first + "]!");
				}
			}
		}
		return Collections.unmodifiableList(result);
	}

	/**
	 * Add value to list, if not already contained.
	 * 
	 * @param <T> element type of list
	 * @param list list of values.
	 * @param value value to add. Not added, if {@code null}.
	 * @return the provided list
	 * @throws NullPointerException if list is {@code null}
	 * @since 3.0
	 */
	public static <T> List<T> addIfAbsent(List<T> list, T value) {
		if (list == null) {
			throw new NullPointerException("List must not be null!");
		}
		if (value != null && !list.contains(value)) {
			list.add(value);
		}
		return list;
	}

	/**
	 * Add values to list, if not already contained.
	 * 
	 * @param <T> element type of list
	 * @param list list of values.
	 * @param newValues values to add. {@code null} are not added.
	 * @return the provided list
	 * @throws NullPointerException if list is {@code null}
	 * @since 3.0
	 */
	public static <T> List<T> addIfAbsent(List<T> list, List<T> newValues) {
		if (list == null) {
			throw new NullPointerException("List must not be null!");
		}
		if (newValues != null && !newValues.isEmpty()) {
			for (T value : newValues) {
				if (value != null && !list.contains(value)) {
					list.add(value);
				}
			}
		}
		return list;
	}
}
