/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.config;

import java.util.Collections;
import java.util.List;

/**
 * Basic definitions for list values.
 *
 * @param <T> item value type
 * @see Configuration#get(BasicDefinition)
 * @see Configuration#setAsList(BasicListDefinition, Object...)
 * @see Configuration#setAsListFromText(BasicListDefinition, String...)
 * @since 3.0
 */
public abstract class BasicListDefinition<T> extends BasicDefinition<List<T>> {

	/**
	 * Creates basic list definition with default value.
	 * 
	 * @param key key for properties. Must be global unique.
	 * @param documentation documentation for properties.
	 * @param defaultValue default value returned instead of {@code null}.
	 * @throws NullPointerException if key is {@code null}
	 */
	@SuppressWarnings("unchecked")
	protected BasicListDefinition(String key, String documentation, List<T> defaultValue) {
		super(key, documentation, (Class<List<T>>) (Class<?>) List.class, defaultValue);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Returns an unmodifiable {@code List<T>}, or {@code null}, if value is
	 * {@code null}.
	 */
	@Override
	public List<T> checkValue(List<T> value) throws ValueException {
		if (value != null) {
			try {
				// forces an exception
				value.remove(-1);
			} catch (IndexOutOfBoundsException ex) {
				value = Collections.unmodifiableList(value);
			} catch (UnsupportedOperationException ex) {
			}
		}
		return value;
	}

}
