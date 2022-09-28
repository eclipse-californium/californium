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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Set/scope of {@link Definition}s.
 *
 * @param <T> type of definitions
 * @since 3.0
 */
public class Definitions<T extends Definition<?>> implements Iterable<T> {

	/**
	 * Name of definition set.
	 */
	private final String name;
	/**
	 * Map of all definitions of this scope.
	 */
	private final ConcurrentMap<String, T> definitions = new ConcurrentHashMap<>();

	/**
	 * Create definitions set.
	 * 
	 * @param name name of definition set
	 */
	public Definitions(String name) {
		this.name = name;
	}

	/**
	 * Create definitions set.
	 * 
	 * @param definitions initial definition set
	 */
	public Definitions(Definitions<T> definitions) {
		this(definitions.getName(), definitions);
	}

	/**
	 * Create definitions set.
	 * 
	 * @param name name of definition set
	 * @param definitions initial definition set
	 */
	public Definitions(String name, Definitions<T> definitions) {
		this.name = name;
		this.definitions.putAll(definitions.definitions);
	}

	/**
	 * Gets name of definition set.
	 * 
	 * @return name of definition set.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Add definition.
	 * 
	 * @param definition definition with unique {@link Definition#getKey()}
	 *            according this set.
	 * @return the definition set for chaining
	 * @throws IllegalArgumentException if definition was already added or the
	 *             value type is not supported by this definitions.
	 */
	public Definitions<T> add(T definition) {
		T previous = addIfAbsent(definition);
		if (previous != null && previous != definition) {
			throw new IllegalArgumentException(name + " already contains " + definition.getKey() + "!");
		}
		return this;
	}

	/**
	 * Add definition, if absent.
	 * 
	 * @param definition definition with unique {@link Definition#getKey()}
	 *            according this set.
	 * @return the previous definition added with the same
	 *         {@link Definition#getKey()}, or {@code null}, if no previous
	 *         definition was added with that {@link Definition#getKey()}.
	 * @throws IllegalArgumentException if the value type is not supported by
	 *             this definitions.
	 */
	public T addIfAbsent(T definition) {
		if (definition == null) {
			throw new NullPointerException();
		}
		return definitions.putIfAbsent(definition.getKey(), definition);
	}

	/**
	 * Checks, if the definition is contained.
	 * 
	 * @param definition definition to check.
	 * @return {@code true}, if contained, {@code false}, if not.
	 */
	public boolean contains(T definition) {
		T contained = get(definition.getKey());
		return definition == contained;
	}

	/**
	 * Get definition.
	 * 
	 * @param key {@link Definition#getKey()} of definition.
	 * @return definition, or {@code null}, if not available.
	 */
	public T get(String key) {
		return definitions.get(key);
	}

	/**
	 * Check, if definitions are available.
	 * 
	 * @return {@code true}, if no definitions are available, {@code false}, if
	 *         definitions are available.
	 * @since 3.8
	 */
	public boolean isEmpty() {
		return definitions.isEmpty();
	}

	/**
	 * Get number of available definitions.
	 * 
	 * @return number of available definitions.
	 * @since 3.8
	 */
	public int size() {
		return definitions.size();
	}

	@Override
	public Iterator<T> iterator() {
		return definitions.values().iterator();
	}
}
