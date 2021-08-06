/*******************************************************************************
 * Copyright (c) 2016, 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - add support for correlation context to provide
 *                                      additional information to application layer for
 *                                      matching messages (fix GitHub issue #1)
 *    Achim Kraus (Bosch Software Innovations GmbH) - extend endpoint context with
 *                                                    inet socket address and principal
 *    Achim Kraus (Bosch Software Innovations GmbH) - make entries map unmodifiable
 *    Achim Kraus (Bosch Software Innovations GmbH) - add constructor with attributes map
 *                                                    to support cloning
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.elements.util.Bytes;

/**
 * A map based endpoint context.
 */
public class MapBasedEndpointContext extends AddressEndpointContext {

	/**
	 * Set of attribute definitions.
	 * 
	 * Only String, Integer, Long, Boolean, InetSocketAddress and Bytes are
	 * supported.
	 * 
	 * @since 3.0
	 */
	public static final Definitions<Definition<?>> ATTRIBUTE_DEFINITIONS = new Definitions<Definition<?>>(
			"EndpointContextAttributes") {

		public Definition<?> addIfAbsent(Definition<?> definition) {
			if (definition == null) {
				throw new NullPointerException();
			}
			Class<?> valueType = definition.getValueType();
			if (valueType != String.class && valueType != Integer.class && valueType != Long.class
					&& valueType != Boolean.class && valueType != InetSocketAddress.class
					&& !Bytes.class.isAssignableFrom(valueType)) {
				throw new IllegalArgumentException(valueType
						+ " is not supported, only String, Integer, Long, Boolean, InetSocketAddress and Bytes!");
			}
			return super.addIfAbsent(definition);
		}
	};

	/**
	 * Prefix for none critical attributes. These attributes are not considered
	 * for context matching nor {@link #hasCriticalEntries()}.
	 */
	public static final String KEY_PREFIX_NONE_CRITICAL = "*";
	/**
	 * {@code true}, if at least one critical attribute is available.
	 * 
	 * @see #findCriticalEntries(Map)
	 */
	private final boolean hasCriticalEntries;
	/**
	 * (Unmodifiable) map of attributes.
	 */
	private final Map<Definition<?>, Object> entries;

	/**
	 * Creates a new endpoint context with correlation context support.
	 * 
	 * @param peerAddress peer address of endpoint context
	 * @param peerIdentity peer identity of endpoint context
	 * @param attributes map of attributes
	 * @throws NullPointerException if provided peer address, or attributes map
	 *             is {@code null}.
	 * @since 3.0
	 */
	public MapBasedEndpointContext(InetSocketAddress peerAddress, Principal peerIdentity, Attributes attributes) {

		this(peerAddress, null, peerIdentity, attributes);
	}

	/**
	 * Creates a new endpoint context with correlation context support.
	 * 
	 * @param peerAddress peer address of endpoint context
	 * @param virtualHost the name of the virtual host at the peer
	 * @param peerIdentity peer identity of endpoint context
	 * @param attributes map of attributes
	 * @throws NullPointerException if provided peer address, or attributes map
	 *             is {@code null}.
	 * @since 3.0
	 */
	public MapBasedEndpointContext(InetSocketAddress peerAddress, String virtualHost, Principal peerIdentity,
			Attributes attributes) {

		super(peerAddress, virtualHost, peerIdentity);

		if (attributes == null) {
			throw new NullPointerException("missing attributes map, must not be null!");
		}
		attributes.lock();
		this.entries = Collections.unmodifiableMap(attributes.entries);
		this.hasCriticalEntries = findCriticalEntries(entries);
	}

	/**
	 * Check, if at least one critical attribute is contained in the provided
	 * map.
	 * 
	 * Use {@link #KEY_PREFIX_NONE_CRITICAL} to distinguish the critical from
	 * the none critical attributes.
	 * 
	 * @param attributes map of attributes
	 * @return {@code true}, if at least one critical attribute is contained.
	 */
	private static final boolean findCriticalEntries(Map<Definition<?>, Object> attributes) {
		for (Definition<?> key : attributes.keySet()) {
			if (!key.getKey().startsWith(KEY_PREFIX_NONE_CRITICAL)) {
				return true;
			}
		}
		return false;
	}

	@SuppressWarnings("unchecked")
	@Override
	public <T> T get(Definition<T> key) {
		return (T) entries.get(key);
	}

	@Override
	public Map<Definition<?>, Object> entries() {
		return entries;
	}

	@Override
	public boolean hasCriticalEntries() {
		return hasCriticalEntries;
	}

	@Override
	public String toString() {
		return String.format("MAP(%s)", getPeerAddressAsString());
	}

	/**
	 * Set entries to endpoint context.
	 * 
	 * @param context original endpoint context.
	 * @param attributes map of attributes.
	 * @return new endpoint context with attributes.
	 * @throws NullPointerException if the provided attributes is {@code null}
	 * @since 3.0
	 */
	public static MapBasedEndpointContext setEntries(EndpointContext context, Attributes attributes) {
		return new MapBasedEndpointContext(context.getPeerAddress(), context.getVirtualHost(),
				context.getPeerIdentity(), attributes);
	}

	/**
	 * Add entries to endpoint context.
	 * 
	 * @param context original endpoint context.
	 * @param attributes map of attributes. The provided attributes may
	 *            overwrite already available ones.
	 * @return new endpoint context with additional attributes.
	 * @throws NullPointerException if the provided attributes is {@code null}
	 * @since 3.0
	 */
	public static MapBasedEndpointContext addEntries(EndpointContext context, Attributes attributes) {
		Attributes allAttributes = new Attributes(context.entries());
		allAttributes.addAll(attributes);
		return setEntries(context, allAttributes);
	}

	/**
	 * Remove entries from endpoint context.
	 * 
	 * @param context original endpoint context.
	 * @param attributes list of key
	 * @return new endpoint context with attributes removed.
	 * @throws NullPointerException if the provided attributes is {@code null},
	 *             or one of the attributes is {@code null}.
	 * @throws IllegalArgumentException if provided attributes list is not
	 *             contained in the original context.
	 * @since 2.1
	 */
	public static MapBasedEndpointContext removeEntries(EndpointContext context, Definition<?>... attributes) {
		if (attributes == null) {
			throw new NullPointerException("attributes must not null!");
		}
		Attributes entries = new Attributes(context.entries());
		for (int index = 0; index < attributes.length; ++index) {
			try {
				Definition<?> key = attributes[index];
				if (!entries.remove(key)) {
					throw new IllegalArgumentException(index + ". key '" + key + "' is not contained");
				}
			} catch (NullPointerException ex) {
				throw new NullPointerException(index + ". " + ex.getMessage());
			} catch (IllegalArgumentException ex) {
				throw new IllegalArgumentException(index + ". " + ex.getMessage());
			}
		}
		return new MapBasedEndpointContext(context.getPeerAddress(), context.getVirtualHost(),
				context.getPeerIdentity(), entries);
	}

	/**
	 * Typed attributes.
	 * 
	 * All attributes must have a unique, none empty, none {@code null} key.
	 * Key's of none-critical attributes starts with
	 * {@link MapBasedEndpointContext#KEY_PREFIX_NONE_CRITICAL}, key's for
	 * critical attributes don't start with that.
	 * 
	 * Values must not be {@code null}. For critical attributes that causes an
	 * {@link NullPointerException}, for none-critical the add is ignored.
	 * 
	 * @since 3.0
	 */
	public static final class Attributes {

		/**
		 * Map of attributes.
		 */
		private final Map<Definition<?>, Object> entries = new HashMap<>();
		/**
		 * Protect attributes from further modification.
		 */
		private volatile boolean lock;

		/**
		 * Create empty instance.
		 */
		public Attributes() {
		}

		/**
		 * Create instance from available entries.
		 * 
		 * @param entries available entries.
		 */
		private Attributes(Map<Definition<?>, Object> entries) {
			this.entries.putAll(entries);
		}

		/**
		 * Lock attributes. Protect from further modifications.
		 * 
		 * @return this for chaining
		 */
		public Attributes lock() {
			lock = true;
			return this;
		}

		/**
		 * Add attributes.
		 * 
		 * May overwrite already available values.
		 * 
		 * Provides a fluent API to chain add functions.
		 * 
		 * @param attributes attributes to add
		 * @return this for chaining
		 * @throws IllegalStateException if instance is locked
		 */
		public Attributes addAll(Attributes attributes) {
			if (lock) {
				throw new IllegalStateException("Already in use!");
			}
			this.entries.putAll(attributes.entries);
			return this;
		}

		/**
		 * Add value for key.
		 * 
		 * @param <T> value type. Support String, Integer, Long, Boolean,
		 *            InetSocketAddress and Bytes. Other types may break
		 *            serialization, especially custom serialization!
		 * @param definition definition to add. Must be contained in
		 *            {@link MapBasedEndpointContext#ATTRIBUTE_DEFINITIONS}.
		 * @param value value to add
		 * @return this for chaining
		 * @throws NullPointerException if key is {@code null}, or a critical
		 *             value is {@code null}
		 * @throws IllegalArgumentException if key is empty or the definition is
		 *             not contained in
		 *             {@link MapBasedEndpointContext#ATTRIBUTE_DEFINITIONS}.
		 * @throws IllegalStateException if instance is locked
		 */
		public <T> Attributes add(Definition<T> definition, T value) {
			if (lock) {
				throw new IllegalStateException("Already in use!");
			} else if (null == definition) {
				throw new NullPointerException("key is null");
			} else if (null == value) {
				if (!definition.getKey().startsWith(KEY_PREFIX_NONE_CRITICAL)) {
					throw new NullPointerException("value is null");
				}
			}
			if (!ATTRIBUTE_DEFINITIONS.contains(definition)) {
				throw new IllegalArgumentException(definition + " is not supported!");
			}
			if (value == null) {
				entries.remove(definition);
			} else if (entries.put(definition, value) != null) {
				throw new IllegalArgumentException("'" + definition + "' already contained!");
			}
			return this;
		}

		/**
		 * Check, if attribute is available.
		 * 
		 * @param <T> value type
		 * @param key the key to check
		 * @return {@code true}, if available, {@code false}, if not.
		 * @throws NullPointerException if key is {@code null}
		 * @throws IllegalArgumentException if key is empty
		 */
		public <T> boolean contains(Definition<T> key) {
			if (null == key) {
				throw new NullPointerException("key is null");
			}
			return entries.containsKey(key);
		}

		/**
		 * Remove attribute.
		 * 
		 * @param <T> value type
		 * @param key key to remove
		 * @return {@code true}, if available, {@code false}, if not.
		 * @throws NullPointerException if key is {@code null}
		 * @throws IllegalArgumentException if key is empty
		 * @throws IllegalStateException if instance is locked
		 */
		public <T> boolean remove(Definition<T> key) {
			if (lock) {
				throw new IllegalStateException("Already in use!");
			} else if (null == key) {
				throw new NullPointerException("key is null");
			}
			return entries.remove(key) != null;
		}

		@Override
		public int hashCode() {
			return entries.hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (obj instanceof Attributes) {
				Attributes other = (Attributes) obj;
				return entries.equals(other.entries);
			}
			return false;
		}
	}
}
