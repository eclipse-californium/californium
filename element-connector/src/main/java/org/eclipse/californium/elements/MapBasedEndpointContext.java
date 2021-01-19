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
	private final Map<String, Object> entries;

	/**
	 * Creates a context for a socket address, authenticated identity and
	 * arbitrary key/value pairs.
	 * 
	 * @param peerAddress peer address of endpoint context
	 * @param peerIdentity peer identity of endpoint context
	 * @param attributes list of attributes (key/value pairs, e.g. key_1,
	 *            value_1, key_2, value_2 ...)
	 * @throws NullPointerException if provided peer address is {@code null},
	 *             the provided attributes is {@code null}, or one of the
	 *             attributes is {@code null}.
	 * @throws IllegalArgumentException if provided attributes list has odd size
	 *             or contains a duplicate key.
	 */
	public MapBasedEndpointContext(InetSocketAddress peerAddress, Principal peerIdentity, String... attributes) {

		this(peerAddress, null, peerIdentity, attributes);
	}

	/**
	 * Creates a context for a socket address, authenticated identity and
	 * arbitrary key/value pairs.
	 * 
	 * @param peerAddress peer address of endpoint context
	 * @param virtualHost the name of the virtual host at the peer
	 * @param peerIdentity peer identity of endpoint context
	 * @param attributes list of attributes (key/value pairs, e.g. key_1,
	 *            value_1, key_2, value_2 ...)
	 * @throws NullPointerException if provided peer address is {@code null},
	 *             the provided attributes is {@code null}, or one of the
	 *             attributes is {@code null}.
	 * @throws IllegalArgumentException if provided attributes list has odd size
	 *             or contains a duplicate key.
	 */
	public MapBasedEndpointContext(InetSocketAddress peerAddress, String virtualHost, Principal peerIdentity,
			String... attributes) {
		this(peerAddress, virtualHost, peerIdentity, createAttributes(attributes));
	}

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
	 * Create map of attributes.
	 * 
	 * @param attributes list of attributes (key/value pairs, e.g. key_1,
	 *            value_1, key_2, value_2 ...)
	 * @return create map
	 * @throws NullPointerException if the provided attributes is {@code null},
	 *             or one of the critical attributes is {@code null}.
	 * @throws IllegalArgumentException if provided attributes list has odd size
	 *             or contains a duplicate key.
	 */
	private static final Attributes createAttributes(String... attributes) {
		if (attributes == null) {
			throw new NullPointerException("attributes must not null!");
		}
		if ((attributes.length & 1) != 0) {
			throw new IllegalArgumentException("number of attributes must be even, not " + attributes.length + "!");
		}
		Attributes entries = new Attributes();
		for (int index = 0; index < attributes.length; ++index) {
			try {
				String key = attributes[index];
				String value = attributes[++index];
				entries.add(key, value);
			} catch (NullPointerException ex) {
				throw new NullPointerException((index / 2) + ". " + ex.getMessage());
			} catch (IllegalArgumentException ex) {
				throw new IllegalArgumentException((index / 2) + ". " + ex.getMessage());
			}
		}
		return entries;
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
	private static final boolean findCriticalEntries(Map<String, Object> attributes) {
		for (String key : attributes.keySet()) {
			if (!key.startsWith(KEY_PREFIX_NONE_CRITICAL)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public Object get(String key) {
		return entries.get(key);
	}

	@Override
	public Map<String, Object> entries() {
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
	 * @param attributes list of attributes (key/value pairs, e.g. key_1,
	 *            value_1, key_2, value_2 ...)..
	 * @return new endpoint context with attributes.
	 * @throws NullPointerException if the provided attributes is {@code null},
	 *             or one of the attributes is {@code null}.
	 * @throws IllegalArgumentException if provided attributes list has odd size
	 *             or contains a duplicate key.
	 *             @since 3.0
	 */
	public static MapBasedEndpointContext setEntries(EndpointContext context, String... attributes) {
		return setEntries(context, createAttributes(attributes));
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
	 * @param attributes list of attributes (key/value pairs, e.g. key_1,
	 *            value_1, key_2, value_2 ...). The provided attributes may
	 *            overwrite already available ones.
	 * @return new endpoint context with additional attributes.
	 * @throws NullPointerException if the provided attributes is {@code null},
	 *             or one of the attributes is {@code null}.
	 * @throws IllegalArgumentException if provided attributes list has odd size
	 *             or contains a duplicate key.
	 */
	public static MapBasedEndpointContext addEntries(EndpointContext context, String... attributes) {
		return addEntries(context, createAttributes(attributes));
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
	public static MapBasedEndpointContext removeEntries(EndpointContext context, String... attributes) {
		if (attributes == null) {
			throw new NullPointerException("attributes must not null!");
		}
		Attributes entries = new Attributes(context.entries());
		for (int index = 0; index < attributes.length; ++index) {
			try {
				String key = attributes[index];
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
		private final Map<String, Object> entries = new HashMap<>();
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
		private Attributes(Map<String, Object> entries) {
			this.entries.putAll(entries);
		}

		/**
		 * Lock attributes. Protect from further modifications.
		 */
		public void lock() {
			lock = true;
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
		 * @param key key to add
		 * @param value value to add
		 * @throws NullPointerException if key is {@code null}, or a critical
		 *             value is {@code null}
		 * @throws IllegalArgumentException if key is empty
		 * @throws IllegalStateException if instance is locked
		 */
		private void addObject(String key, Object value) {
			if (lock) {
				throw new IllegalStateException("Already in use!");
			} else if (null == key) {
				throw new NullPointerException("key is null");
			} else if (key.isEmpty()) {
				throw new IllegalArgumentException("key is empty");
			} else if (null == value) {
				if (!key.startsWith(KEY_PREFIX_NONE_CRITICAL)) {
					throw new NullPointerException("value is null");
				}
			} else if (entries.put(key, value) != null) {
				throw new IllegalArgumentException("'" + key + "' already contained!");
			}
		}

		/**
		 * Add {@link String} value with key.
		 * 
		 * Provides a fluent API to chain add functions.
		 * 
		 * @param key key to add
		 * @param value value to add
		 * @return this for chaining
		 * @throws NullPointerException if key is {@code null}, or a critical
		 *             value is {@code null}
		 * @throws IllegalArgumentException if key is empty
		 * @throws IllegalStateException if instance is locked
		 */
		public Attributes add(String key, String value) {
			addObject(key, value);
			return this;
		}

		/**
		 * Add {@link Integer} value with key.
		 * 
		 * Provides a fluent API to chain add functions.
		 * 
		 * @param key key to add
		 * @param value value to add
		 * @return this for chaining
		 * @throws NullPointerException if key is {@code null}, or a critical
		 *             value is {@code null}
		 * @throws IllegalArgumentException if key is empty
		 * @throws IllegalStateException if instance is locked
		 */
		public Attributes add(String key, Integer value) {
			addObject(key, value);
			return this;
		}

		/**
		 * Add {@link Long} value with key.
		 * 
		 * Provides a fluent API to chain add functions.
		 * 
		 * @param key key to add
		 * @param value value to add
		 * @return this for chaining
		 * @throws NullPointerException if key is {@code null}, or a critical
		 *             value is {@code null}
		 * @throws IllegalArgumentException if key is empty
		 * @throws IllegalStateException if instance is locked
		 */
		public Attributes add(String key, Long value) {
			addObject(key, value);
			return this;
		}

		/**
		 * Add {@link Bytes} value with key.
		 * 
		 * Provides a fluent API to chain add functions.
		 * 
		 * @param key key to add
		 * @param value value to add
		 * @return this for chaining
		 * @throws NullPointerException if key is {@code null}, or a critical
		 *             value is {@code null}
		 * @throws IllegalArgumentException if key is empty
		 * @throws IllegalStateException if instance is locked
		 */
		public Attributes add(String key, Bytes value) {
			addObject(key, value);
			return this;
		}

		/**
		 * Check, if attribute is available.
		 * 
		 * @param key the key to check
		 * @return {@code true}, if available, {@code false}, if not.
		 * @throws NullPointerException if key is {@code null}
		 * @throws IllegalArgumentException if key is empty
		 */
		public boolean contains(String key) {
			if (null == key) {
				throw new NullPointerException("key is null");
			} else if (key.isEmpty()) {
				throw new IllegalArgumentException("key is empty");
			}
			return entries.containsKey(key);
		}

		/**
		 * Remove attribute.
		 * 
		 * @param key key to remove
		 * @return {@code true}, if available, {@code false}, if not.
		 * @throws NullPointerException if key is {@code null}
		 * @throws IllegalArgumentException if key is empty
		 * @throws IllegalStateException if instance is locked
		 */
		public boolean remove(String key) {
			if (lock) {
				throw new IllegalStateException("Already in use!");
			} else if (null == key) {
				throw new NullPointerException("key is null");
			} else if (key.isEmpty()) {
				throw new IllegalArgumentException("key is empty");
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
