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
package org.eclipse.californium.core.coap.option;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.CodeClass;
import org.eclipse.californium.core.coap.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Option registry.
 * 
 * Using {@link Map}s to keep the {@link OptionDefinition}s.
 * 
 * @since 3.8
 */
public class MapBasedOptionRegistry implements OptionRegistry {

	private final static Logger LOGGER = LoggerFactory.getLogger(MapBasedOptionRegistry.class);

	/**
	 * Map by option number.
	 * 
	 * To support message code specific option numbers, the option number is
	 * extended with the message code.
	 * 
	 * @see #getExtendedNumber(int, int)
	 */
	protected final Map<Integer, OptionDefinition> numberMap = new ConcurrentHashMap<>();
	/**
	 * Map by option name.
	 */
	private final Map<String, OptionDefinition> nameMap = new ConcurrentHashMap<>();

	/**
	 * Create option definition map from option definitions.
	 * 
	 * @param definitions option definitions to add
	 */
	public MapBasedOptionRegistry(OptionDefinition... definitions) {
		try {
			for (OptionDefinition definition : definitions) {
				put(definition);
			}
		} catch (IllegalArgumentException ex) {
			LOGGER.error("{}", ex.getMessage());
			throw ex;
		}
	}

	/**
	 * Create option definition map from option registry and option definitions.
	 * 
	 * @param registry option registry to add.
	 * @param definitions option definitions to add
	 */
	public MapBasedOptionRegistry(OptionRegistry registry, OptionDefinition... definitions) {
		try {
			add(registry);
			for (OptionDefinition definition : definitions) {
				put(definition);
			}
		} catch (IllegalArgumentException ex) {
			LOGGER.error("{}", ex.getMessage());
			throw ex;
		}
	}

	/**
	 * Create option definition map from option registries.
	 * 
	 * @param registry option registry to add.
	 * @param registries additional option registry to add.
	 */
	public MapBasedOptionRegistry(OptionRegistry registry, OptionRegistry... registries) {
		try {
			add(registry);
			for (OptionRegistry reg : registries) {
				add(reg);
			}
		} catch (IllegalArgumentException ex) {
			LOGGER.error("{}", ex.getMessage());
			throw ex;
		}
	}

	/**
	 * Add option registry.
	 * 
	 * @param registry option registry to add.
	 */
	protected void add(OptionRegistry registry) {
		for (Entry entry : registry) {
			putInternal(entry.getKey(), entry.getOptioneDefinition());
		}
	}

	/**
	 * Add message code unspecific option definition.
	 * 
	 * @param definition option definition
	 */
	protected void put(OptionDefinition definition) {
		putInternal(getExtendedNumber(0, definition.getNumber()), definition);
	}

	/**
	 * Add message code specific option definition.
	 * 
	 * @param code message code
	 * @param definition option definition
	 * @see Message#getRawCode()
	 * @see #getExtendedNumber(int, int)
	 */
	protected void put(int code, OptionDefinition definition) {
		putInternal(getExtendedNumber(code, definition.getNumber()), definition);
	}

	/**
	 * Add message code specific option definition.
	 * 
	 * @param key extended option number
	 * @param definition option definition
	 * @see #getExtendedNumber(int, int)
	 */
	protected synchronized void putInternal(int key, OptionDefinition definition) {
		OptionDefinition current = numberMap.get(key);
		if (current != null) {
			throw new IllegalArgumentException(
					"Number " + definition.getNumber() + " already in use for " + current.getName());
		}
		current = nameMap.get(definition.getName());
		if (current != null) {
			throw new IllegalArgumentException(
					"Name " + definition.getName() + " already in use for " + current.getNumber());
		}
		numberMap.put(key, definition);
		nameMap.put(definition.getName(), definition);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Calls {@link #getCustomDefinition(int)} on missing none code specific
	 * definition. Legacy support adds either a {@code CustomOptionDefinition},
	 * if missing and supported by {@code CustomOptionNumberRegistry}, or
	 * returns a ephemeral {@code UnspecificOptionDefinition}, if
	 * {@code #supportUndefinedOptions} is enabled.
	 */
	@Override
	public OptionDefinition getDefinitionByNumber(int code, int optionNumber) {
		int key = getExtendedNumber(code, optionNumber);
		OptionDefinition defintion = getInternal(key);
		if (defintion == null && key == optionNumber) {
			defintion = getCustomDefinition(optionNumber);
		}
		return defintion;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Calls {@link #getCustomDefinition(int)} on missing definition. Legacy
	 * support adds either a {@code CustomOptionDefinition}, if missing and
	 * supported by {@code CustomOptionNumberRegistry}, or returns a ephemeral
	 * {@code UnspecificOptionDefinition}, if {@code #supportUndefinedOptions}
	 * is enabled.
	 */
	@Override
	public OptionDefinition getDefinitionByNumber(int optionNumber) {
		int key = getExtendedNumber(0, optionNumber);
		OptionDefinition defintion = getInternal(key);
		if (defintion == null) {
			defintion = getCustomDefinition(optionNumber);
		}
		return defintion;
	}

	/**
	 * Get custom definition.
	 * 
	 * Intended to be overwritten, if legacy support for custom definitions is
	 * required.
	 * 
	 * @param optionNumber option number
	 * @return option definition
	 * @deprecated please add used option definition before using it
	 */
	@Deprecated
	protected OptionDefinition getCustomDefinition(int optionNumber) {
		return null;
	}

	/**
	 * Get option definition.
	 * 
	 * @param key key (extended option number)
	 * @return option definition
	 * @see #getExtendedNumber(int, int)
	 */
	protected OptionDefinition getInternal(int key) {
		return numberMap.get(key);
	}

	@Override
	public OptionDefinition getDefinitionByName(String name) {
		return nameMap.get(name);
	}

	@Override
	public boolean contains(OptionDefinition definition) {
		if (numberMap.containsValue(definition)) {
			return true;
		}
		OptionDefinition contained = numberMap.get(definition.getNumber());
		if (contained != null) {
			LOGGER.debug("{}/{} => {}/{}: {}.", definition.getNumber(), definition.getName(), contained.getNumber(),
					contained.getName(), contained == definition);
			return definition.equals(contained);
		}
		return false;
	}

	@Override
	public Iterator<Entry> iterator() {
		return new Iterator<OptionRegistry.Entry>() {

			private final Iterator<Map.Entry<Integer, OptionDefinition>> cursor = numberMap.entrySet().iterator();

			@Override
			public boolean hasNext() {
				return cursor.hasNext();
			}

			@Override
			public Entry next() {
				return new DefinitionEntry(cursor.next());
			}

			@Override
			public void remove() {
				cursor.remove();
			}

		};
	}

	/**
	 * Definition entry.
	 * 
	 * Used internal for {@link MapBasedOptionRegistry#iterator()}.
	 */
	private static class DefinitionEntry implements Entry {

		/**
		 * Related map entry.
		 */
		private final Map.Entry<Integer, OptionDefinition> entry;

		/**
		 * Create definition entry from map entry.
		 * 
		 * @param entry map entry
		 */
		private DefinitionEntry(Map.Entry<Integer, OptionDefinition> entry) {
			this.entry = entry;
		}

		@Override
		public int getKey() {
			return entry.getKey();
		}

		@Override
		public OptionDefinition getOptioneDefinition() {
			return entry.getValue();
		}

	}

	/**
	 * Get extended message code specific option number.
	 * 
	 * @param code message code
	 * @param optionNumber option number
	 * @return extended option number
	 * @see Message#getRawCode()
	 * @see OptionDefinition#getNumber()
	 */
	protected static int getExtendedNumber(int code, int optionNumber) {
		if (optionNumber > 0xffff || optionNumber < 0) {
			throw new IllegalArgumentException(optionNumber + " invalid option number!");
		}
		if (CoAP.getCodeClass(code) == CodeClass.SIGNAL.value) {
			return (optionNumber & 0xffff) + (code << 16);
		} else {
			return optionNumber;
		}
	}
}
