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

import java.util.Arrays;

import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionNumberRegistry.CustomOptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionNumberRegistry.OptionFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Legacy option registry.
 * 
 * Provides backwards compatibility for the deprecated
 * {@link CustomOptionNumberRegistry}.
 * 
 * @deprecated only for backwards compatibility
 * @since 3.8
 */
@Deprecated
public class LegacyMapBasedOptionRegistry extends MapBasedOptionRegistry {

	private final static Logger LOGGER = LoggerFactory.getLogger(LegacyMapBasedOptionRegistry.class);

	/**
	 * Enables to support undefined options.
	 * 
	 * Only for backwards compatibility. Please add {@link OptionDefinition}s
	 * for all used customer options. With the next major version, all undefined
	 * options will be either ignored (none-critical) or cause an error
	 * (critical).
	 */
	private final boolean supportUndefinedOptions;
	/**
	 * Array with supported critical custom options.
	 * 
	 * Only for backwards compatibility. Please add {@link OptionDefinition}s
	 * for all used customer options. With the next major version, all undefined
	 * options will be either ignored (none-critical) or cause an error
	 * (critical).
	 */
	private final int[] criticalCustomOptions;
	/**
	 * Custom option number registry.
	 * 
	 * Only for backwards compatibility. Please add {@link OptionDefinition}s
	 * for all used customer options. With the next major version, all undefined
	 * options will be either ignored (none-critical) or cause an error
	 * (critical).
	 */
	private final CustomOptionNumberRegistry customOptionNumberRegistry;

	/**
	 * Create legacy option registry.
	 * 
	 * @param supportUndefinedOptions {@code true} to enable support for
	 *            undefined options.
	 * @param criticalCustomOptions array with option numbers of critical custom
	 *            options. If {@code null} but option registries with a custom
	 *            option number registry are provided, use that as default.
	 * @param registries registries to include
	 */
	public LegacyMapBasedOptionRegistry(boolean supportUndefinedOptions, int[] criticalCustomOptions,
			OptionRegistry... registries) {
		this.supportUndefinedOptions = supportUndefinedOptions;
		this.customOptionNumberRegistry = getCustomOptionNumberRegistry(registries);
		if (this.customOptionNumberRegistry != null && criticalCustomOptions == null) {
			criticalCustomOptions = this.customOptionNumberRegistry.getCriticalCustomOptions();
		}
		if (criticalCustomOptions != null) {
			this.criticalCustomOptions = criticalCustomOptions.clone();
			Arrays.sort(this.criticalCustomOptions);
		} else {
			this.criticalCustomOptions = null;
		}
		for (OptionRegistry registry : registries) {
			add(registry);
		}
	}

	/**
	 * Create legacy option registry.
	 * 
	 * @param supportUndefinedOptions {@code true} to enable support for
	 *            undefined options.
	 * @param customOptionNumberRegistry custom option number registry. If
	 *            {@code null} but option registries with a custom option number
	 *            registry are provided, use that as default.
	 * @param registries registries to include
	 */
	public LegacyMapBasedOptionRegistry(boolean supportUndefinedOptions,
			CustomOptionNumberRegistry customOptionNumberRegistry, OptionRegistry... registries) {
		int[] criticalCustomOptions = null;
		this.supportUndefinedOptions = supportUndefinedOptions;

		if (customOptionNumberRegistry != null) {
			this.customOptionNumberRegistry = customOptionNumberRegistry;
			criticalCustomOptions = this.customOptionNumberRegistry.getCriticalCustomOptions();
		} else {
			this.customOptionNumberRegistry = getCustomOptionNumberRegistry(registries);
			if (this.customOptionNumberRegistry != null) {
				criticalCustomOptions = this.customOptionNumberRegistry.getCriticalCustomOptions();
			}
		}
		if (criticalCustomOptions != null) {
			this.criticalCustomOptions = criticalCustomOptions.clone();
			Arrays.sort(this.criticalCustomOptions);
		} else {
			this.criticalCustomOptions = null;
		}
		for (OptionRegistry registry : registries) {
			add(registry);
		}
	}

	/**
	 * Check, if option number is a (supported) critical custom option.
	 * 
	 * @param optionNumber option number to check
	 * @return {@code true}, if option number is a critical custom option,
	 *         {@code false}, if not.
	 */
	private boolean isSupportedCiriticalCustomOption(int optionNumber) {
		return criticalCustomOptions == null || Arrays.binarySearch(criticalCustomOptions, optionNumber) >= 0;
	}

	@Override
	public void add(OptionRegistry registry) {
		super.add(registry);
	}

	@Override
	public void put(OptionDefinition definition) {
		super.put(definition);
	}

	@Override
	protected OptionDefinition getCustomDefinition(int optionNumber) {
		boolean add = false;
		OptionDefinition definition = null;
		if (customOptionNumberRegistry != null) {
			String name = customOptionNumberRegistry.toString(optionNumber);
			if (customOptionNumberRegistry.toNumber(name) != OptionNumberRegistry.UNKNOWN) {
				definition = new CustomOptionDefinition(optionNumber, customOptionNumberRegistry);
				add = true;
			}
		}
		if (definition == null && supportUndefinedOptions) {
			if (!OptionNumberRegistry.isCritical(optionNumber) || isSupportedCiriticalCustomOption(optionNumber)) {
				definition = new UnspecificOptionDefinition(optionNumber);
			}
		}
		if (add) {
			try {
				put(definition);
				LOGGER.debug("{}/{} added.", definition.getNumber(), definition.getName());
			} catch (IllegalArgumentException ex) {
				return super.getInternal(optionNumber);
			}
		}
		return definition;
	}

	@Override
	public boolean contains(OptionDefinition definition) {
		if (super.contains(definition)) {
			return true;
		}
		if (supportUndefinedOptions) {
			return definition instanceof UnspecificOptionDefinition;
		}
		return false;
	}

	private static CustomOptionNumberRegistry getCustomOptionNumberRegistry(OptionRegistry... registries) {
		CustomOptionNumberRegistry customRegistry = null;
		for (OptionRegistry registry : registries) {
			if (registry instanceof LegacyMapBasedOptionRegistry) {
				if (customRegistry == null) {
					customRegistry = ((LegacyMapBasedOptionRegistry) registry).customOptionNumberRegistry;
				} else if (customRegistry != ((LegacyMapBasedOptionRegistry) registry).customOptionNumberRegistry) {
					throw new IllegalArgumentException("Ambiguous custom registry");
				}
			}
		}
		return customRegistry;
	}

	private static class UnspecificOptionDefinition implements OptionDefinition {

		private static final int[] LENGTHS = { 0, 65535 + 269 };

		private final int optionNumber;
		private final String name;

		protected UnspecificOptionDefinition(int optionNumber) {
			this(optionNumber, String.format("Unknown (%d)", optionNumber));
		}

		protected UnspecificOptionDefinition(int optionNumber, String name) {
			this.optionNumber = optionNumber;
			this.name = name;
		}

		@Override
		public OptionFormat getFormat() {
			return OptionFormat.UNKNOWN;
		}

		@Override
		public boolean isSingleValue() {
			return true;
		}

		@Override
		public void assertValue(byte[] value) {
			int valueLength = value.length;
			int lengths[] = getValueLengths();
			int min = lengths[0];
			int max = lengths.length == 1 ? min : lengths[1];

			if (valueLength < min || valueLength > max) {
				if (min == max) {
					if (min == 0) {
						throw new IllegalArgumentException(
								"Option " + getName() + " value of " + valueLength + " bytes must be empty.");
					} else {
						throw new IllegalArgumentException("Option " + getName() + " value of " + valueLength
								+ " bytes must be " + min + " bytes.");
					}
				} else {
					throw new IllegalArgumentException("Option " + getName() + " value of " + valueLength
							+ " bytes must be in range of [" + min + "-" + max + "] bytes.");
				}
			}
		}

		@Override
		public int[] getValueLengths() {
			return LENGTHS;
		}

		@Override
		public int getNumber() {
			return optionNumber;
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public Option create(byte[] value) {
			return new Option(this, value);
		}

		@Override
		public Option create(String value) {
			return create(StringOptionDefinition.setStringValue(value));
		}

		@Override
		public Option create(long value) {
			return create(IntegerOptionDefinition.setLongValue(value));
		}

		@Override
		public int hashCode() {
			return getNumber() + 0x1000000;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			if (!(obj instanceof UnspecificOptionDefinition))
				return false;
			UnspecificOptionDefinition other = (UnspecificOptionDefinition) obj;
			return getNumber() == other.getNumber() && getName().equals(other.getName());
		}

	}

	private static class CustomOptionDefinition extends UnspecificOptionDefinition {

		private final CustomOptionNumberRegistry customOptionNumberRegistry;

		private CustomOptionDefinition(int optionNumber, CustomOptionNumberRegistry customOptionNumberRegistry) {
			super(optionNumber, customOptionNumberRegistry.toString(optionNumber));
			this.customOptionNumberRegistry = customOptionNumberRegistry;
		}

		@Override
		public OptionFormat getFormat() {
			return customOptionNumberRegistry.getFormatByNr(getNumber());
		}

		@Override
		public boolean isSingleValue() {
			return customOptionNumberRegistry.isSingleValue(getNumber());
		}

		@Override
		public void assertValue(byte[] value) {
			super.assertValue(value);
			if (getFormat() == OptionFormat.INTEGER) {
				long numberValue = IntegerOptionDefinition.getLongValue(value);
				customOptionNumberRegistry.assertValue(getNumber(), numberValue);
			}
		}

		@Override
		public int[] getValueLengths() {
			int[] lengths = customOptionNumberRegistry.getValueLengths(getNumber());
			if (lengths == null) {
				lengths = super.getValueLengths();
			}
			return lengths;
		}

		@Override
		public String getName() {
			return customOptionNumberRegistry.toString(getNumber());
		}

	}
}
