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

package org.eclipse.californium.core.coap.option;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.OptionNumberRegistry.OptionFormat;
import org.eclipse.californium.elements.util.DatagramReader;

/**
 * Option representing a string value.
 * 
 * @since 4.0
 */
public class StringOption extends OpaqueOption {

	/**
	 * String option value.
	 */
	private final String value;

	/**
	 * Creates string option.
	 * 
	 * @param definition string option definition
	 * @param value string value as byte array
	 * @throws NullPointerException if definition or value is {@code null}.
	 * @throws IllegalArgumentException if value doesn't match the definition.
	 */
	public StringOption(Definition definition, byte[] value) {
		super(definition, value);
		this.value = Definition.getStringValue(value);
	}

	/**
	 * Creates string option.
	 * 
	 * @param definition string option definition
	 * @param value string value
	 * @throws NullPointerException if definition or value is {@code null}.
	 * @throws IllegalArgumentException if value doesn't match the definition.
	 */
	public StringOption(Definition definition, String value) {
		super(definition, Definition.setStringValue(value));
		this.value = value;
	}

	/**
	 * Gets value as string.
	 * 
	 * @return string value
	 */
	public String getStringValue() {
		return value;
	}

	@Override
	public String toValueString() {
		return "\"" + this.getStringValue() + "\"";
	}

	/**
	 * Option definition for string options.
	 * 
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-3.2" target=
	 *      "_blank">RFC7252 3.2. Option Value Formats</a>
	 * 
	 * @since 4.0 (moved from StringOptionDefinition)
	 */
	public static class Definition extends OpaqueOption.Definition {

		/**
		 * Creates option definition for an single value string option.
		 * 
		 * @param number option number
		 * @param name option name
		 */
		public Definition(int number, String name) {
			this(number, name, true, null);
		}

		/**
		 * Creates option definition for an string option.
		 * 
		 * @param number option number
		 * @param name option name
		 * @param singleValue {@code true}, if option supports a single value,
		 *            {@code false}, if option supports multiple values.
		 */
		public Definition(int number, String name, boolean singleValue) {
			this(number, name, singleValue, null);
		}

		/**
		 * Creates option definition for an string option with provide length
		 * range.
		 * 
		 * @param number option number
		 * @param name option name
		 * @param singleValue {@code true}, if option supports a single value,
		 *            {@code false}, if option supports multiple values.
		 * @param lengths minimum and maximum value lengths. If only one length
		 *            is provided, this is used for both, minimum and maximum
		 *            length.
		 */
		public Definition(int number, String name, boolean singleValue, int... lengths) {
			super(number, name, singleValue, lengths);
		}

		@Override
		public OptionFormat getFormat() {
			return OptionFormat.STRING;
		}

		@Override
		public StringOption create(DatagramReader reader, int length) {
			if (reader == null) {
				throw new NullPointerException("Option " + getName() + " reader must not be null.");
			}
			return new StringOption(this, reader.readBytes(length));
		}

		/**
		 * Creates string option from byte array.
		 * 
		 * @param value the byte array
		 * @return created string option
		 * @throws NullPointerException if value is {@code null}.
		 * @throws IllegalArgumentException if value doesn't match the
		 *             definition.
		 */
		@Override
		public StringOption create(byte[] value) {
			if (value == null) {
				throw new NullPointerException("Option " + getName() + " value must not be null.");
			}
			return new StringOption(this, value);
		}

		/**
		 * Creates string option from string value.
		 * 
		 * @param value the string value
		 * @return created string option
		 * @throws NullPointerException if value is {@code null}.
		 * @throws IllegalArgumentException if value doesn't match the
		 *             definition.
		 */
		public StringOption create(String value) {
			if (value == null) {
				throw new NullPointerException("Option " + getName() + " value must not be null.");
			}
			return new StringOption(this, value);
		}

		/**
		 * Gets the option value as string.
		 * 
		 * @param value value as array in UTF-8.
		 * @return the string value, or {@code null}, when value is
		 *         {@code null}.
		 */
		public static String getStringValue(byte[] value) {
			return value == null ? null : new String(value, CoAP.UTF8_CHARSET);
		}

		/**
		 * Sets the option value from a string.
		 *
		 * @param value the new option value as string
		 * @return the string value array in UTF-8, or {@code null}, when value
		 *         is {@code null}.
		 */
		public static byte[] setStringValue(String value) {
			return value == null ? null : value.getBytes(CoAP.UTF8_CHARSET);
		}

	}
}
