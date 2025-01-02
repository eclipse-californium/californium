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

import java.util.Arrays;

import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionNumberRegistry.OptionFormat;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * Option representing an opaque value.
 * 
 * @since 4.0
 */
public class OpaqueOption extends Option {

	/** The value as byte array. */
	private final byte[] value; // not null

	/**
	 * Create opaque option.
	 * 
	 * @param definition opaque option definition
	 * @param value opaque value
	 * @throws NullPointerException if definition or value is {@code null}.
	 * @throws IllegalArgumentException if value doesn't match the definition.
	 */
	public OpaqueOption(Definition definition, byte[] value) {
		super(definition);
		if (value == null) {
			throw new NullPointerException("Option " + definition.getName() + " value must not be null.");
		}
		this.value = value;
		definition.assertValueLength(value.length);
	}

	/**
	 * Gets the length of the option value.
	 *
	 * @return the length
	 * @throws IllegalStateException if value was not set before (since 3.0).
	 */
	@Override
	public int getLength() {
		return value.length;
	}

	public byte[] getValue() {
		return value;
	}

	@Override
	public void writeTo(DatagramWriter writer) {
		writer.writeBytes(value);
	}

	/**
	 * Renders the option value as string.
	 * <p>
	 * Takes into account of option type, thus giving more accurate
	 * representation of an option {@code value}. Formats {@code value} as
	 * integer or string if so defined in {@link OptionNumberRegistry}. In case
	 * of option {@code value} is just an opaque byte array, formats this value
	 * as hex string.
	 *
	 * @return the option value as string
	 */
	public String toValueString() {
		return "0x" + StringUtil.byteArray2Hex(value);
	}

	@Override
	public boolean equals(Object o) {
		if (o == this) {
			return true;
		} else if (!(o instanceof OpaqueOption)) {
			return false;
		}
		OpaqueOption op = (OpaqueOption) o;
		return Arrays.equals(value, op.value) && getDefinition().equals(op.getDefinition());
	}

	@Override
	public int hashCode() {
		return 31 * super.hashCode() + Arrays.hashCode(value);
	}

	/**
	 * Option definition for opaque options.
	 * 
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-3.2" target=
	 *      "_blank">RFC7252 3.2. Option Value Formats</a>
	 * 
	 * @since 4.0 (moved from OpaqueOptionDefinition)
	 */
	public static class Definition extends BaseOptionDefinition {

		/**
		 * Creates option definition for an single value opaque option.
		 * 
		 * @param number option number
		 * @param name option name
		 */
		public Definition(int number, String name) {
			this(number, name, true, null);
		}

		/**
		 * Creates option definition for an opaque option.
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
		 * Creates option definition for an opaque option with provide length
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
			return OptionFormat.OPAQUE;
		}

		@Override
		public OpaqueOption create(DatagramReader reader, int length) {
			if (reader == null) {
				throw new NullPointerException("Option " + getName() + " reader must not be null.");
			}
			return new OpaqueOption(this, reader.readBytes(length));
		}

		/**
		 * Creates opaque option from byte array.
		 * 
		 * @param value the byte array
		 * @return created opaque option
		 * @throws NullPointerException if value is {@code null}.
		 * @throws IllegalArgumentException if value doesn't match the
		 *             definition.
		 */
		public OpaqueOption create(byte[] value) {
			if (value == null) {
				throw new NullPointerException("Option " + getName() + " value must not be null.");
			}
			return new OpaqueOption(this, value);
		}

	}

}
