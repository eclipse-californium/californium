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

import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry.OptionFormat;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;

/**
 * Option representing a integer value.
 * 
 * @since 4.0
 */
public class IntegerOption extends Option {

	/**
	 * Integer value.
	 */
	private final long value;
	/**
	 * Length of encoded value.
	 */
	private final int length;

	/**
	 * Creates integer option.
	 * 
	 * @param definition integer option definition
	 * @param value value as long
	 * @throws NullPointerException if definition is {@code null}.
	 * @throws IllegalArgumentException if value doesn't match the definition.
	 */
	public IntegerOption(Definition definition, long value) {
		super(definition);
		this.value = value;
		this.length = Definition.getValueLength(value);
		definition.assertValue(value, length);
	}

	@Override
	public int getLength() {
		return length;
	}

	@Override
	public void writeTo(DatagramWriter writer) {
		writer.writeLong(value, getLength() * Byte.SIZE);
	}

	/**
	 * Gets value as integer.
	 * 
	 * @return integer value
	 */
	public int getIntegerValue() {
		return (int) value;
	}

	/**
	 * Gets value as long.
	 * 
	 * @return long value
	 */
	public long getLongValue() {
		return value;
	}

	@Override
	public String toValueString() {
		int iValue = getIntegerValue();
		if (StandardOptionRegistry.ACCEPT.equals(getDefinition())
				|| StandardOptionRegistry.CONTENT_FORMAT.equals(getDefinition())) {
			return "\"" + MediaTypeRegistry.toString(iValue) + "\"";
		}
		return Long.toString(getLongValue());
	}

	@Override
	public boolean equals(Object o) {
		if (o == this) {
			return true;
		} else if (!(o instanceof IntegerOption)) {
			return false;
		}
		IntegerOption op = (IntegerOption) o;
		return value == op.value && getDefinition().equals(op.getDefinition());
	}

	@Override
	public int hashCode() {
		return 31 * super.hashCode() + Long.hashCode(value);
	}

	/**
	 * Option definition for integer options.
	 * 
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-3.2" target=
	 *      "_blank">RFC7252 3.2. Option Value Formats</a>
	 * 
	 * @since 4.0 (moved from IntegerOptionDefinition)
	 */
	public static class Definition extends BaseOptionDefinition {

		private static final int[] LENGTHS = { 0, 8 };

		/**
		 * Creates option definition for an single value integer option.
		 * 
		 * @param number option number
		 * @param name option name
		 */
		public Definition(int number, String name) {
			this(number, name, true, LENGTHS);
		}

		/**
		 * Creates option definition for an integer option.
		 * 
		 * @param number option number
		 * @param name option name
		 * @param singleValue {@code true}, if option supports a single value,
		 *            {@code false}, if option supports multiple values.
		 */
		public Definition(int number, String name, boolean singleValue) {
			this(number, name, singleValue, LENGTHS);
		}

		/**
		 * Creates option definition for an integer option with provide length
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
			super(number, name, singleValue, lengths == null ? LENGTHS : lengths);
		}

		@Override
		public OptionFormat getFormat() {
			return OptionFormat.INTEGER;
		}

		@Override
		public IntegerOption create(DatagramReader reader, int length) {
			if (reader == null) {
				throw new NullPointerException("Option " + getName() + " reader must not be null.");
			}
			return new IntegerOption(this, getLongValue(reader, length));
		}

		/**
		 * Creates integer option from integer value.
		 * 
		 * @param value the integer value
		 * @return created integer option
		 * @throws IllegalArgumentException if value doesn't match the
		 *             definition.
		 */
		public IntegerOption create(long value) {
			return new IntegerOption(this, value);
		}

		/**
		 * Asserts the value matches the options's definition.
		 * 
		 * @param value value to check
		 * @param length value length to check
		 * @throws IllegalArgumentException if value doesn't match the
		 *             definition
		 * @since 4.0
		 */
		public void assertValue(long value, int length) {
			assertValueLength(length);
		}

		/**
		 * Gets the option value as long.
		 * <p>
		 * Handles cases where {@code value} contains leading 0's or a case
		 * where {@code value} is empty which returns 0.
		 *
		 * @param reader datagram reader to read option
		 * @param length length of option value
		 * @return the long value
		 * @throws NullPointerException if reader is {@code null}.
		 * @throws IllegalArgumentException if length is {@code > 8}.
		 */
		public static long getLongValue(DatagramReader reader, int length) {
			if (reader == null) {
				throw new NullPointerException("Reader must not be null.");
			}
			if (length > 8) {
				throw new IllegalArgumentException("Long's length must not be more than 8!");
			}
			long ret = 0;
			while (length-- > 0) {
				ret <<= 8;
				ret += (reader.readNextByte() & 0xFF);
			}
			return ret;
		}

		/**
		 * Gets the option value as int.
		 * <p>
		 * Handles cases where {@code value} contains leading 0's or a case
		 * where {@code value} is empty which returns 0.
		 *
		 * @param reader datagram reader to read option
		 * @param length length of option value
		 * @return the int value
		 * @throws NullPointerException if reader is {@code null}.
		 * @throws IllegalArgumentException if length is {@code > 4}.
		 * @since 4.0
		 */
		public static int getIntegerValue(DatagramReader reader, int length) {
			if (reader == null) {
				throw new NullPointerException("Reader must not be null.");
			}
			if (length > 4) {
				throw new IllegalArgumentException("Integer's length must not be more than 4!");
			}
			int ret = 0;
			while (length-- > 0) {
				ret <<= 8;
				ret += (reader.readNextByte() & 0xFF);
			}
			return ret;
		}

		/**
		 * Gets the option values encoding length.
		 * 
		 * @param value option value.
		 * @return encoding length
		 */
		public static int getValueLength(long value) {
			return (Long.SIZE - Long.numberOfLeadingZeros(value) + 7) / Byte.SIZE;
		}

	}

	/**
	 * Option definition for integer options with specific value ranges.
	 * 
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-3.2" target=
	 *      "_blank">RFC7252 3.2. Option Value Formats</a>
	 * 
	 * @since 3.8
	 */
	public static class RangeDefinition extends Definition {

		/**
		 * Minimum value.
		 */
		private final long min;
		/**
		 * Maximum value.
		 */
		private final long max;

		/**
		 * Creates option definition for an single value integer option.
		 * 
		 * @param number option number
		 * @param name option name
		 * @param min minimum value (inclusive)
		 * @param max maximum value (inclusive)
		 */
		public RangeDefinition(int number, String name, long min, long max) {
			this(number, name, true, min, max);
		}

		/**
		 * Creates option definition for an integer option.
		 * 
		 * @param number option number
		 * @param name option name
		 * @param singleValue {@code true}, if option supports a single value,
		 *            {@code false}, if option supports multiple values.
		 * @param min minimum value (inclusive)
		 * @param max maximum value (inclusive)
		 */
		public RangeDefinition(int number, String name, boolean singleValue, long min, long max) {
			super(number, name, singleValue, getValueLength(min), getValueLength(max));
			if (min <= max) {
				this.min = min;
				this.max = max;
			} else {
				this.min = max;
				this.max = min;
			}
		}

		@Override
		public void assertValue(long value, int length) {
			super.assertValue(value, length);
			if (value < min) {
				throw new IllegalArgumentException(
						"Option " + getName() + " value " + value + " must be at least " + min + ".");
			} else if (value > max) {
				throw new IllegalArgumentException(
						"Option " + getName() + " value " + value + "  must be at most " + max + ".");
			}
		}

	}
}
