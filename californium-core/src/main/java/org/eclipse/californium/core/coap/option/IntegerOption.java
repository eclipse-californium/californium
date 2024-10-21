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
	 * Creates integer option.
	 * 
	 * @param definition integer option definition
	 * @param value value as byte array
	 */
	public IntegerOption(Definition definition, byte[] value) {
		super(definition, value);
		this.value = Definition.getLongValue(value);
	}

	/**
	 * Creates integer option.
	 * 
	 * @param definition integer option definition
	 * @param value value as long
	 */
	public IntegerOption(Definition definition, long value) {
		super(definition, Definition.setLongValue(value));
		this.value = value;
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
			super(number, name, singleValue, lengths);
		}

		@Override
		public OptionFormat getFormat() {
			return OptionFormat.INTEGER;
		}

		@Override
		public IntegerOption create(byte[] value) {
			if (value == null) {
				throw new NullPointerException("Option " + getName() + " value must not be null.");
			}
			return new IntegerOption(this, value);
		}

		/**
		 * Creates integer option from integer value
		 * 
		 * @param value the integer value
		 * @return created integer option
		 */
		public IntegerOption create(long value) {
			return new IntegerOption(this, value);
		}

		/**
		 * Gets the option value as long.
		 * <p>
		 * Handles cases where {@code value} contains leading 0's or a case
		 * where {@code value} is empty which returns 0.
		 *
		 * @param value value as array
		 * @return the long value
		 */
		public static long getLongValue(byte[] value) {
			long ret = 0;
			for (int i = 0; i < value.length; i++) {
				ret += (long) (value[value.length - i - 1] & 0xFF) << (i * 8);
			}
			return ret;
		}

		/**
		 * Sets the option value from a long.
		 *
		 * @param val the new option value as long
		 * @return the value as byte array
		 */
		public static byte[] setLongValue(long val) {
			int length = (Long.SIZE - Long.numberOfLeadingZeros(val) + 7) / Byte.SIZE;
			byte[] value = new byte[length];
			for (int i = 0; i < length; i++) {
				value[length - i - 1] = (byte) (val >> i * 8);
			}
			return value;
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
			super(number, name, singleValue, null);
			if (min <= max) {
				this.min = min;
				this.max = max;
			} else {
				this.min = max;
				this.max = min;
			}
		}

		@Override
		public void assertValue(byte[] value) {
			long number = getLongValue(value);
			if (number < min) {
				throw new IllegalArgumentException(
						"Option " + getName() + " value " + number + " must be at least " + min + ".");
			} else if (number > max) {
				throw new IllegalArgumentException(
						"Option " + getName() + " value " + number + "  must be at most " + max + ".");
			}
		}

	}

}
