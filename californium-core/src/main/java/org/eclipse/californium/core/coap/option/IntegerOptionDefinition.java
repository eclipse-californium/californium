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

import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry.OptionFormat;

/**
 * Option definition for integer options.
 * 
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-3.2" target=
 *      "_blank">RFC7252 3.2. Option Value Formats</a>
 * 
 * @since 3.8
 */
public class IntegerOptionDefinition extends BaseOptionDefinition {

	private static final int[] LENGTHS = { 0, 8 };

	/**
	 * Create option definition for an single value integer option.
	 * 
	 * @param number option number
	 * @param name option name
	 */
	public IntegerOptionDefinition(int number, String name) {
		this(number, name, true, LENGTHS);
	}

	/**
	 * Create option definition for an integer option.
	 * 
	 * @param number option number
	 * @param name option name
	 * @param singleValue {@code true}, if option supports a single value,
	 *            {@code false}, if option supports multiple values.
	 */
	public IntegerOptionDefinition(int number, String name, boolean singleValue) {
		this(number, name, singleValue, LENGTHS);
	}

	/**
	 * Create option definition for an integer option with provide length range.
	 * 
	 * @param number option number
	 * @param name option name
	 * @param singleValue {@code true}, if option supports a single value,
	 *            {@code false}, if option supports multiple values.
	 * @param lengths minimum and maximum value lengths. If only one length is
	 *            provided, this is used for both, minimum and maximum length.
	 */
	public IntegerOptionDefinition(int number, String name, boolean singleValue, int... lengths) {
		super(number, name, OptionFormat.INTEGER, singleValue, lengths);
	}

	@Override
	public Option create(long value) {
		return new Option(this, value);
	}

	/**
	 * Gets the option value as integer.
	 * 
	 * Handles cases where {@code value} contains leading 0's or a case where
	 * {@code value} is empty which returns 0.
	 * 
	 * @param value value as array
	 * @return the integer value
	 */
	public static int getIntegerValue(byte[] value) {
		int ret = 0;
		for (int i = 0; i < value.length; i++) {
			ret += (value[value.length - i - 1] & 0xFF) << (i * 8);
		}
		return ret;
	}

	/**
	 * Gets the option value as long.
	 * 
	 * Handles cases where {@code value} contains leading 0's or a case where
	 * {@code value} is empty which returns 0.
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
	 * Sets the option value from an integer.
	 *
	 * @param val the new option value as integer
	 * @return the value as byte array
	 */
	public static byte[] setIntegerValue(int val) {
		int length = (Integer.SIZE - Integer.numberOfLeadingZeros(val) + 7) / Byte.SIZE;
		byte[] value = new byte[length];
		for (int i = 0; i < length; i++) {
			value[length - i - 1] = (byte) (val >> i * 8);
		}
		return value;
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
