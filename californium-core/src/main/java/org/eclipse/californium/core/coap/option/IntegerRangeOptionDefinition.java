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

/**
 * Option definition for integer options with specific value ranges.
 * 
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-3.2" target=
 *      "_blank">RFC7252 3.2. Option Value Formats</a>
 * 
 * @since 3.8
 */
public class IntegerRangeOptionDefinition extends IntegerOptionDefinition {

	/**
	 * Minimum value.
	 */
	private final long min;
	/**
	 * Maximum value.
	 */
	private final long max;

	/**
	 * Create option definition for an single value integer option.
	 * 
	 * @param number option number
	 * @param name option name
	 * @param min minimum value (inclusive)
	 * @param max maximum value (inclusive)
	 */
	public IntegerRangeOptionDefinition(int number, String name, long min, long max) {
		this(number, name, true, min, max);
	}

	/**
	 * Create option definition for an integer option.
	 * 
	 * @param number option number
	 * @param name option name
	 * @param singleValue {@code true}, if option supports a single value,
	 *            {@code false}, if option supports multiple values.
	 * @param min minimum value (inclusive)
	 * @param max maximum value (inclusive)
	 */
	public IntegerRangeOptionDefinition(int number, String name, boolean singleValue, long min, long max) {
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
