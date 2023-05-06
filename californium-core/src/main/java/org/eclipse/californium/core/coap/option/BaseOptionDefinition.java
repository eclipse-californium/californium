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
import org.eclipse.californium.core.coap.OptionNumberRegistry.OptionFormat;

/**
 * Basic option definition.
 * 
 * @since 3.8
 */
public abstract class BaseOptionDefinition implements OptionDefinition {

	/**
	 * Default option lengths.
	 * 
	 * The maximum value length is derived from the encoding, it's rather
	 * unrealistic to use more than 1035 (as for the Proxy-Uri option).
	 */
	private static final int[] LENGTHS = { 0, 65535 + 269 };

	/**
	 * Number of the option.
	 * 
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.4.6"
	 *      target= "_blank">RFC7252 5.4.6. Option Numbers</a>
	 */
	private final int number;
	/**
	 * Name of the option.
	 */
	private final String name;
	/**
	 * Value format of the option.
	 * 
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-3.2" target=
	 *      "_blank">RFC7252 3.2. Option Value Formats</a>
	 */
	private final OptionFormat format;
	/**
	 * Indicates, if the option is a single value option or may be used multiple
	 * times.
	 * 
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.4.5"
	 *      target= "_blank">RFC7252 5.4.5. Repeatable Options</a>
	 */
	private final boolean singleValue;
	/**
	 * Array with minimum and maximum value length. {@code lengths[0]} with the
	 * minimum length.
	 */
	private final int[] lengths;

	/**
	 * Create instance with provided parameter.
	 * 
	 * @param number option number
	 * @param name option name
	 * @param format option format
	 * @param singleValue {@code true}, if option supports a single value,
	 *            {@code false}, if option supports multiple values.
	 * @param lengths minimum and maximum value lengths. If only one length is
	 *            provided, this is used for both, minimum and maximum length.
	 */
	protected BaseOptionDefinition(int number, String name, OptionFormat format, boolean singleValue, int[] lengths) {
		if (number > 0xffff || number < 0) {
			throw new IllegalArgumentException(number + " invalid option number!");
		}
		this.number = number;
		this.name = name;
		this.format = format;
		this.singleValue = singleValue;
		if (lengths == null || lengths.length == 0) {
			// default lengths
			this.lengths = LENGTHS;
		} else if (lengths.length == 1) {
			// min and max length are the same
			this.lengths = new int[2];
			this.lengths[0] = lengths[0];
			this.lengths[1] = lengths[0];
		} else {
			this.lengths = Arrays.copyOf(lengths, 2);
		}
	}

	@Override
	public OptionFormat getFormat() {
		return format;
	}

	@Override
	public boolean isSingleValue() {
		return singleValue;
	}

	@Override
	public final int[] getValueLengths() {
		return lengths;
	}

	@Override
	public void assertValue(byte[] value) {
		int min = lengths[0];
		int max = lengths[1];
		int valueLength = value.length;
		if (getFormat() == OptionFormat.INTEGER) {
			// skip leading 0s
			for (byte b : value) {
				if (b == 0) {
					--valueLength;
				} else {
					break;
				}
			}
		}
		if (valueLength < min || valueLength > max) {
			if (min == max) {
				if (min == 0) {
					throw new IllegalArgumentException(
							"Option " + name + " value of " + valueLength + " bytes must be empty.");
				} else {
					throw new IllegalArgumentException(
							"Option " + name + " value of " + valueLength + " bytes must be " + min + " bytes.");
				}
			} else {
				throw new IllegalArgumentException("Option " + name + " value of " + valueLength
						+ " bytes must be in range of [" + min + "-" + max + "] bytes.");
			}
		}
	}

	@Override
	public String toString() {
		return name + "/" + format;
	}

	@Override
	public int getNumber() {
		return number;
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
		throw new IllegalArgumentException(getClass().getSimpleName() + " doesn't support string-values!");
	}

	@Override
	public Option create(long value) {
		throw new IllegalArgumentException(getClass().getSimpleName() + " doesn't support integer-values!");
	}

}
