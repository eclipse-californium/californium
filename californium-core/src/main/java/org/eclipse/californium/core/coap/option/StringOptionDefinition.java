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

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry.OptionFormat;

/**
 * Option definition for string options.
 * 
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-3.2" target=
 *      "_blank">RFC7252 3.2. Option Value Formats</a>
 * 
 * @since 3.8
 */
public class StringOptionDefinition extends BaseOptionDefinition {

	/**
	 * Create option definition for an single value string option.
	 * 
	 * @param number option number
	 * @param name option name
	 */
	public StringOptionDefinition(int number, String name) {
		this(number, name, true, null);
	}

	/**
	 * Create option definition for an string option.
	 * 
	 * @param number option number
	 * @param name option name
	 * @param singleValue {@code true}, if option supports a single value,
	 *            {@code false}, if option supports multiple values.
	 */
	public StringOptionDefinition(int number, String name, boolean singleValue) {
		this(number, name, singleValue, null);
	}

	/**
	 * Create option definition for an string option with provide length range.
	 * 
	 * @param number option number
	 * @param name option name
	 * @param singleValue {@code true}, if option supports a single value,
	 *            {@code false}, if option supports multiple values.
	 * @param lengths minimum and maximum value lengths. If only one length is
	 *            provided, this is used for both, minimum and maximum length.
	 */
	public StringOptionDefinition(int number, String name, boolean singleValue, int... lengths) {
		super(number, name, OptionFormat.STRING, singleValue, lengths);
	}

	@Override
	public Option create(String value) {
		return new Option(this, value);
	}

	/**
	 * Gets the option value as string.
	 * 
	 * @param value value as array in UTF-8.
	 * @return the string value
	 */
	public static String getStringValue(byte[] value) {
		return new String(value, CoAP.UTF8_CHARSET);
	}

	/**
	 * Sets the option value from a string.
	 *
	 * @param value the new option value as string
	 * @return the string value array in UTF-8
	 */
	public static byte[] setStringValue(String value) {
		return value.getBytes(CoAP.UTF8_CHARSET);
	}

}
