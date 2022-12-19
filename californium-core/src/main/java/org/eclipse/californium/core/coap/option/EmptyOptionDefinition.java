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
import org.eclipse.californium.elements.util.Bytes;

/**
 * Option definition for empty options.
 * 
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-3.2" target=
 *      "_blank">RFC7252 3.2. Option Value Formats</a>
 * 
 * @since 3.8
 */
public class EmptyOptionDefinition extends BaseOptionDefinition {

	private static final int[] LENGTHS = { 0, 0 };

	/**
	 * Create option definition for an empty option.
	 * 
	 * @param number option number
	 * @param name option name
	 */
	public EmptyOptionDefinition(int number, String name) {
		super(number, name, OptionFormat.EMPTY, true, LENGTHS);
	}

	@Override
	public Option create(byte[] value) {
		if (value == null) {
			throw new NullPointerException("Option " + getName() + " value must not be null.");
		}
		if (value.length > 0) {
			throw new IllegalArgumentException("Option " + getName() + " value must be empty.");
		}
		return new Option(this, Bytes.EMPTY);
	}

}
