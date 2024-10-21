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

import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry.OptionFormat;

/**
 * Option representing an opaque value.
 * 
 * @since 4.0
 */
public class OpaqueOption extends Option {

	/**
	 * Create opaque option.
	 * 
	 * @param definition opaque option definition
	 * @param value opaque value
	 */
	public OpaqueOption(Definition definition, byte[] value) {
		super(definition, value);
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
		public OpaqueOption create(byte[] value) {
			if (value == null) {
				throw new NullPointerException("Option " + getName() + " value must not be null.");
			}
			return new OpaqueOption(this, value);
		}

	}

}
