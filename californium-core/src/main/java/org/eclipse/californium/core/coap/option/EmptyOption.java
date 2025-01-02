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
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;

/**
 * Empty options.
 * 
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-3.2" target=
 *      "_blank">RFC7252 3.2. Option Value Formats</a>
 * 
 * @since 4.0
 */
public class EmptyOption extends Option {

	/**
	 * Creates a new empty option with the specified definition.
	 * 
	 * @param definition the empty option definition
	 * @throws NullPointerException if definition is {@code null}.
	 */
	private EmptyOption(Definition definition) {
		super(definition);
	}

	@Override
	public int getLength() {
		return 0;
	}

	@Override
	public void writeTo(DatagramWriter writer) {
		// empty by intention
	}

	@Override
	public String toValueString() {
		return "";
	}

	/**
	 * Option definition for empty options.
	 * 
	 * @since 4.0
	 */
	public static class Definition extends BaseOptionDefinition {

		/**
		 * Lengths for empty option.
		 */
		private static final int[] LENGTHS = { 0, 0 };

		/**
		 * Singleton representing specific empty option.
		 */
		private final EmptyOption option;

		/**
		 * Create option definition for an empty option.
		 * 
		 * @param number option number
		 * @param name option name
		 */
		public Definition(int number, String name) {
			super(number, name, true, LENGTHS);
			option = new EmptyOption(this);
		}

		@Override
		public OptionFormat getFormat() {
			return OptionFormat.EMPTY;
		}

		@Override
		public EmptyOption create(DatagramReader reader, int length) {
			if (reader == null) {
				throw new NullPointerException("Option " + getName() + " reader must not be null.");
			}
			if (length != 0) {
				throw new IllegalArgumentException("Option " + getName() + " value must be empty.");
			}
			return option;
		}

		/**
		 * Creates {@link EmptyOption} of this definition.
		 * 
		 * @return created {@link EmptyOption}
		 */
		public EmptyOption create() {
			return option;
		}
	}

}
