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

import org.eclipse.californium.core.coap.Message;

/**
 * Registry of option definitions.
 * 
 * @since 3.8
 */
public interface OptionRegistry extends Iterable<OptionRegistry.Entry> {

	/**
	 * Returns the option definition based on the option number and message
	 * code.
	 * 
	 * RFC7252, RFC7641, RFC7959, RFC7967 and RFC8613 specifies options based on
	 * the option number only, RFC 8323 introduces message specific options.
	 * 
	 * @param code the message code. Maybe {@code 0} for common RFC7252
	 *            messages.
	 * @param optionNumber The option number
	 * @return The option definition corresponding to the option number,
	 *         {@code null}, if not available.
	 * @throws IllegalArgumentException if a critical option is unknown.
	 * @see Message#getRawCode()
	 * @see OptionDefinition#getNumber()
	 * @see #getDefinitionByNumber(int)
	 */
	OptionDefinition getDefinitionByNumber(int code, int optionNumber);

	/**
	 * Returns the option definition based on the option number.
	 * 
	 * @param optionNumber The option number
	 * @return The option definition corresponding to the option number,
	 *         {@code null}, if not available.
	 * @see #getDefinitionByNumber(int, int)
	 */
	OptionDefinition getDefinitionByNumber(int optionNumber);

	/**
	 * Returns the option definition based on the option name.
	 * 
	 * @param name the option name
	 * @return The option definition corresponding to the option number,
	 *         {@code null}, if not available.
	 * @see #getDefinitionByNumber(int, int)
	 */
	OptionDefinition getDefinitionByName(String name);

	/**
	 * Checks, if an option definition is contained.
	 * 
	 * @param definition the option definition to check
	 * @return {@code true}, if available, {@code false}, otherwise.
	 */
	boolean contains(OptionDefinition definition);

	/**
	 * Option definition entry.
	 */
	interface Entry {

		/**
		 * Get the option definition key.
		 * 
		 * @return the option definition key
		 */
		int getKey();;

		/**
		 * Get the option definition.
		 * 
		 * @return the option definition
		 */
		OptionDefinition getOptioneDefinition();
	}

}
