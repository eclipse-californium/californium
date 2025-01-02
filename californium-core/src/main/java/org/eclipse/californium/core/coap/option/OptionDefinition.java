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

/**
 * Option definition.
 * 
 * Generic definition for CoAP options.
 * 
 * @since 3.8
 */
public interface OptionDefinition extends OptionNumber {

	/**
	 * Get name of option.
	 * 
	 * @return name of the option
	 */
	String getName();

	/**
	 * Returns a string representation of the custom option definition.
	 * 
	 * @return a string describing the custom option definition.
	 */
	String toString();

	/**
	 * Creates option from reader.
	 * 
	 * @param reader datagram reader to read the option value
	 * @param length length of the option value
	 * @return created option
	 * @throws NullPointerException if reader is {@code null}.
	 * @throws IllegalArgumentException if value doesn't match the definition.
	 * @since 4.0
	 */
	Option create(DatagramReader reader, int length);

	/**
	 * Get option format.
	 * 
	 * @return option format
	 * 
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-3.2" target=
	 *      "_blank">RFC7252 3.2. Option Value Formats</a>
	 */
	OptionFormat getFormat();

	/**
	 * Asserts the value length matches the options's definition.
	 * 
	 * @param length length to check
	 * @throws IllegalArgumentException if length doesn't match the definition
	 * @since 4.0
	 */
	void assertValueLength(int length);

}
