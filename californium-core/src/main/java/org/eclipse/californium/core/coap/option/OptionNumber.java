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

/**
 * Option number.
 * 
 * @since 4.0
 */
public interface OptionNumber {

	/**
	 * Returns the option number.
	 * 
	 * @return the option number
	 * 
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.4.6"
	 *      target= "_blank">RFC7252 5.4.6. Option Numbers</a>
	 */
	int getNumber();
	/**
	 * Checks whether an option has a single value.
	 * 
	 * @return {@code true}, if the option has a single value, {@code false}, if
	 *         the option is repeatable
	 * 
	 * @see <a href="https://www.rfc-editor.org/rfc/rfc7252#section-5.4.5"
	 *      target= "_blank">RFC7252 5.4.5. Repeatable Options</a>
	 */
	boolean isSingleValue();

}
