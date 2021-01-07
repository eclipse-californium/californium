/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import java.util.Arrays;

/**
 * A utility to test malicious options.
 * 
 * @since 3.0
 */
public final class TestOption {

	/**
	 * Create option with unchecked value.
	 * 
	 * @param number option number
	 * @param length value length
	 * @return created option
	 */
	public static Option newOption(int number, int length) {
		byte[] value = new byte[length];
		Arrays.fill(value, (byte) 'p');
		return new Option(number).setValueUnchecked(value);
	}

}
