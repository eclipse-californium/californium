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
package org.eclipse.californium.cloud.option;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MessageFormatException;
import org.eclipse.californium.core.coap.option.IntegerOptionDefinition;
import org.eclipse.californium.core.coap.Option;

/**
 * CoAP custom option for response code of combined read.
 * 
 * @since 3.12
 */
public class ReadResponseOption extends Option {

	/**
	 * Number of custom option.
	 */
	public static final int COAP_OPTION_READ_RESPONSE = 0xfdf0;

	public static final IntegerOptionDefinition DEFINITION = new IntegerOptionDefinition(COAP_OPTION_READ_RESPONSE,
			"Read_ResponseCode", true, 1, 1) {

		@Override
		public Option create(byte[] value) {
			return new ReadResponseOption(value);
		}

		@Override
		public void assertValue(byte[] value) {
			int code = value[0] & 0xff;
			try {
				ResponseCode.valueOf(code);
			} catch (MessageFormatException ex) {
				throw new IllegalArgumentException(ex.getMessage() + " Value " + value);
			}
		}

	};

	/**
	 * Create response code option for combined read.
	 * 
	 * @param code response code
	 */
	public ReadResponseOption(int code) {
		super(DEFINITION, code);
	}

	/**
	 * Create response code option for combined read.
	 * 
	 * @param code response code
	 */
	public ReadResponseOption(ResponseCode code) {
		this(code.value);
	}

	public ReadResponseOption(byte[] value) {
		super(DEFINITION, value);
	}

	@Override
	public String toValueString() {
		return CoAP.toDisplayString(getIntegerValue());
	}
}
