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
package org.eclipse.californium.cloud.s3.option;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MessageFormatException;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.option.IntegerOptionDefinition;

/**
 * CoAP custom option for response code of combined forwarded request.
 * 
 * @since 3.13
 */
public class ForwardResponseOption extends Option {

	/**
	 * Number of custom option.
	 */
	public static final int COAP_OPTION_FORWARD_RESPONSE = 0xfdf8;

	public static final IntegerOptionDefinition DEFINITION = new IntegerOptionDefinition(COAP_OPTION_FORWARD_RESPONSE,
			"Forward_ResponseCode", true, 1, 1) {

		@Override
		public Option create(byte[] value) {
			return new ForwardResponseOption(value);
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
	public ForwardResponseOption(int code) {
		super(DEFINITION, code);
	}

	/**
	 * Create response code option for combined read.
	 * 
	 * @param code response code
	 */
	public ForwardResponseOption(ResponseCode code) {
		this(code.value);
	}

	public ForwardResponseOption(byte[] value) {
		super(DEFINITION, value);
	}

	@Override
	public String toValueString() {
		return CoAP.toDisplayString(getIntegerValue());
	}
}
