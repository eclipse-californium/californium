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
import org.eclipse.californium.core.coap.option.IntegerOption;

/**
 * CoAP custom option for response code of combined read.
 * 
 * @since 3.12
 */
public class ResponseCodeOption extends IntegerOption {

	/**
	 * Create response code option for combined read.
	 * 
	 * @param code response code
	 */
	public ResponseCodeOption(Definition definition, long code) {
		super(definition, code);
	}

	/**
	 * Create response code option for combined read.
	 * 
	 * @param code response code
	 */
	public ResponseCodeOption(Definition definition, ResponseCode code) {
		this(definition, code.value);
	}

	public ResponseCodeOption(Definition definition, byte[] value) {
		super(definition, value);
	}

	@Override
	public Definition getDefinition() {
		return (Definition) super.getDefinition();
	}

	@Override
	public String toValueString() {
		return CoAP.toDisplayString(getIntegerValue());
	}

	public static class Definition extends IntegerOption.Definition {

		public Definition(int number, String name) {
			super(number, name, true, 1, 1);
		}

		@Override
		public ResponseCodeOption create(byte[] value) {
			return new ResponseCodeOption(this, value);
		}

		@Override
		public ResponseCodeOption create(long value) {
			return new ResponseCodeOption(this, value);
		}

		public ResponseCodeOption create(ResponseCode code) {
			return new ResponseCodeOption(this, code);
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
	}
}
