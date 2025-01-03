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

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MessageFormatException;
import org.eclipse.californium.core.coap.option.IntegerOption;
import org.eclipse.californium.elements.util.DatagramReader;

/**
 * CoAP custom option for response code of combined read.
 * 
 * @since 3.12
 */
public class ResponseCodeOption extends IntegerOption {

	private final ResponseCode code;

	/**
	 * Create response code option for combined read.
	 * 
	 * @param code response code
	 * @throws IllegalArgumentException if code is no valid response code.
	 * @see ResponseCode#valueOf(int)
	 */
	public ResponseCodeOption(Definition definition, int code) {
		super(definition, code);
		try {
			this.code = ResponseCode.valueOf(code);
		} catch (MessageFormatException ex) {
			throw new IllegalArgumentException(getDefinition().getName() + " " + ex.getMessage());
		}
	}

	/**
	 * Create response code option for combined read.
	 * 
	 * @param code response code
	 */
	public ResponseCodeOption(Definition definition, ResponseCode code) {
		super(definition, code != null ? code.value : 0);
		if (code == null) {
			throw new NullPointerException("Option " + getDefinition().getName() + " code must not be null.");
		}
		this.code = code;
	}

	@Override
	public Definition getDefinition() {
		return (Definition) super.getDefinition();
	}

	@Override
	public String toValueString() {
		return code.text + "/" + code.name();
	}

	public ResponseCode getResponseCode() {
		return code;
	}

	public static class Definition extends IntegerOption.Definition {

		public Definition(int number, String name) {
			super(number, name, true, 1, 1);
		}

		@Override
		public ResponseCodeOption create(DatagramReader reader, int length) {
			if (reader == null) {
				throw new NullPointerException("Option " + getName() + " reader must not be null.");
			}
			if (length != 1) {
				throw new IllegalArgumentException("Option " + getName() + " value must be 1 byte.");
			}
			return new ResponseCodeOption(this, reader.readNextByte() & 0xFF);
		}

		@Override
		public ResponseCodeOption create(long value) {
			return new ResponseCodeOption(this, (int) value);
		}

		public ResponseCodeOption create(ResponseCode code) {
			if (code == null) {
				throw new NullPointerException("Option " + getName() + " code must not be null.");
			}
			return new ResponseCodeOption(this, code);
		}
	}
}
