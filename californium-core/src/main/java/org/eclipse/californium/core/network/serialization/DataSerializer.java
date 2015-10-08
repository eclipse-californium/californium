/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 ******************************************************************************/
package org.eclipse.californium.core.network.serialization;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.CODE_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.MESSAGE_ID_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.OPTION_DELTA_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.OPTION_LENGTH_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.PAYLOAD_MARKER;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.TOKEN_LENGTH_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.TYPE_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.VERSION;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.VERSION_BITS;

import java.util.List;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;


/**
 * The DataSerialized serializes outgoing messages to byte arrays.
 */
// TODO: Should we call this "Encoder/Decoder"?
public class DataSerializer {
	
	private DatagramWriter writer;
	
	public byte[] serializeRequest(Request request) {
		writer = new DatagramWriter();
		Code code = request.getCode();
		serializeMessage(request, code == null ? 0 : code.value);
		return writer.toByteArray();
	}
	
	public byte[] serializeResponse(Response response) {
		writer = new DatagramWriter();
		serializeMessage(response, response.getCode().value);
		return writer.toByteArray();
	}
	
	public byte[] serializeEmptyMessage(Message message) {
		writer = new DatagramWriter();
		serializeMessage(message, 0);
		return writer.toByteArray();
	}
	
	private void serializeMessage(Message message, int code) {
		if (message.getToken() == null)
			throw new NullPointerException("No Token has been set, not even an empty byte[0]");
		writer.write(VERSION, VERSION_BITS);
		writer.write(message.getType().value, TYPE_BITS);
		writer.write(message.getToken().length, TOKEN_LENGTH_BITS);
		writer.write(code, CODE_BITS);
		writer.write(message.getMID(), MESSAGE_ID_BITS);
		writer.writeBytes(message.getToken());
		
		List<Option> options = message.getOptions().asSortedList(); // already sorted
		int lastOptionNumber = 0;
		for (Option option:options) {
			
			// write 4-bit option delta
			int optionDelta = option.getNumber() - lastOptionNumber;
			int optionDeltaNibble = getOptionNibble(optionDelta);
			writer.write(optionDeltaNibble, OPTION_DELTA_BITS);
			
			// write 4-bit option length
			int optionLength = option.getLength();
			int optionLengthNibble = getOptionNibble(optionLength);
			writer.write(optionLengthNibble, OPTION_LENGTH_BITS);
			
			// write extended option delta field (0 - 2 bytes)
			if (optionDeltaNibble == 13) {
				writer.write(optionDelta - 13, 8);
			} else if (optionDeltaNibble == 14) {
				writer.write(optionDelta - 269, 16);
			}
			
			// write extended option length field (0 - 2 bytes)
			if (optionLengthNibble == 13) {
				writer.write(optionLength - 13, 8);
			} else if (optionLengthNibble == 14) {
				writer.write(optionLength - 269, 16);
			}

			// write option value
			writer.writeBytes(option.getValue());

			// update last option number
			lastOptionNumber = option.getNumber();
		}
		
		byte[] payload = message.getPayload();
		if (payload != null && payload.length > 0) {
			// if payload is present and of non-zero length, it is prefixed by
			// an one-byte Payload Marker (0xFF) which indicates the end of
			// options and the start of the payload
			writer.writeByte(PAYLOAD_MARKER);
			writer.writeBytes(payload);
		}
	}
	
	/**
	 * Returns the 4-bit option header value.
	 * 
	 * @param optionValue
	 *            the option value (delta or length) to be encoded.
	 * @return the 4-bit option header value.
	 */
	private int getOptionNibble(int optionValue) {
		if (optionValue <= 12) {
			return optionValue;
		} else if (optionValue <= 255 + 13) {
			return 13;
		} else if (optionValue <= 65535 + 269) {
			return 14;
		} else {
			throw new IllegalArgumentException("Unsupported option delta "+optionValue);
		}
	}
	
}
