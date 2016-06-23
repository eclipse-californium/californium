/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Bosch Software Innovations GmbH - turn into utility class with static methods only
 *    Joe Magerramov (Amazon AWS) - CoAP over TCP support
 ******************************************************************************/
package org.eclipse.californium.core.network.serialization;

import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;

import java.util.List;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.CODE_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.LENGTH_NIBBLE_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.MESSAGE_ID_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.OPTION_DELTA_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.OPTION_LENGTH_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.PAYLOAD_MARKER;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.TOKEN_LENGTH_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.TYPE_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.VERSION;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.VERSION_BITS;

/**
 * The DataSerialized serializes outgoing messages to byte arrays based on CoAP TCP/TLS spec:
 * <a href="https://tools.ietf.org/html/draft-ietf-core-coap-tcp-tls"/>
 */
public final class TcpDataSerializer implements DataSerializer {

	@Override
	public byte[] serializeRequest(Request request) {
		DatagramWriter writer = new DatagramWriter();
		Code code = request.getCode();
		serializeMessage(writer, request, code == null ? 0 : code.value);
		return writer.toByteArray();
	}

	@Override
	public byte[] serializeResponse(Response response) {
		DatagramWriter writer = new DatagramWriter();
		serializeMessage(writer, response, response.getCode().value);
		return writer.toByteArray();
	}

	@Override
	public byte[] serializeEmptyMessage(Message message) {
		DatagramWriter writer = new DatagramWriter();
		serializeMessage(writer, message, 0);
		return writer.toByteArray();
	}

	private void serializeMessage(final DatagramWriter writer, final Message message, final int code) {
		if (message.getToken() == null)
			throw new NullPointerException("No Token has been set, not even an empty byte[0]");

		byte[] optionsAndPayload = writeOptionsAndPayload(message);

		// Variable length encoding per: https://tools.ietf.org/html/draft-ietf-core-coap-tcp-tls-02
		if (optionsAndPayload.length < 13) {
			writer.write(optionsAndPayload.length, LENGTH_NIBBLE_BITS);
			writer.write(message.getToken().length, TOKEN_LENGTH_BITS);
		} else if (optionsAndPayload.length < (1 << 8) + 13) {
			writer.write(13, LENGTH_NIBBLE_BITS);
			writer.write(message.getToken().length, TOKEN_LENGTH_BITS);
			writer.write(optionsAndPayload.length - 13, Byte.SIZE);
		} else if (optionsAndPayload.length < (1 << 16) + 269){
			writer.write(14, LENGTH_NIBBLE_BITS);
			writer.write(message.getToken().length, TOKEN_LENGTH_BITS);
			writer.write(optionsAndPayload.length - 269, 2 * Byte.SIZE);
		} else {
			writer.write(15, LENGTH_NIBBLE_BITS);
			writer.write(message.getToken().length, TOKEN_LENGTH_BITS);
			writer.write(optionsAndPayload.length - 65805, 4 * Byte.SIZE);
		}

		writer.write(code, CODE_BITS);
		writer.writeBytes(message.getToken());
		writer.writeBytes(optionsAndPayload);
	}

	private byte[] writeOptionsAndPayload(final Message message) {
		DatagramWriter writer = new DatagramWriter();
		List<Option> options = message.getOptions().asSortedList(); // already
		// sorted
		int lastOptionNumber = 0;
		for (Option option : options) {
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
				writer.write(optionDelta - 13, Byte.SIZE);
			} else if (optionDeltaNibble == 14) {
				writer.write(optionDelta - 269, 2 * Byte.SIZE);
			}

			// write extended option length field (0 - 2 bytes)
			if (optionLengthNibble == 13) {
				writer.write(optionLength - 13, Byte.SIZE);
			} else if (optionLengthNibble == 14) {
				writer.write(optionLength - 269, 2 * Byte.SIZE);
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

		return writer.toByteArray();
	}

	/**
	 * Returns the 4-bit option header value.
	 * 
	 * @param optionValue the option value (delta or length) to be encoded.
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
			throw new IllegalArgumentException("Unsupported option delta " + optionValue);
		}
	}
}
