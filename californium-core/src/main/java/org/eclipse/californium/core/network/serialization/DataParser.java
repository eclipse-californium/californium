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
 *    Bosch Software Innovations GmbH - introduce dedicated MessageFormatException
 ******************************************************************************/
package org.eclipse.californium.core.network.serialization;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.*;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageFormatException;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;

/**
 * The DataParser parses incoming byte arrays to messages.
 */
public final class DataParser {

	private DatagramReader reader;

	private int version;
	private int type;
	private int tokenlength;
	private int code;
	private int mid;

	public DataParser(final byte[] bytes) {
		setBytes(bytes);
	}

	private void setBytes(final byte[] bytes) {
		this.reader = new DatagramReader(bytes);
		this.version = reader.read(VERSION_BITS);
		this.type = reader.read(TYPE_BITS);
		this.tokenlength = reader.read(TOKEN_LENGTH_BITS);
		this.code = reader.read(CODE_BITS);
		this.mid = reader.read(MESSAGE_ID_BITS);
	}

	@Override
	public String toString() {
		return new StringBuffer()
				.append("[Ver=").append(version)
				.append("|T=").append(CoAP.Type.valueOf(type))
				.append("|TKL=").append(tokenlength)
				.append("|Code=").append(CoAP.formatCode(code))
				.append("|MID=").append(mid)
				.append("]").toString();
	}

	/**
	 * 
	 * @return {@code true} if the version in the message is {@link CoAP#VERSION}.
	 */
	private void assertCorrectVersion() {
		if (version != CoAP.VERSION) {
			throw new MessageFormatException("Message has invalid version: " + version);
		}
	}

	public int getVersion() {
		return version;
	}

	public int getMID() {
		return mid;
	}

	public boolean isReply() {
		return type > CoAP.Type.NON.value;
	}

	public boolean isRequest() {
		return CoAP.isRequest(code);
	}

	public boolean isResponse() {
		return CoAP.isResponse(code);
	}

	public boolean isEmpty() {
		return CoAP.isEmptyMessage(code);
	}

	/**
	 * 
	 * @return the request object
	 * @throws MessageFormatException if the message contains a message format error
	 */
	public Request parseRequest() {
		Request request = new Request(Code.valueOf(code));
		parseMessage(request);
		return request;
	}

	/**
	 * 
	 * @return the response object
	 * @throws MessageFormatException if the message contains a message format error
	 */
	public Response parseResponse() {
		Response response = new Response(ResponseCode.valueOf(code));
		parseMessage(response);
		return response;
	}

	/**
	 * 
	 * @return the empty message object
	 * @throws MessageFormatException if the message contains a message format error
	 */
	public EmptyMessage parseEmptyMessage() {
		if (!isEmpty()) {
			throw new MessageFormatException("Message does not have empty message code: " + CoAP.formatCode(code));
		}
		EmptyMessage message = new EmptyMessage(Type.valueOf(type));
		parseMessage(message);
		return message;
	}

	/**
	 * Tries to read a token, options and payload from the binary representation of the CoAP message
	 * this parser has been created for.
	 * 
	 * @param message the CoAP message object to set the read values on.
	 * @throws MessageFormatException if the underlying message contains a message format error.
	 */
	private void parseMessage(final Message message) {
		assertCorrectVersion();
		message.setType(Type.valueOf(type));
		message.setMID(mid);

		if (tokenlength > 0) {
			message.setToken(reader.readBytes(tokenlength));
		} else {
			message.setToken(new byte[0]);
		}

		int currentOptionNumber = 0;
		byte nextByte = 0;

		// TODO detect malformed options
		while (reader.bytesAvailable()) {
			nextByte = reader.readNextByte();
			if (nextByte != PAYLOAD_MARKER) {
				// the first 4 bits of the byte represent the option delta
				int optionDeltaNibble = (0xF0 & nextByte) >> 4;
				currentOptionNumber = calculateNextOptionNumber(currentOptionNumber, optionDeltaNibble);

				// the second 4 bits represent the option length
				int optionLengthNibble = 0x0F & nextByte;
				int optionLength = determineValueFromNibble(optionLengthNibble);

				// read option
				Option option = new Option(currentOptionNumber);
				option.setValue(reader.readBytes(optionLength));

				// add option to message
				message.getOptions().addOption(option);
			} else break;
		}

		if (nextByte == PAYLOAD_MARKER) {
			// the presence of a marker followed by a zero-length payload must be processed as a message format error
			if (!reader.bytesAvailable()) {
				throw new MessageFormatException("Found payload marker (0xFF) but message contains no payload");
			} else {
				// get payload
				message.setPayload(reader.readBytesLeft());
			}
		} else {
			message.setPayload(new byte[0]); // or null?
		}
	}

	/**
	 * Calculates the next option number based on the current option number and the option delta as specified in
	 * RFC 7252, Section 3.1
	 * 
	 * @param delta
	 *            the 4-bit option delta value.
	 * @return the next option number.
	 * @throws MessageFormatException if the option number cannot be determined due to a message format error.
	 */
	private int calculateNextOptionNumber(final int currentOptionNumber, final int delta) {
		return currentOptionNumber + determineValueFromNibble(delta);
	}

	private int determineValueFromNibble(final int delta) {
		if (delta <= 12) {
			return delta;
		} else if (delta == 13) {
			return reader.read(8) + 13;
		} else if (delta == 14) {
			return reader.read(16) + 269;
		} else {
			throw new MessageFormatException("Message contains illegal option delta/length: " + delta);
		}
	}
}
