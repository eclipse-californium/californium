/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.html.
 * <p>
 * Contributors:
 * Matthias Kovatsch - creator and main architect
 * Martin Lanter - architect and re-implementation
 * Dominique Im Obersteg - parsers and initial implementation
 * Daniel Pauli - parsers and initial implementation
 * Kai Hudalla - logging
 * Bosch Software Innovations GmbH - turn into utility class with static methods only
 * Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 * Achim Kraus (Bosch Software Innovations GmbH) - add CoAP detail information 
 *                                                 to MessageFormatException
 * Achim Kraus (Bosch Software Innovations GmbH) - add EndpointContext when parsing
 *                                                 RawData. 
 * Achim Kraus (Bosch Software Innovations GmbH) - expose parseOptionsAndPayload
 ******************************************************************************/
package org.eclipse.californium.core.network.serialization;

import org.eclipse.californium.core.coap.*;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.util.DatagramReader;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.PAYLOAD_MARKER;

import java.io.ByteArrayInputStream;

/**
 * A base class for parsing CoAP messages from a byte array.
 */
public abstract class DataParser {

	/**
	 * Parses a byte array into a CoAP Message.
	 * 
	 * @param raw contains the byte array to parse.
	 * @return the message.
	 * @throws MessageFormatException if the raw-data byte array cannot be
	 *             parsed into a message.
	 * @throws NullPointerException if the raw-data is {@code null}.
	 */
	public final Message parseMessage(final RawData raw) {
		if (raw == null) {
			throw new NullPointerException("raw-data must not be null!");
		}
		Message message = parseMessage(raw.getBytes());
		message.setSourceContext(raw.getEndpointContext());
		return message;
	}

	/**
	 * Parses a byte array into a CoAP Message.
	 * 
	 * @param msg the byte array to parse.
	 * @return the message.
	 * @throws MessageFormatException if the array cannot be parsed into a message.
	 */
	public final Message parseMessage(final byte[] msg) {

		String errorMsg = "illegal message code";
		DatagramReader reader = new DatagramReader(new ByteArrayInputStream(msg));
		MessageHeader header = parseHeader(reader);
		try {
			Message message = null;
			if (CoAP.isRequest(header.getCode())) {
				message = parseMessage(reader, header, new Request(CoAP.Code.valueOf(header.getCode())));
			} else if (CoAP.isResponse(header.getCode())) {
				message = parseMessage(reader, header, new Response(CoAP.ResponseCode.valueOf(header.getCode())));
			} else if (CoAP.isEmptyMessage(header.getCode())) {
				message = parseMessage(reader, header, new EmptyMessage(header.getType()));
			}

			// Set the message's bytes and return the message
			if (message != null) {
				message.setBytes(msg);
				return message;
			}
		} catch (MessageFormatException e) {
			/** use message to add CoAP message specific information */
			errorMsg = e.getMessage();
		}
		throw new CoAPMessageFormatException(errorMsg, header.getMID(), header.getCode(), CoAP.Type.CON == header.getType());
	}

	private static Message parseMessage(final DatagramReader source, final MessageHeader header, final Message target) {
		target.setMID(header.getMID());
		target.setType(header.getType());
		target.setToken(header.getToken());

		parseOptionsAndPayload(source, target);
		return target;
	}

	/**
	 * Parses a byte array into a CoAP message header.
	 * <p>
	 * Subclasses need to override this method according to the concrete type of message
	 * encoding to support.
	 * 
	 * @param reader for reading the byte array to parse.
	 * @return the message header the array has been parsed into.
	 */
	protected abstract MessageHeader parseHeader(DatagramReader reader);

	/**
	 * Asserts that the length of the token as read from the encoded message complies
	 * with the CoAP spec.
	 * 
	 * @param tokenLength the length value read from the message header.
	 * @throws MessageFormatException if the value is greater than eight.
	 */
	protected static final void assertValidTokenLength(int tokenLength) {
		if (tokenLength > 8) {
			// must be treated as a message format error according to CoAP spec
			// https://tools.ietf.org/html/rfc7252#section-3
			throw new MessageFormatException("Message has invalid token length (> 8)" + tokenLength);
		}
	}

	/**
	 * Parse options and payload from reader.
	 * 
	 * @param reader reader that contains the bytes to parse
	 * @param message message to set parsed options and payload
	 * @throws NullPointerException if one of the provided parameters is
	 *             {@code null}
	 */
	public static void parseOptionsAndPayload(DatagramReader reader, Message message) {
		if (reader == null) {
			throw new NullPointerException("reader must not be null!");
		}
		if (message == null) {
			throw new NullPointerException("message must not be null!");
		}
		int currentOptionNumber = 0;
		byte nextByte = 0;

		while (reader.bytesAvailable()) {
			nextByte = reader.readNextByte();
			if (nextByte != PAYLOAD_MARKER) {
				// the first 4 bits of the byte represent the option delta
				int optionDeltaNibble = (0xF0 & nextByte) >> 4;
				currentOptionNumber = calculateNextOptionNumber(reader, currentOptionNumber, optionDeltaNibble, message);

				// the second 4 bits represent the option length
				int optionLengthNibble = 0x0F & nextByte;
				int optionLength = determineValueFromNibble(reader, optionLengthNibble, message);

				// read option
				if (reader.bytesAvailable(optionLength)) {
					Option option = new Option(currentOptionNumber);
					option.setValue(reader.readBytes(optionLength));

					// add option to message
					message.getOptions().addOption(option);
				} else {
					String msg = String.format(
							"Message contains option of length %d with only fewer bytes left in the message",
							optionLength);
					throw new CoAPMessageFormatException(msg, message.getMID(), message.getRawCode(), message.isConfirmable());
				}
			} else
				break;
		}

		if (nextByte == PAYLOAD_MARKER) {
			// the presence of a marker followed by a zero-length payload must be processed as a message format error
			if (!reader.bytesAvailable()) {
				throw new CoAPMessageFormatException(
						"Found payload marker (0xFF) but message contains no payload",
						message.getMID(), message.getRawCode(), message.isConfirmable());
			} else {
				// get payload
				message.setPayload(reader.readBytesLeft());
			}
		} else {
			message.setPayload((String) null);
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
	private static int calculateNextOptionNumber(
			final DatagramReader reader,
			final int currentOptionNumber,
			final int delta,
			final Message message) {
		return currentOptionNumber + determineValueFromNibble(reader, delta, message);
	}

	private static int determineValueFromNibble(final DatagramReader reader, final int delta, final Message message) {
		if (delta <= 12) {
			return delta;
		} else if (delta == 13) {
			return reader.read(8) + 13;
		} else if (delta == 14) {
			return reader.read(16) + 269;
		} else {
			throw new CoAPMessageFormatException(
					"Message contains illegal option delta/length: " + delta,
					message.getMID(), message.getRawCode(), message.isConfirmable());
		}
	}
}
