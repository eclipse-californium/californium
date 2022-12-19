/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v20.html
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

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.PAYLOAD_MARKER;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.option.LegacyMapBasedOptionRegistry;
import org.eclipse.californium.core.coap.option.OptionDefinition;
import org.eclipse.californium.core.coap.option.OptionRegistry;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.core.coap.CoAPMessageFormatException;
import org.eclipse.californium.core.coap.CoAPOptionException;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageFormatException;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.DatagramReader;

/**
 * A base class for parsing CoAP messages from a byte array.
 */
@SuppressWarnings("deprecation")
public abstract class DataParser {

	protected final OptionRegistry optionRegistry;

	/**
	 * Create data parser.
	 * 
	 * @since 3.8 Use {@link StandardOptionRegistry#getDefaultOptionRegistry()}
	 *        as default option registry.
	 */
	protected DataParser() {
		optionRegistry = StandardOptionRegistry.getDefaultOptionRegistry();
	}

	/**
	 * Create data parser with support for critical custom options.
	 * 
	 * @param criticalCustomOptions Array of critical custom options. Empty to
	 *            fail on custom critical options. {@code null} to use
	 *            {@link OptionNumberRegistry#getCriticalCustomOptions()} as
	 *            default to check for critical custom options.
	 * @see OptionNumberRegistry#getCriticalCustomOptions()
	 * @since 3.8 Use {@link StandardOptionRegistry#getDefaultOptionRegistry()}
	 *        as default option registry.
	 * @deprecated please use {@link OptionRegistry} with
	 *             {@link #DataParser(OptionRegistry)}.
	 */
	@Deprecated
	protected DataParser(int[] criticalCustomOptions) {
		if (criticalCustomOptions == null) {
			criticalCustomOptions = OptionNumberRegistry.getCriticalCustomOptions();
		}
		this.optionRegistry = new LegacyMapBasedOptionRegistry(true, criticalCustomOptions,
				StandardOptionRegistry.getDefaultOptionRegistry());
	}

	/**
	 * Create data parser with provided option registry.
	 * 
	 * @param optionRegistry option registry. {@code null} to use
	 *            {@link StandardOptionRegistry#getDefaultOptionRegistry()}
	 * @since 3.8
	 */
	protected DataParser(OptionRegistry optionRegistry) {
		if (optionRegistry == null) {
			optionRegistry = StandardOptionRegistry.getDefaultOptionRegistry();
		}
		this.optionRegistry = optionRegistry;
	}

	/**
	 * Parses and converts a incoming raw message into CoAP Message.
	 * 
	 * @param raw raw message containing the byte array to parse and additional
	 *            incoming information.
	 * @return the message.
	 * @throws MessageFormatException if the raw-data byte array cannot be
	 *             parsed into a message.
	 * @throws NullPointerException if the raw-data is {@code null}.
	 */
	public final Message parseMessage(final RawData raw) {
		if (raw == null) {
			throw new NullPointerException("raw-data must not be null!");
		}
		if (raw.getConnectorAddress() == null) {
			throw new NullPointerException("raw-data connector's address must not be null!");
		}
		Message message = parseMessage(raw.getBytes());
		message.setSourceContext(raw.getEndpointContext());
		if (message instanceof Request) {
			((Request) message).setLocalAddress(raw.getConnectorAddress(), raw.isMulticast());
		} else {
			message.setLocalAddress(raw.getConnectorAddress());
		}
		message.setNanoTimestamp(raw.getReceiveNanoTimestamp());
		return message;
	}

	/**
	 * Parses a byte array into a CoAP Message.
	 * 
	 * @param msg the byte array to parse.
	 * @return the message.
	 * @throws MessageFormatException if the array cannot be parsed into a
	 *             message.
	 */
	public final Message parseMessage(final byte[] msg) {

		String errorMsg = "illegal message code";
		DatagramReader reader = new DatagramReader(msg);
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
		} catch (CoAPMessageFormatException e) {
			throw e;
		} catch (MessageFormatException e) {
			/** use message to add CoAP message specific information */
			errorMsg = e.getMessage();
		}
		throw new CoAPMessageFormatException(errorMsg, header.getToken(), header.getMID(), header.getCode(),
				CoAP.Type.CON == header.getType());
	}

	/**
	 * Parse message after header.
	 * 
	 * @param reader for reading the byte array to parse.
	 * @param header already read message header
	 * @param target target message.
	 * @return read and completed message.
	 * @see #parseOptionsAndPayload(DatagramReader, Message)
	 * @since 2.6
	 */
	protected Message parseMessage(DatagramReader reader, MessageHeader header, Message target) {
		target.setMID(header.getMID());
		target.setType(header.getType());
		target.setToken(header.getToken());

		parseOptionsAndPayload(reader, target);
		return target;
	}

	/**
	 * Parses a byte array into a CoAP message header.
	 * <p>
	 * Subclasses need to override this method according to the concrete type of
	 * message encoding to support.
	 * 
	 * @param reader for reading the byte array to parse.
	 * @return the message header the array has been parsed into.
	 * @see #parseMessage(DatagramReader, MessageHeader, Message)
	 */
	protected abstract MessageHeader parseHeader(DatagramReader reader);

	/**
	 * Assert, if options are supported for the specific protocol flavor.
	 * 
	 * @param options option set to validate.
	 * @throws IllegalArgumentException if at least one option is not valid for
	 *             the specific flavor.
	 * @since 3.0
	 */
	protected void assertValidOptions(OptionSet options) {
		// empty default implementation
	}

	/**
	 * Check, if option number is a (supported) critical custom option.
	 * 
	 * @param optionNumber option number to check
	 * @return {@code true}, if option number is a critical custom option,
	 *         {@code false}, if not.
	 * @since 3.4
	 * @deprecated
	 */
	@Deprecated
	protected boolean isCiriticalCustomOption(int optionNumber) {
		return false;
	}

	/**
	 * Parse options and payload from reader.
	 * 
	 * @param reader reader that contains the bytes to parse
	 * @param message message to set parsed options and payload
	 * @throws NullPointerException if one of the provided parameters is
	 *             {@code null}
	 * @since 3.0 not longer {@code static}. Please create either a
	 *        {@link TcpDataParser} or a {@link UdpDataParser} in order to
	 *        validate the options according the protocol flavor.
	 */
	public void parseOptionsAndPayload(DatagramReader reader, Message message) {
		if (reader == null) {
			throw new NullPointerException("reader must not be null!");
		}
		if (message == null) {
			throw new NullPointerException("message must not be null!");
		}
		int code = message.getRawCode();
		int currentOptionNumber = 0;
		byte nextByte = 0;
		OptionSet optionSet = message.getOptions();

		while (reader.bytesAvailable()) {
			nextByte = reader.readNextByte();
			if (nextByte == PAYLOAD_MARKER) {
				break;
			}
			try {
				// the first 4 bits of the byte represent the option delta
				int optionDeltaNibble = (0xF0 & nextByte) >> 4;
				currentOptionNumber += determineValueFromNibble(reader, optionDeltaNibble);

				// the second 4 bits represent the option length
				int optionLengthNibble = 0x0F & nextByte;
				int optionLength = determineValueFromNibble(reader, optionLengthNibble);

				// read option
				if (reader.bytesAvailable(optionLength)) {
					byte[] value = reader.readBytes(optionLength);
					Option option = createOption(code, currentOptionNumber, value);
					if (option != null) {
						optionSet.addOption(option);
					}
				} else {
					String msg = String.format(
							"Message contains option of length %d with only fewer bytes left in the message",
							optionLength);
					throw new IllegalArgumentException(msg);
				}
			} catch (CoAPOptionException ex) {
				throw new CoAPMessageFormatException(ex.getMessage(), message.getToken(), message.getMID(),
						message.getRawCode(), message.isConfirmable(), ex.getErrorCode());
			} catch (IllegalArgumentException ex) {
				throw new CoAPMessageFormatException(ex.getMessage(), message.getToken(), message.getMID(),
						message.getRawCode(), message.isConfirmable());
			}
		}
		try {
			assertValidOptions(message.getOptions());
		} catch (IllegalArgumentException ex) {
			throw new CoAPMessageFormatException(ex.getMessage(), message.getToken(), message.getMID(),
					message.getRawCode(), message.isConfirmable(), ResponseCode.BAD_REQUEST);
		}
		if (nextByte == PAYLOAD_MARKER) {
			// the presence of a marker followed by a zero-length payload must
			// be processed as a message format error
			if (!reader.bytesAvailable()) {
				throw new CoAPMessageFormatException("Found payload marker (0xFF) but message contains no payload",
						message.getToken(), message.getMID(), message.getRawCode(), message.isConfirmable());
			} else {
				// get payload
				if (!message.isIntendedPayload()) {
					message.setUnintendedPayload();
				}
				message.setPayload(reader.readBytesLeft());
				message.assertPayloadMatchsBlocksize();
			}
		} else {
			message.setPayload(Bytes.EMPTY);
		}
	}

	/**
	 * Create option.
	 * 
	 * Enables custom implementation to override this method in order to ignore,
	 * fix malformed options, or provide details for an custom error response.
	 * 
	 * Note: only malformed CON-requests are responded with an error message.
	 * Malformed CON-responses are always rejected and malformed NON-messages
	 * are always ignored.
	 * 
	 * @param code message code
	 * @param optionNumber option number
	 * @param value option value
	 * @return create option, or {@code null}, to ignore this option. Please
	 *         take care, if you ignore malformed critical options, the outcome
	 *         will be undefined!
	 * @throws CoAPOptionException details for a custom error response, if the
	 *             option is malformed.
	 * @throws IllegalArgumentException if the option is a critical custom
	 *             option or the value doesn't match the option's specification.
	 * @throws NullPointerException if provided value is {@code null}
	 * @see Message#getRawCode()
	 * @see Option#getNumber()
	 * @since 3.8 (add parameter code)
	 */
	public Option createOption(int code, int optionNumber, byte[] value) {
		OptionDefinition definition = optionRegistry.getDefinitionByNumber(code, optionNumber);
		if (definition != null) {
			return definition.create(value);
		} else if (OptionNumberRegistry.isCritical(optionNumber)) {
			throw new IllegalArgumentException("Unknown critical option " + optionNumber + " is not supported!");
		} else {
			return null;
		}
	}

	/**
	 * Calculates the number based on the delta (nibble).
	 * 
	 * @param reader reader with data
	 * @param delta the 4-bit option delta value.
	 * @return the next number.
	 * @throws IllegalArgumentException if the number cannot be determined due
	 *             to a message format error.
	 * @since 3.0 (removed Message from parameter list)
	 */
	private static int determineValueFromNibble(DatagramReader reader, int delta) {
		if (delta <= 12) {
			return delta;
		} else if (delta == 13) {
			return reader.read(8) + 13;
		} else if (delta == 14) {
			return reader.read(16) + 269;
		} else {
			throw new IllegalArgumentException("Message contains illegal option delta/length: " + delta);
		}
	}
}
