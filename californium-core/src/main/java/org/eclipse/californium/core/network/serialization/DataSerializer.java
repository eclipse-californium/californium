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
 * Achim Kraus (Bosch Software Innovations GmbH) - add CorrelationContext for response
 *                                                 (fix GitHub issue #104)
 * Achim Kraus (Bosch Software Innovations GmbH) - add outboundCallback for responses
 *                                                 and empty messages. issue #305
 * Achim Kraus (Bosch Software Innovations GmbH) - use Destination EndpointContext 
 *                                                 for RawData
 * Achim Kraus (Bosch Software Innovations GmbH) - expose serializeOptionsAndPayload
 *                                                 and adapt parameters
 ******************************************************************************/
package org.eclipse.californium.core.network.serialization;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.OPTION_DELTA_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.OPTION_LENGTH_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.PAYLOAD_MARKER;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.MessageCallback;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.util.DatagramWriter;

/**
 * Serializes messages into wire format.
 */
public abstract class DataSerializer {

	/**
	 * Serializes a message to the wire format.
	 * <p>
	 * This does <em>not</em> cache the byte array in the message's
	 * <em>bytes</em> property.
	 * 
	 * @param message The message to serialize.
	 * @return The encoded message.
	 * @throws NullPointerException if message is {@code null}
	 * @throws IllegalArgumentException if a NON empty-message is provided, or a
	 *             empty-message uses a none-empty-token.
	 * @see #serializeEmpytMessage(Message)
	 * @see #serializeMessage(Message)
	 */
	public final byte[] getByteArray(final Message message) {
		if (message == null) {
			throw new NullPointerException("message must not be null!");
		}
		assertValidOptions(message);
		message.assertPayloadMatchsBlocksize();
		if (message.getRawCode() == 0) {
			// simple serialization for empty message.
			// https://tools.ietf.org/html/rfc7252#section-4.1
			if (message.getType() == Type.NON) {
				throw new IllegalArgumentException("NON message must not use code 0 (empty message)!");
			} else if (!message.hasEmptyToken()) {
				throw new IllegalArgumentException("Empty messages must not use a token!");
			} else if (message.getPayloadSize() > 0) {
				throw new IllegalArgumentException("Empty messages must not contain payload!");
			}
			return serializeEmpytMessage(message);
		} else {
			if (message.getType() == Type.RST) {
				throw new IllegalArgumentException("RST must use code 0 (empty message)!");
			}
			return serializeMessage(message);
		}
	}

	/**
	 * Ensures the message is serialized.
	 * <p>
	 * Ensures, that {@link Message#getBytes()} returns the serialized message.
	 * 
	 * @param message message to serialize.
	 * @since 4.0
	 */
	public final void ensureByteArray(final Message message) {
		if (message == null) {
			throw new NullPointerException("message must not be null!");
		}
		if (message.getBytes() == null) {
			message.setBytes(getByteArray(message));
		}
	}

	/**
	 * Serializes a request and caches the result on the request object to skip
	 * future serializations.
	 * <p>
	 * This method simply invokes
	 * {@link #serializeRequest(Request, MessageCallback)} with a {@code null}
	 * callback.
	 * 
	 * @param request The request to serialize.
	 * @return The object containing the serialized request.
	 * @throws NullPointerException if request is {@code null}
	 */
	public final RawData serializeRequest(final Request request) {
		return serializeRequest(request, null);
	}

	/**
	 * Serializes a request and caches the result on the request object to skip
	 * future serializations.
	 * <p>
	 * NB: The byte array cached in the message is encoded according to the
	 * specific serializer implementation's supported wire format. Any
	 * subsequent invocation of this method with the same request object will
	 * therefore simply return the cached byte array. This may cause problems
	 * when the first invocation was done on a different type of serializer than
	 * the second.
	 * <p>
	 * Clients should use the {@link #getByteArray(Message)} method in order to
	 * prevent caching of the resulting byte array.
	 * 
	 * @param request The request to serialize.
	 * @param outboundCallback The callback to invoke once the message is sent.
	 * @return The object containing the serialized request and the callback.
	 * @throws NullPointerException if request is {@code null}
	 */
	public final RawData serializeRequest(final Request request, final MessageCallback outboundCallback) {
		if (request == null) {
			throw new NullPointerException("request must not be null!");
		}
		ensureByteArray(request);
		return RawData.outbound(request.getBytes(), request.getEffectiveDestinationContext(), outboundCallback,
				request.isMulticast());
	}

	/**
	 * Serializes response and caches bytes on the request object to skip future
	 * serializations.
	 * 
	 * @param response The response to serialize.
	 * @return The object containing the serialized response.
	 * @throws NullPointerException if response is {@code null}
	 */
	public final RawData serializeResponse(final Response response) {
		return serializeResponse(response, null);
	}

	/**
	 * Serializes response and caches bytes on the request object to skip future
	 * serializations.
	 * 
	 * @param response The response to serialize.
	 * @param outboundCallback The callback to invoke once the message is sent.
	 * @return The object containing the serialized response.
	 * @throws NullPointerException if response is {@code null}
	 */
	public final RawData serializeResponse(final Response response, final MessageCallback outboundCallback) {
		if (response == null) {
			throw new NullPointerException("response must not be null!");
		}
		ensureByteArray(response);
		return RawData.outbound(response.getBytes(), response.getEffectiveDestinationContext(), outboundCallback,
				false);
	}

	/**
	 * Serializes empty messages and caches bytes on the emptyMessage object to
	 * skip future serializations.
	 * 
	 * @param emptyMessage The message to serialize.
	 * @return The object containing the serialized message.
	 * @throws NullPointerException if empty-message is {@code null}
	 */
	public final RawData serializeEmptyMessage(final EmptyMessage emptyMessage) {
		return serializeEmptyMessage(emptyMessage, null);
	}

	/**
	 * Serializes empty messages and caches bytes on the emptyMessage object to
	 * skip future serializations.
	 * 
	 * @param emptyMessage The message to serialize.
	 * @param outboundCallback The callback to invoke once the message is sent.
	 * @return The object containing the serialized message.
	 * @throws NullPointerException if empty-message is {@code null}
	 */
	public final RawData serializeEmptyMessage(final EmptyMessage emptyMessage,
			final MessageCallback outboundCallback) {
		if (emptyMessage == null) {
			throw new NullPointerException("empty-message must not be null!");
		}
		ensureByteArray(emptyMessage);
		return RawData.outbound(emptyMessage.getBytes(), emptyMessage.getEffectiveDestinationContext(),
				outboundCallback, false);
	}

	/**
	 * Serialize empty message (code 0).
	 * <p>
	 * Used to serialize empty messages without token, options and payload.
	 * 
	 * @param message the message to serialize.
	 * @return serialized message as byte array.
	 * @see #serializeMessage(Message)
	 * @since 4.0
	 */
	protected abstract byte[] serializeEmpytMessage(Message message);

	/**
	 * Serialize message.
	 * 
	 * @param message the message to serialize.
	 * @return serialized message as byte array.
	 * @see #serializeOptionsAndPayload(DatagramWriter, OptionSet, byte[])
	 * @see #serializeEmpytMessage(Message)
	 * @since 4.0
	 */
	protected abstract byte[] serializeMessage(Message message);

	/**
	 * Assert, if options are supported for the specific protocol flavor.
	 * 
	 * @param message message of option set to validate.
	 * @throws IllegalArgumentException if at least one option is not valid for
	 *             the specific flavor.
	 * @since 4.0 (changed parameter to Message)
	 */
	protected void assertValidOptions(Message message) {
		if (CoAP.isResponse(message.getRawCode())) {
			int count = message.getOptions().getETagCount();
			if (count > 1) {
				throw new IllegalArgumentException("Multiple ETAGs (" + count + ") in response!");
			}
		}
	}

	/**
	 * Serialize options and payload. Append the serialized options and payload
	 * to the writer.
	 * 
	 * @param writer writer to append the data
	 * @param optionSet option set to be serialized
	 * @param payload payload to be serialized. Maybe {@code null} for no
	 *            payload.
	 * @throws NullPointerException if either writer or options is {@code null}
	 */
	public static void serializeOptionsAndPayload(DatagramWriter writer, final OptionSet optionSet,
			final byte[] payload) {
		if (writer == null) {
			throw new NullPointerException("writer must not be null!");
		}
		if (optionSet == null) {
			throw new NullPointerException("option-set must not be null!");
		}

		int lastOptionNumber = 0;
		for (Option option : optionSet.asSortedList()) {

			// write 4-bit option delta
			int optionNumber = option.getNumber();
			int optionDelta = optionNumber - lastOptionNumber;
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

			option.writeTo(writer);

			// update last option number
			lastOptionNumber = optionNumber;
		}

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
	 * @param optionValue the option value (delta or length) to be encoded.
	 * @return the 4-bit option header value.
	 * @throws IllegalArgumentException if the option value is &gt; 65535 + 269.
	 */
	private static int getOptionNibble(final int optionValue) {
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
