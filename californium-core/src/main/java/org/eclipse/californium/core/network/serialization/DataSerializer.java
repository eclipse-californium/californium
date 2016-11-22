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
 ******************************************************************************/
package org.eclipse.californium.core.network.serialization;

import org.eclipse.californium.core.coap.*;
import org.eclipse.californium.elements.MessageCallback;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.util.DatagramWriter;

import java.net.InetSocketAddress;
import java.util.List;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.*;

/**
 * Serializes messages into wire format.
 */
public abstract class DataSerializer {

	/**
	 * Serializes a request and caches the result on the request object to skip future serializations.
	 * <p>
	 * This method simply invokes {@link #serializeRequest(Request, MessageCallback)} with
	 * a {@code null} callback.
	 * 
	 * @param request The request to serialize.
	 * @return The object containing the serialized request.
	 */
	public final RawData serializeRequest(final Request request) {
		return serializeRequest(request, null);
	}

	/**
	 * Serializes a request and caches the result on the request object to skip future serializations.
	 * <p>
	 * NB: The byte array cached in the message is encoded according to the specific serializer implementation's
	 * supported wire format. Any subsequent invocation of this method with the same request object will therefore
	 * simply return the cached byte array. This may cause problems when the first invocation was done on a different
	 * type of serializer than the second.
	 * <p>
	 * Clients should use the {@link #getByteArray(Request)} method in order to prevent caching of the resulting
	 * byte array.
	 * 
	 * @param request The request to serialize.
	 * @param outboundCallback The callback to invoke once the message's correlation context
	 *                         has been established. 
	 * @return The object containing the serialized request and the callback.
	 */
	public final RawData serializeRequest(final Request request, final MessageCallback outboundCallback) {

		if (request.getBytes() == null) {
			request.setBytes(getByteArray(request));
		}
		return RawData.outbound(
						request.getBytes(),
						new InetSocketAddress(request.getDestination(),
						request.getDestinationPort()),
						outboundCallback,
						false);
	}

	/**
	 * Serializes a request to the wire format.
	 * <p>
	 * The main difference between this and the <em>serializeRequest</em> method is that this method
	 * does <em>not</em> cache the byte array in the request's <em>bytes</em> property.
	 * 
	 * @param request The request to serialize.
	 * @return The encoded request.
	 */
	public final byte[] getByteArray(final Request request) {

		DatagramWriter writer = new DatagramWriter();
		byte[] body = serializeOptionsAndPayload(request);

		MessageHeader header = new MessageHeader(CoAP.VERSION, request.getType(), request.getToken(),
				request.getRawCode(), request.getMID(), body.length);
		serializeHeader(writer, header);
		writer.writeBytes(body);

		return writer.toByteArray();
	}

	/**
	 * Serializes response and caches bytes on the request object to skip future serializations.
	 * 
	 * @param response The response to serialize.
	 * @return The object containing the serialized response.
	 */
	public final RawData serializeResponse(final Response response) {
		if (response.getBytes() == null) {
			DatagramWriter writer = new DatagramWriter();
			byte[] body = serializeOptionsAndPayload(response);

			MessageHeader header = new MessageHeader(CoAP.VERSION, response.getType(), response.getToken(),
					response.getCode().value, response.getMID(), body.length);
			serializeHeader(writer, header);
			writer.writeBytes(body);

			byte[] bytes = writer.toByteArray();
			response.setBytes(bytes);
		}
		return new RawData(response.getBytes(), response.getDestination(), response.getDestinationPort());
	}

	/**
	 * Serializes empty messages and caches bytes on the emptyMessage object to skip future serializations.
	 * 
	 * @param emptyMessage The message to serialize.
	 * @return The object containing the serialized message.
	 */
	public final RawData serializeEmptyMessage(final EmptyMessage emptyMessage) {
		if (emptyMessage.getBytes() == null) {
			DatagramWriter writer = new DatagramWriter();
			byte[] body = serializeOptionsAndPayload(emptyMessage);

			MessageHeader header = new MessageHeader(CoAP.VERSION, emptyMessage.getType(), emptyMessage.getToken(), 0,
					emptyMessage.getMID(), body.length);
			serializeHeader(writer, header);
			writer.writeBytes(body);

			byte[] bytes = writer.toByteArray();
			emptyMessage.setBytes(bytes);
		}
		return new RawData(emptyMessage.getBytes(), emptyMessage.getDestination(), emptyMessage.getDestinationPort());
	}

	/**
	 * Serializes a message's <em>header</em> values to the wire format.
	 * 
	 * @param writer The writer to serialize the values to.
	 * @param header The header values.
	 */
	protected abstract void serializeHeader(DatagramWriter writer, MessageHeader header);

	private static byte[] serializeOptionsAndPayload(final Message message) {
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
