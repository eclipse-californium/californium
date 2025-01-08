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
 * Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 ******************************************************************************/
package org.eclipse.californium.core.network.serialization;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.CODE_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.LENGTH_NIBBLE_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.TOKEN_LENGTH_BITS;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.elements.util.DatagramWriter;

/**
 * The DataSerialized serializes outgoing messages to byte arrays based on CoAP
 * TCP/TLS spec:
 * <a href="https://tools.ietf.org/html/draft-ietf-core-coap-tcp-tls-02" target=
 * "_blank">draft-ietf-core-coap-tcp-tls-02</a>
 */
public final class TcpDataSerializer extends DataSerializer {

	// an empty TCP coap message has
	// BIT[7..4] := 0, no payload, no options
	// BIT[3..0] := 0, empty token.
	// BIT[7..0] := 0, code 0.0
	// => two zero bytes
	private final static byte[] EMPTY = new byte[2];

	@Override
	protected byte[] serializeEmpytMessage(Message message) {
		return EMPTY;
	}

	@Override
	protected byte[] serializeMessage(Message message) {
		// first serialize options and payload to get message length
		DatagramWriter optionsAndPayloadWriter = new DatagramWriter();
		serializeOptionsAndPayload(optionsAndPayloadWriter, message.getOptions(), message.getPayload());
		optionsAndPayloadWriter.writeCurrentByte();

		// Variable length encoding per:
		// https://tools.ietf.org/html/draft-ietf-core-coap-tcp-tls-02
		int bodyLength = optionsAndPayloadWriter.size();
		int length = 0;
		int lengthSize = 0;

		if (bodyLength < 13) {
			length = bodyLength;
		} else {
			bodyLength -= 13;
			if (bodyLength < (1 << 8)) {
				length = 13;
				lengthSize = 1;
			} else {
				bodyLength -= (1 << 8);
				if (bodyLength < (1 << 16)) {
					length = 14;
					lengthSize = 2;
				} else {
					length = 15;
					lengthSize = 4;
					bodyLength -= (1 << 16);
				}
			}
		}

		byte[] token = message.getTokenBytes();
		DatagramWriter writer = new DatagramWriter(bodyLength + token.length + lengthSize);
		writer.write(length, LENGTH_NIBBLE_BITS);
		writer.write(token.length, TOKEN_LENGTH_BITS);
		if (lengthSize > 0) {
			writer.write(bodyLength, Byte.SIZE * lengthSize);
		}
		writer.write(message.getRawCode(), CODE_BITS);
		writer.writeBytes(token);
		writer.write(optionsAndPayloadWriter);
		return writer.toByteArray();
	}
}
