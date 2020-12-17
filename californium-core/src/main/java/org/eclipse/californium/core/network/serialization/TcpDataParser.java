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
 * Bosch Software Innovations GmbH - introduce dedicated MessageFormatException
 * Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 * Achim Kraus (Bosch Software Innovations GmbH) - use Message.NONE as mid
 * Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 ******************************************************************************/
package org.eclipse.californium.core.network.serialization;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageFormatException;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.elements.util.DatagramReader;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.*;

/**
 * A parser for messages encoded following the encoding defined by the
 * <a href="https://tools.ietf.org/html/draft-ietf-core-coap-tcp-tls-03">CoAP-over-TCP draft</a>.
 */
public final class TcpDataParser extends DataParser {

	@Override
	protected MessageHeader parseHeader(final DatagramReader reader) {
		if (!reader.bytesAvailable(1)) {
			throw new MessageFormatException(
					"TCP Message too short! " + (reader.bitsLeft() / Byte.SIZE) + " must be at least 1 byte!");
		}
		int len = reader.read(LENGTH_NIBBLE_BITS);
		int tokenLength = reader.read(TOKEN_LENGTH_BITS);
		int lengthSize = 0;
		if (tokenLength > 8) {
			// must be treated as a message format error according to CoAP spec
			// https://tools.ietf.org/html/rfc7252#section-3
			throw new MessageFormatException("TCP Message has invalid token length (> 8) " + tokenLength);
		}

		if (len == 13) {
			lengthSize = 1;
		} else if (len == 14) {
			lengthSize = 2;
		} else if (len == 15) {
			lengthSize = 4;
		}
		int size = lengthSize + 1 + tokenLength;
		if (!reader.bytesAvailable(size)) {
			throw new MessageFormatException(
					"TCP Message too short! " + (reader.bitsLeft() / Byte.SIZE) + " must be at least " + size + " bytes!");
		}
		reader.readBytes(lengthSize);
		int code = reader.read(CODE_BITS);
		Token token = Token.fromProvider(reader.readBytes(tokenLength));

		// No MID/Type/VERSION in TCP message. Use defaults.
		return new MessageHeader(CoAP.VERSION, CoAP.Type.CON, token, code, Message.NONE, 0);
	}
}
