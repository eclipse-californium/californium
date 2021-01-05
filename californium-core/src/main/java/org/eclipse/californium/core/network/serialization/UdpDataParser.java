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
 * Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 ******************************************************************************/
package org.eclipse.californium.core.network.serialization;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAPMessageFormatException;
import org.eclipse.californium.core.coap.MessageFormatException;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.elements.util.DatagramReader;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.*;

import org.eclipse.californium.core.coap.BlockOption;

/**
 * A parser for messages encoded following the standard CoAP encoding.
 */
public final class UdpDataParser extends DataParser {

	@Override
	protected MessageHeader parseHeader(final DatagramReader reader) {
		if (!reader.bytesAvailable(4)) {
			throw new MessageFormatException(
					"UDP Message too short! " + (reader.bitsLeft() / Byte.SIZE) + " must be at least 4 bytes!");
		}
		int version = reader.read(VERSION_BITS);
		assertCorrectVersion(version);
		int type = reader.read(TYPE_BITS);
		int tokenLength = reader.read(TOKEN_LENGTH_BITS);
		if (tokenLength > 8) {
			// must be treated as a message format error according to CoAP spec
			// https://tools.ietf.org/html/rfc7252#section-3
			throw new MessageFormatException("UDP Message has invalid token length (> 8) " + tokenLength);
		}
		int code = reader.read(CODE_BITS);
		int mid = reader.read(MESSAGE_ID_BITS);
		if (!reader.bytesAvailable(tokenLength)) {
			throw new CoAPMessageFormatException("UDP Message too short for token! " + (reader.bitsLeft() / Byte.SIZE)
					+ " must be at least " + tokenLength + " bytes!", null, mid, code, CoAP.Type.CON.value == type);
		}
		Token token = Token.fromProvider(reader.readBytes(tokenLength));

		return new MessageHeader(version, CoAP.Type.valueOf(type), token, code, mid, 0);
	}

	@Override
	protected void assertValidOptions(OptionSet options) {
		assertValidUdpOptions(options);
	}

	private void assertCorrectVersion(int version) {
		if (version != CoAP.VERSION) {
			throw new MessageFormatException("UDP Message has invalid version: " + version);
		}
	}

	/**
	 * Assert, if options are supported for the UDP protocol flavor.
	 * 
	 * @param options option set to validate.
	 * @throws IllegalArgumentException if one block option uses BERT.
	 * @since 3.0
	 */
	public static void assertValidUdpOptions(OptionSet options) {
		BlockOption block = options.getBlock1();
		if (block != null && block.isBERT()) {
			throw new IllegalArgumentException("Block1 BERT used for UDP!");
		}
		block = options.getBlock2();
		if (block != null && block.isBERT()) {
			throw new IllegalArgumentException("Block2 BERT used for UDP!");
		}
	}
}
