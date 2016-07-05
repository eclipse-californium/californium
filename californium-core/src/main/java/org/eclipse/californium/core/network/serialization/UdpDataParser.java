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
 *    Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 ******************************************************************************/
package org.eclipse.californium.core.network.serialization;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.*;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MessageFormatException;

/**
 * The DataParser parses incoming byte arrays to messages.
 */
public final class UdpDataParser extends DataParser {

	@Override
	protected MessageHeader parseHeader(final DatagramReader reader) {
		int version = reader.read(VERSION_BITS);
		int type = reader.read(TYPE_BITS);
		int tokenLength = reader.read(TOKEN_LENGTH_BITS);
		int code = reader.read(CODE_BITS);
		int mid = reader.read(MESSAGE_ID_BITS);
		byte token[] = reader.readBytes(tokenLength);

		assertCorrectVersion(version);
		return new MessageHeader(version, type, token, code, mid, 0);
	}

	private void assertCorrectVersion(int version) {
		if (version != CoAP.VERSION) {
			throw new MessageFormatException("Message has invalid version: " + version);
		}
	}
}
