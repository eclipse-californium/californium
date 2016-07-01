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
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageFormatException;
import org.eclipse.californium.elements.RawData;

/**
 * The DataParser parses incoming byte arrays to messages.
 */
public final class UdpDataParser extends DataParser {

	@Override
	public int readMessageCode(RawData rawData) {
		DatagramReader reader = new DatagramReader(rawData.getBytes());

		reader.read(VERSION_BITS);
		reader.read(TYPE_BITS);
		reader.read(TOKEN_LENGTH_BITS);
		return reader.read(CODE_BITS);
	}

	@Override
	public EmptyMessage generateRst(RawData rawData) {
		DatagramReader reader = new DatagramReader(rawData.getBytes());
		EmptyMessage message = new EmptyMessage(CoAP.Type.RST);

		reader.read(VERSION_BITS);
		reader.read(TYPE_BITS);
		int tokenlength = reader.read(TOKEN_LENGTH_BITS);
		reader.read(CODE_BITS);
		int mid = reader.read(MESSAGE_ID_BITS);

		message.setMID(mid);

		byte token[] = reader.readBytes(tokenlength);
		message.setToken(token);

		return message;
	}

	@Override
	public void parseMessage(Message message, RawData rawData) {
		DatagramReader reader = new DatagramReader(rawData.getBytes());

		int version = reader.read(VERSION_BITS);
		int type = reader.read(TYPE_BITS);
		int tokenLength = reader.read(TOKEN_LENGTH_BITS);
		reader.read(CODE_BITS);
		int mid = reader.read(MESSAGE_ID_BITS);

		assertCorrectVersion(version);
		message.setMID(mid);
		message.setType(CoAP.Type.valueOf(type));

		byte token[] = reader.readBytes(tokenLength);
		message.setToken(token);

		parseOptionsAndPayload(reader, message);
	}

	/**
	 * 
	 * @return {@code true} if the version in the message is {@link CoAP#VERSION}.
	 */
	private void assertCorrectVersion(int version) {
		if (version != CoAP.VERSION) {
			throw new MessageFormatException("Message has invalid version: " + version);
		}
	}
}
