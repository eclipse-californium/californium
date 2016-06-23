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
 *    Joe Magerramov (Amazon AWS) - CoAP over TCP support
 ******************************************************************************/
package org.eclipse.californium.core.network.serialization;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.tcp.DatagramFramer;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.CODE_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.LENGTH_NIBBLE_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.TOKEN_LENGTH_BITS;

/**
 * The DataParser parses incoming byte arrays to messages.
 */
public final class TcpDataParser extends DataParser {

	@Override
	public int readMessageCode(RawData rawData) {
		DatagramReader reader = new DatagramReader(rawData.getBytes());
		int len = reader.read(LENGTH_NIBBLE_BITS);
		reader.read(TOKEN_LENGTH_BITS);
		reader.readBytes(DatagramFramer.getLengthFieldSize(len));

		return reader.read(CODE_BITS);
	}

	@Override
	public EmptyMessage generateRst(RawData rawData) {
		// No RSTs in TCP land.
		return null;
	}

	@Override
	public void parseMessage(Message message, RawData rawData) {
		DatagramReader reader = new DatagramReader(rawData.getBytes());

		int len = reader.read(LENGTH_NIBBLE_BITS);
		int tokenlength = reader.read(TOKEN_LENGTH_BITS);

		// Only need length bits to skip right count of bytes. The connector already handle message delimiting for us.
		reader.readBytes(DatagramFramer.getLengthFieldSize(len));

		reader.read(CODE_BITS);
		byte token[] = reader.readBytes(tokenlength);

		// Running over TCP type is irrelevant. But to keep things backwards copmatible setting type to CON.
		message.setMID(0);
		message.setToken(token);
		message.setType(CoAP.Type.CON);

		parseOptionsAndPayload(reader, message);
	}
}
