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
 * Bosch Software Innovations GmbH - introduce dedicated MessageFormatException
 * Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 * Achim Kraus (Bosch Software Innovations GmbH) - use Message.NONE as mid
 ******************************************************************************/
package org.eclipse.californium.core.network.serialization;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.elements.tcp.DatagramFramer;
import org.eclipse.californium.elements.util.DatagramReader;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.*;

/**
 * A parser for messages encoded following the encoding defined by the
 * <a href="https://tools.ietf.org/html/draft-ietf-core-coap-tcp-tls-03">CoAP-over-TCP draft</a>.
 */
public final class TcpDataParser extends DataParser {

	@Override
	public MessageHeader parseHeader(final DatagramReader reader) {

		int len = reader.read(LENGTH_NIBBLE_BITS);
		int tokenLength = reader.read(TOKEN_LENGTH_BITS);
		assertValidTokenLength(tokenLength);
		reader.readBytes(DatagramFramer.getLengthFieldSize(len));
		int code = reader.read(CODE_BITS);
		byte token[] = reader.readBytes(tokenLength);

		// No MID/Type/VERSION in TCP message. Use defaults.
		return new MessageHeader(CoAP.VERSION, CoAP.Type.CON, token, code, Message.NONE, 0);
	}
}
