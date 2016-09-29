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

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.*;

import org.eclipse.californium.elements.util.DatagramWriter;

/**
 * The DataSerialized serializes outgoing messages to byte arrays based on CoAP TCP/TLS spec:
 * <a href="https://tools.ietf.org/html/draft-ietf-core-coap-tcp-tls"/>
 */
public final class TcpDataSerializer extends DataSerializer {

	@Override protected void serializeHeader(final DatagramWriter writer, final MessageHeader header) {
		// Variable length encoding per: https://tools.ietf.org/html/draft-ietf-core-coap-tcp-tls-02
		if (header.getBodyLength() < 13) {
			writer.write(header.getBodyLength(), LENGTH_NIBBLE_BITS);
			writer.write(header.getToken().length, TOKEN_LENGTH_BITS);
		} else if (header.getBodyLength() < (1 << 8) + 13) {
			writer.write(13, LENGTH_NIBBLE_BITS);
			writer.write(header.getToken().length, TOKEN_LENGTH_BITS);
			writer.write(header.getBodyLength() - 13, Byte.SIZE);
		} else if (header.getBodyLength() < (1 << 16) + 269) {
			writer.write(14, LENGTH_NIBBLE_BITS);
			writer.write(header.getToken().length, TOKEN_LENGTH_BITS);
			writer.write(header.getBodyLength() - 269, 2 * Byte.SIZE);
		} else {
			writer.write(15, LENGTH_NIBBLE_BITS);
			writer.write(header.getToken().length, TOKEN_LENGTH_BITS);
			writer.write(header.getBodyLength() - 65805, 4 * Byte.SIZE);
		}

		writer.write(header.getCode(), CODE_BITS);
		writer.writeBytes(header.getToken());
	}
}
