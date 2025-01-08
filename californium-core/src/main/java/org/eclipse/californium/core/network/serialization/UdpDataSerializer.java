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
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.MESSAGE_ID_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.TOKEN_LENGTH_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.TYPE_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.VERSION;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.VERSION_BITS;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The DataSerialized serializes outgoing messages to byte arrays.
 */
public class UdpDataSerializer extends DataSerializer {

	/** the logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(UdpDataSerializer.class);

	@Override
	protected byte[] serializeEmpytMessage(Message message) {
		int mid = message.getMID();
		if (mid == Message.NONE) {
			IllegalArgumentException ex = new IllegalArgumentException("MID required for UDP serialization!");
			LOGGER.warn("UDP, {}:", message, ex);
			throw ex;
		}
		DatagramWriter writer = new DatagramWriter(4);
		writer.write(VERSION, VERSION_BITS);
		writer.write(message.getType().value, TYPE_BITS);
		writer.write(0, TOKEN_LENGTH_BITS);
		writer.write(0, CODE_BITS);
		writer.write(message.getMID(), MESSAGE_ID_BITS);
		return writer.toByteArray();
	}

	@Override
	protected byte[] serializeMessage(Message message) {
		int mid = message.getMID();
		if (mid == Message.NONE) {
			IllegalArgumentException ex = new IllegalArgumentException("MID required for UDP serialization!");
			LOGGER.warn("UDP, {}:", message, ex);
			throw ex;
		}
		DatagramWriter writer = new DatagramWriter(message.getPayloadSize() + 32);
		byte[] token = message.getTokenBytes();
		writer.write(VERSION, VERSION_BITS);
		writer.write(message.getType().value, TYPE_BITS);
		writer.write(token.length, TOKEN_LENGTH_BITS);
		writer.write(message.getRawCode(), CODE_BITS);
		writer.write(message.getMID(), MESSAGE_ID_BITS);
		writer.writeBytes(token);
		serializeOptionsAndPayload(writer, message.getOptions(), message.getPayload());
		return writer.toByteArray();
	}

	@Override
	protected void assertValidOptions(Message message) {
		super.assertValidOptions(message);
		UdpDataParser.assertValidUdpOptions(message);
	}
}
