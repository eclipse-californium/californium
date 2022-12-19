/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.CODE_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.MESSAGE_ID_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.TOKEN_LENGTH_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.TYPE_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.VERSION;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.VERSION_BITS;

import java.util.Arrays;

import org.eclipse.californium.core.coap.option.OptionDefinition;
import org.eclipse.californium.core.network.serialization.DataSerializer;
import org.eclipse.californium.core.network.serialization.MessageHeader;
import org.eclipse.californium.elements.util.DatagramWriter;

/**
 * A utility to test malicious options.
 * 
 * @since 3.0
 */
public final class TestOption {

	/**
	 * Create option with unchecked value.
	 * 
	 * @param number option number
	 * @param length value length
	 * @return created option
	 * @deprecated use {@link #newOption(OptionDefinition, int)} instead
	 */
	@Deprecated
	public static Option newOption(int number, int length) {
		byte[] value = new byte[length];
		Arrays.fill(value, (byte) 'p');
		return new Option(number).setValueUnchecked(value);
	}

	/**
	 * Create option with unchecked value.
	 * 
	 * @param defintion option definition.
	 * @param length value length
	 * @return created option
	 * @since 3.8
	 */
	public static Option newOption(OptionDefinition definition, int length) {
		byte[] value = new byte[length];
		Arrays.fill(value, (byte) 'p');
		return new Option(definition).setValueUnchecked(value);
	}

	/**
	 * Test {@link DataSerializer} to serialize malformed messages for tests.
	 */
	public static class TestDataSerializer extends DataSerializer {

		protected void serializeMessage(DatagramWriter writer, Message message) {
			int mid = message.getMID();
			if (mid == Message.NONE) {
				IllegalArgumentException ex = new IllegalArgumentException("MID required for UDP serialization!");
				throw ex;
			}
			MessageHeader header = new MessageHeader(CoAP.VERSION, message.getType(), message.getToken(),
					message.getRawCode(), mid, -1);
			serializeHeader(writer, header);
			writer.writeCurrentByte();
			serializeOptionsAndPayload(writer, message.getOptions(), message.getPayload());
		}

		@Override 
		protected void serializeHeader(final DatagramWriter writer, final MessageHeader header) {
			writer.write(VERSION, VERSION_BITS);
			writer.write(header.getType().value, TYPE_BITS);
			writer.write(header.getToken().length(), TOKEN_LENGTH_BITS);
			writer.write(header.getCode(), CODE_BITS);
			writer.write(header.getMID(), MESSAGE_ID_BITS);
			writer.writeBytes(header.getToken().getBytes());
		}
	}
}
