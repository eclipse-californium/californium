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

import java.util.Arrays;

import org.eclipse.californium.core.coap.option.OptionDefinition;
import org.eclipse.californium.core.network.serialization.DataSerializer;
import org.eclipse.californium.core.network.serialization.UdpDataSerializer;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.StringUtil;

/**
 * A utility to test malicious options.
 * 
 * @since 3.0
 */
public final class TestOption {

	/**
	 * Create option with unchecked value.
	 * 
	 * @param definition option definition.
	 * @param length value length
	 * @return created option
	 * @since 3.8
	 */
	public static Option newOption(OptionDefinition definition, int length) {
		final byte[] value = new byte[length];
		Arrays.fill(value, (byte) 'p');
		return new Option(definition) {

			@Override
			public int getLength() {
				return value.length;
			}

			@Override
			public void writeTo(DatagramWriter writer) {
				writer.writeBytes(value);
			}

			@Override
			public String toValueString() {
				return "0x" + StringUtil.byteArray2Hex(value);
			}
			
		};
	}

	/**
	 * Test {@link DataSerializer} to serialize malformed messages for tests.
	 */
	public static class TestDataSerializer extends UdpDataSerializer {
		@Override
		protected void assertValidOptions(Message message) {
		}
	}
}
