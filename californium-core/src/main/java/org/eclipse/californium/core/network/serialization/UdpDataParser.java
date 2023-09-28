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
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.option.OptionRegistry;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.core.coap.CoAPMessageFormatException;
import org.eclipse.californium.core.coap.MessageFormatException;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.elements.util.DatagramReader;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.*;

import org.eclipse.californium.core.coap.BlockOption;

/**
 * A parser for messages encoded following the standard CoAP encoding.
 */
public class UdpDataParser extends DataParser {

	private final boolean strictEmptyMessageFormat;

	/**
	 * Create UDP data parser.
	 * 
	 * @since 3.8 Use {@link StandardOptionRegistry#getDefaultOptionRegistry()}
	 *        as default option registry.
	 */
	public UdpDataParser() {
		this(false, StandardOptionRegistry.getDefaultOptionRegistry());
	}

	/**
	 * Create UDP data parser with support for critical custom options.
	 * 
	 * @param criticalCustomOptions Array of critical custom options. Empty to
	 *            fail on custom critical options. {@code null} to use
	 *            {@link OptionNumberRegistry#getCriticalCustomOptions()} as
	 *            default to check for critical custom options.
	 * @see OptionNumberRegistry#getCriticalCustomOptions()
	 * @since 3.8 Use {@link StandardOptionRegistry#getDefaultOptionRegistry()}
	 *        as default option registry.
	 * @deprecated please use {@link OptionRegistry} with
	 *             {@link #UdpDataParser(boolean, OptionRegistry)}.
	 */
	@Deprecated
	public UdpDataParser(int[] criticalCustomOptions) {
		this(false, criticalCustomOptions);
	}

	/**
	 * Create UDP data parser with support for critical custom options and
	 * provided strictness for empty message format.
	 * 
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7252#section-4.1"
	 * target="_blank">RFC7252, Section 4.1</a> defines:
	 * 
	 * <pre>
	 * An Empty message has the Code field set to 0.00.  The Token Length
	 * field MUST be set to 0 and bytes of data MUST NOT be present after
	 * the Message ID field.  If there are any bytes, they MUST be processed
	 * as a message format error.
	 * </pre>
	 * 
	 * @param strictEmptyMessageFormat {@code true}, to process messages with
	 *            code {@code 0} strictly according RFC7252, 4.1.,
	 *            {@code false}, to relax the MUST in a not compliant way!
	 * @param criticalCustomOptions Array of critical custom options. Empty to
	 *            fail on custom critical options. {@code null} to use
	 *            {@link OptionNumberRegistry#getCriticalCustomOptions()} as
	 *            default to check for critical custom options.
	 * @see OptionNumberRegistry#getCriticalCustomOptions()
	 * @since 3.8 Use {@link StandardOptionRegistry#getDefaultOptionRegistry()}
	 *        as default option registry.
	 * @deprecated please use {@link OptionRegistry} with
	 *             {@link #UdpDataParser(boolean, OptionRegistry)}.
	 */
	@Deprecated
	public UdpDataParser(boolean strictEmptyMessageFormat, int[] criticalCustomOptions) {
		super(criticalCustomOptions);
		this.strictEmptyMessageFormat = strictEmptyMessageFormat;
	}

	/**
	 * Create UDP data parser with support for critical custom options and
	 * provided strictness for empty message format.
	 * 
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7252#section-4.1"
	 * target="_blank">RFC7252, Section 4.1</a> defines:
	 * 
	 * <pre>
	 * An Empty message has the Code field set to 0.00.  The Token Length
	 * field MUST be set to 0 and bytes of data MUST NOT be present after
	 * the Message ID field.  If there are any bytes, they MUST be processed
	 * as a message format error.
	 * </pre>
	 * 
	 * @param strictEmptyMessageFormat {@code true}, to process messages with
	 *            code {@code 0} strictly according RFC7252, 4.1.,
	 *            {@code false}, to relax the MUST in a not compliant way!
	 * @param optionRegistry option registry. {@code null} to use
	 *            {@link StandardOptionRegistry#getDefaultOptionRegistry()}
	 * @since 3.8
	 */
	public UdpDataParser(boolean strictEmptyMessageFormat, OptionRegistry optionRegistry) {
		super(optionRegistry);
		this.strictEmptyMessageFormat = strictEmptyMessageFormat;
	}

	@Override
	protected MessageHeader parseHeader(final DatagramReader reader) {
		if (!reader.bytesAvailable(4)) {
			throw new MessageFormatException(
					"UDP Message too short! " + (reader.bitsLeft() / Byte.SIZE) + " must be at least 4 bytes!");
		}
		int version = reader.read(VERSION_BITS);
		assertCorrectVersion(version);
		int typeValue = reader.read(TYPE_BITS);
		Type type = CoAP.Type.valueOf(typeValue);
		boolean confirmable = type == CoAP.Type.CON;
		int tokenLength = reader.read(TOKEN_LENGTH_BITS);
		if (tokenLength > 8) {
			// must be treated as a message format error according to CoAP spec
			// https://tools.ietf.org/html/rfc7252#section-3
			throw new MessageFormatException("UDP Message has invalid token length (> 8) " + tokenLength);
		}
		int code = reader.read(CODE_BITS);
		int mid = reader.read(MESSAGE_ID_BITS);
		if (strictEmptyMessageFormat) {
			if (code == 0) {
				if (reader.bytesAvailable()) {
					throw new CoAPMessageFormatException("UDP malformed Empty Message!", null, mid, code, confirmable);
				}
			} else if (type == Type.RST) {
				throw new CoAPMessageFormatException("UDP malformed RST Message!", null, mid, code, confirmable);				
			}
		}
		if (!reader.bytesAvailable(tokenLength)) {
			throw new CoAPMessageFormatException("UDP Message too short for token! " + (reader.bitsLeft() / Byte.SIZE)
					+ " must be at least " + tokenLength + " bytes!", null, mid, code, confirmable);
		}
		Token token = Token.fromProvider(reader.readBytes(tokenLength));

		return new MessageHeader(version, type, token, code, mid, 0);
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
