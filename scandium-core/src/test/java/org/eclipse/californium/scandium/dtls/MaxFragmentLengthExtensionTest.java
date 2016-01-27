/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.net.InetSocketAddress;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.HelloExtension.ExtensionType;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class MaxFragmentLengthExtensionTest {

	static final byte[] EXT_512_BYTES = new byte[]{
			(byte) 0x00, (byte) 0x05, // length of extensions list: 5 bytes 
			(byte) 0x00, (byte) 0x01, // type code
			(byte) 0x00, (byte) 0x01, // length of extension data: 1 byte
			(byte) 0x01}; // code 2^9
	byte[] maxFragmentLengthStructure;
	MaxFragmentLengthExtension extension;

	@Test
	public void testFromByteArray() throws HandshakeException {
		// given a max fragment length extension data struct with code 1
		byte code = (byte) 0x01;
		givenAMaxFragmentLengthStruct(code);

		whenParsingTheExtensionStruct();

		// then assert that length is 512 bytes
		assertThat(extension.getFragmentLength().length(), is(512));
	}

	@Test
	public void testFromByteArrayDetectsIllegalCode() throws HandshakeException {
		// given a max fragment length extension data struct with undefined code
		byte code = (byte) 0x06;
		givenAMaxFragmentLengthStruct(code);

		try {
			whenParsingTheExtensionStruct();
			fail("Should have thrown HandshakeException");
		} catch (HandshakeException e) {
			// then a HandshakeException should indicate illegal code
			assertThat(e.getAlert().getDescription(), is(AlertMessage.AlertDescription.ILLEGAL_PARAMETER));
			assertThat(e.getAlert().getLevel(), is(AlertMessage.AlertLevel.FATAL));
		}
	}

	@Test
	public void testSerialization() {

		givenA512ByteMaxFragmentLengthExtension();

		// when serializing the extension
		HelloExtensions helloExtensions = new HelloExtensions();
		helloExtensions.addExtension(extension);
		maxFragmentLengthStructure = helloExtensions.toByteArray();

		assertThat(maxFragmentLengthStructure, is(EXT_512_BYTES));
	}

	private void givenA512ByteMaxFragmentLengthExtension() {
		extension = new MaxFragmentLengthExtension(1);
	}

	private void givenAMaxFragmentLengthStruct(byte code) {
		maxFragmentLengthStructure = new byte[]{
				(byte) 0x00, (byte) 0x05, // length of extensions list: 5 bytes 
				(byte) 0x00, (byte) 0x01, // type code
				(byte) 0x00, (byte) 0x01, // length of extension data: 1 byte
				code}; // code 
	}

	private void whenParsingTheExtensionStruct() throws HandshakeException {
		HelloExtensions helloExtions = HelloExtensions.fromByteArray(maxFragmentLengthStructure, new InetSocketAddress(0));
		extension = (MaxFragmentLengthExtension) 
				helloExtions.getExtension(ExtensionType.MAX_FRAGMENT_LENGTH);
	}
}
