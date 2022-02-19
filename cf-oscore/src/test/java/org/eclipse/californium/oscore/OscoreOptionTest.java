/*******************************************************************************
 * Copyright (c) 2022 RISE and others.
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
 * Rikard Höglund (RISE) - testing OSCORE option encoding/decoding
 ******************************************************************************/
package org.eclipse.californium.oscore;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.eclipse.californium.elements.util.Bytes;
import org.junit.Test;

/**
 * Test class for testing encoding and decoding of the OSCORE option. Uses the
 * OscoreOptionEncoder and OscoreOptionDecoder classes.
 *
 */
public class OscoreOptionTest {

	/**
	 * Tests encoding of the OSCORE option compared to known values from the
	 * OSCORE RFC test vectors.
	 * https://datatracker.ietf.org/doc/html/rfc8613#appendix-C.6
	 */
	@Test
	public void testEncoding() {

		byte[] correctOption = new byte[] { (byte) 0x19, (byte) 0x14, (byte) 0x08, (byte) 0x37, (byte) 0xcb,
				(byte) 0xf3, (byte) 0x21, (byte) 0x00, (byte) 0x17, (byte) 0xa2, (byte) 0xd3 };

		byte[] idContext = new byte[] { (byte) 0x37, (byte) 0xcb, (byte) 0xf3, (byte) 0x21, (byte) 0x00, (byte) 0x17,
				(byte) 0xa2, (byte) 0xd3 };
		int senderSequenceNumber = 20;
		byte[] partialIV = new byte[] { (byte) 0x14 };
		byte[] kid = Bytes.EMPTY;

		OscoreOptionEncoder encoder = new OscoreOptionEncoder();
		encoder.setIdContext(idContext);
		encoder.setKid(kid);
		encoder.setPartialIV(senderSequenceNumber);
		byte[] encodedOption = encoder.getBytes();

		assertArrayEquals("Encoded option incorrect", correctOption, encodedOption);

		// Encode the option again but directly using the Partial IV
		encoder.setIdContext(idContext);
		encoder.setKid(kid);
		encoder.setPartialIV(partialIV);
		encodedOption = encoder.getBytes();

		assertArrayEquals("Encoded option incorrect", correctOption, encodedOption);
	}

	/**
	 * Tests encoding of the OSCORE option compared to a known value.
	 */
	@Test
	public void testEncodingCustom() {

		byte[] correctOption = new byte[] { (byte) 0x0b, (byte) 0x08, (byte) 0x7a, (byte) 0x23, (byte) 0x33 };

		byte[] kid = new byte[] { (byte) 0x33 };
		int senderSequenceNumber = 555555;
		byte[] idContext = null;

		OscoreOptionEncoder encoder = new OscoreOptionEncoder();
		encoder.setIdContext(idContext);
		encoder.setKid(kid);
		encoder.setPartialIV(senderSequenceNumber);
		byte[] encodedOption = encoder.getBytes();

		assertArrayEquals("Encoded option incorrect", correctOption, encodedOption);
	}

	/**
	 * Tests decoding of the OSCORE option compared to known values from the
	 * OSCORE RFC test vectors.
	 * https://datatracker.ietf.org/doc/html/rfc8613#appendix-C.6
	 * 
	 * @throws CoapOSException on failure to decode the OSCORE option value
	 */
	@Test
	public void testDecoding() throws CoapOSException {

		byte[] oscoreOption = new byte[] { (byte) 0x19, (byte) 0x14, (byte) 0x08, (byte) 0x37, (byte) 0xcb, (byte) 0xf3,
				(byte) 0x21, (byte) 0x00, (byte) 0x17, (byte) 0xa2, (byte) 0xd3 };

		byte[] correctIdContext = new byte[] { (byte) 0x37, (byte) 0xcb, (byte) 0xf3, (byte) 0x21, (byte) 0x00,
				(byte) 0x17, (byte) 0xa2, (byte) 0xd3 };
		int correctSenderSequenceNumber = 20;
		byte[] correctPartialIV = new byte[] { (byte) 0x14 };
		byte[] correctKid = Bytes.EMPTY;
		int correctH = 1;
		int correctK = 1;
		int correctN = 1;

		OscoreOptionDecoder decoder = new OscoreOptionDecoder(oscoreOption);
		byte[] idContext = decoder.getIdContext();
		byte[] kid = decoder.getKid();
		int senderSequenceNumber = decoder.getSequenceNumber();
		byte[] partialIV = decoder.getPartialIV();
		int h = decoder.getH();
		int k = decoder.getK();
		int n = decoder.getN();

		assertArrayEquals("Decoded ID Context incorrect", correctIdContext, idContext);
		assertArrayEquals("Decoded KID incorrect", correctKid, kid);
		assertEquals("Decoded SSN incorrect", correctSenderSequenceNumber, senderSequenceNumber);
		assertArrayEquals("Decoded Partial IV incorrect", correctPartialIV, partialIV);

		assertEquals("Decoded H flag bit incorrect", correctH, h);
		assertEquals("Decoded K flag bit incorrect", correctK, k);
		assertEquals("Decoded N flag bits incorrect", correctN, n);
		assertEquals("Decoded N flag bits differ from PIV length", correctPartialIV.length, n);
	}

	/**
	 * Tests decoding of the OSCORE option compared to a known value.
	 * 
	 * @throws CoapOSException on failure to decode the OSCORE option value
	 */
	@Test
	public void testDecodingCustom() throws CoapOSException {

		byte[] oscoreOption = new byte[] { (byte) 0x0b, (byte) 0x08, (byte) 0x7a, (byte) 0x23, (byte) 0x33 };

		byte[] correctKid = new byte[] { (byte) 0x33 };
		int correctSenderSequenceNumber = 555555;
		byte[] correctPartialIV = new byte[] { (byte) 0x08, (byte) 0x7A, (byte) 0x23 };
		byte[] correctIdContext = null;
		int correctH = 0;
		int correctK = 1;
		int correctN = 3;

		OscoreOptionDecoder decoder = new OscoreOptionDecoder(oscoreOption);
		byte[] idContext = decoder.getIdContext();
		byte[] kid = decoder.getKid();
		int senderSequenceNumber = decoder.getSequenceNumber();
		byte[] partialIV = decoder.getPartialIV();
		int h = decoder.getH();
		int k = decoder.getK();
		int n = decoder.getN();

		assertArrayEquals("Decoded ID Context incorrect", correctIdContext, idContext);
		assertArrayEquals("Decoded KID incorrect", correctKid, kid);
		assertEquals("Decoded SSN incorrect", correctSenderSequenceNumber, senderSequenceNumber);
		assertArrayEquals("Decoded Partial IV incorrect", correctPartialIV, partialIV);

		assertEquals("Decoded H flag bit incorrect", correctH, h);
		assertEquals("Decoded K flag bit incorrect", correctK, k);
		assertEquals("Decoded N flag bits incorrect", correctN, n);
		assertEquals("Decoded N flag bits differ from PIV length", correctPartialIV.length, n);
	}

	/**
	 * Tests encoding and decoding of the OSCORE option with varying values for
	 * the Partial IV (Sender Sequence Number). The test varies the SSN to set
	 * between 0 and 2^30, and checks that it is decoded correctly.
	 * 
	 * @throws CoapOSException on failure to decode the OSCORE option value
	 */
	@Test
	public void testOptionPiv() throws CoapOSException {

		byte[] correctIdContext = new byte[] { (byte) 0x37, (byte) 0xcb, (byte) 0xf3, (byte) 0x21, (byte) 0x00,
				(byte) 0x17, (byte) 0xa2, (byte) 0xd3 };
		byte[] correctKid = new byte[] { (byte) 0x04, (byte) 0x99 };

		for (int i = 0; i < 30; i++) {

			// Sender Sequence Number to use
			int correctSenderSequenceNumber = (int) Math.pow(2, i);

			// Encode the option
			OscoreOptionEncoder encoder = new OscoreOptionEncoder();
			encoder.setIdContext(correctIdContext);
			encoder.setKid(correctKid);
			encoder.setPartialIV(correctSenderSequenceNumber);
			byte[] encodedOption = encoder.getBytes();

			// Decode the option
			OscoreOptionDecoder decoder = new OscoreOptionDecoder(encodedOption);
			byte[] idContext = decoder.getIdContext();
			byte[] kid = decoder.getKid();
			int senderSequenceNumber = decoder.getSequenceNumber();
			byte[] partialIV = decoder.getPartialIV();
			int n = decoder.getN();

			assertArrayEquals("Decoded ID Context incorrect", correctIdContext, idContext);
			assertArrayEquals("Decoded KID incorrect", correctKid, kid);
			assertEquals("Decoded SSN incorrect", correctSenderSequenceNumber, senderSequenceNumber);
			assertEquals("Decoded N flag bits differ from decoded PIV length", partialIV.length, n);
			assertEquals("Decoded N flag bits differ from expected PIV length", 1 + (i / 8), n);

		}

	}

}
