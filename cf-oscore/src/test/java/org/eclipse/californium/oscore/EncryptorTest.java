/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
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
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import static org.junit.Assert.assertArrayEquals;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.core.network.serialization.UdpDataSerializer;
import org.eclipse.californium.core.coap.Message;
import org.junit.After;
import org.junit.Test;
import org.eclipse.californium.cose.AlgorithmID;

/**
 * Tests the encryption of request and response messages.
 * Uses test vectors from the OSCORE draft for comparison.
 *
 */
public class EncryptorTest {

	// test vector OSCORE draft Appendix C.2.1
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] sid = new byte[] { 0x00 };
	private final static byte[] rid = new byte[] { 0x01 };
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	private final static int seq = 20;

	private static OSCoreCtx ctx = null;

	@After
	public void tearDown() throws Exception {
	}

	/**
	 * Tests encryption of a CoAP Request.
	 * Test vector is from OSCORE draft. (Test Vector 5)
	 *
	 * @throws OSException if encryption fails
	 */
	@Test
	public void testRequestEncryptor() throws OSException {
		//Set up OSCORE context
		ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, null, null);
		ctx.setSenderSeq(seq);

		//Create request message from raw byte array
		byte[] requestBytes = new byte[] { 0x44, 0x01, 0x71, (byte) 0xc3, 0x00, 0x00, (byte) 0xb9, 0x32,
				0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, (byte) 0x83, 0x74, 0x76, 0x31 };
		
		UdpDataParser parser = new UdpDataParser();
		Message mess = parser.parseMessage(requestBytes);
		
		Request r = null;
		if(mess instanceof Request) {
			r = (Request)mess;
		}
		
		//Encrypt the request message
		Request encrypted = RequestEncryptor.encrypt(r, ctx);
		
		//Check the OSCORE option value
		byte[] predictedOSCoreOption = { 0x09, 0x14, 0x00 };
		
		assertArrayEquals(predictedOSCoreOption, encrypted.getOptions().getOscore());
		
		//Check the OSCORE request payload (ciphertext)
		byte[] predictedOSCorePayload = { 0x4e, (byte) 0xd3, 0x39, (byte) 0xa5, (byte) 0xa3, 0x79, (byte) 0xb0, (byte) 0xb8,
				(byte) 0xbc, 0x73, 0x1f, (byte) 0xff, (byte) 0xb0 };
		
		assertArrayEquals(predictedOSCorePayload, encrypted.getPayload());
		
		//Serialize the request message to byte array
		UdpDataSerializer serializer = new UdpDataSerializer();
		byte[] encryptedBytes = serializer.getByteArray(encrypted);
		
		//Check the whole OSCORE request
		byte[] predictedOSCoreBytes = { 0x44, 0x02, 0x71, (byte) 0xc3, 0x00, 0x00, (byte) 0xb9, 0x32,
				0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x63, 0x09, 0x14, 0x00,
				(byte) 0xff, 0x4e, (byte) 0xd3, 0x39, (byte) 0xa5, (byte) 0xa3, 0x79, (byte) 0xb0,
				(byte) 0xb8, (byte) 0xbc, 0x73, 0x1f, (byte) 0xff, (byte) 0xb0 };
		
		assertArrayEquals(predictedOSCoreBytes, encryptedBytes);
		
	}
	
	/**
	 * Tests encryption of a CoAP Response with partial IV.
	 * Test vector is from OSCORE draft. (Test Vector 8)
	 *
	 * @throws OSException if encryption fails
	 */
	@Test
	public void testResponseEncryptor() throws OSException {
		//Set up OSCORE context
		// test vector OSCORE draft Appendix C.1.2
		byte[] master_salt = new byte[] { (byte) 0x9e, 0x7c, (byte) 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40 };
		byte[] sid = new byte[] { 0x01 };
		byte[] rid = new byte[0];
		
		ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null);
		ctx.setSenderSeq(0);
		ctx.setReceiverSeq(seq);

		//Create response message from raw byte array
		byte[] responseBytes = new byte[] { 0x64, 0x45, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
				(byte) 0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21 };
		
		UdpDataParser parser = new UdpDataParser();
		Message mess = parser.parseMessage(responseBytes);
		
		Response r = null;
		if(mess instanceof Response) {
			r = (Response)mess;
		}

		//Encrypt the response message
		boolean newPartialIV = true;
		Response encrypted = ResponseEncryptor.encrypt(r, ctx, newPartialIV);
		
		//Check the OSCORE option value
		byte[] predictedOSCoreOption = { 0x01, 0x00 };
		
		assertArrayEquals(predictedOSCoreOption, encrypted.getOptions().getOscore());
		
		//Check the OSCORE response payload (ciphertext)
		byte[] predictedOSCorePayload = { 0x4d, 0x4c, 0x13, 0x66, (byte) 0x93, (byte) 0x84, (byte) 0xb6, 0x73,
				0x54, (byte) 0xb2, (byte) 0xb6, 0x17, 0x5f, (byte) 0xf4, (byte) 0xb8, 0x65, (byte) 0x8c, 0x66,
				0x6a, 0x6c, (byte) 0xf8, (byte) 0x8e };
		
		assertArrayEquals(predictedOSCorePayload, encrypted.getPayload());

		//Serialize the response message to byte array
		UdpDataSerializer serializer = new UdpDataSerializer();
		byte[] encryptedBytes = serializer.getByteArray(encrypted);

		//Check the whole OSCORE response
		byte[] predictedOSCoreBytes = { 0x64, 0x44, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
				(byte) 0x92, 0x01, 0x00, (byte) 0xff, 0x4d, 0x4c, 0x13, 0x66, (byte) 0x93,
				(byte) 0x84, (byte) 0xb6, 0x73, 0x54, (byte) 0xb2, (byte)0xb6, 0x17, 0x5f,
				(byte) 0xf4, (byte) 0xb8, 0x65, (byte) 0x8c, 0x66, 0x6a, 0x6c, (byte) 0xf8,
				(byte) 0x8e  };
		
		assertArrayEquals(predictedOSCoreBytes, encryptedBytes);
		
	}

}
