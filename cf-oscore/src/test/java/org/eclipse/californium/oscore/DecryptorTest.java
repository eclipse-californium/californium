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
import static org.junit.Assert.assertEquals;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.core.network.serialization.UdpDataSerializer;
import org.eclipse.californium.core.coap.Message;
import org.junit.After;
import org.junit.Test;
import org.eclipse.californium.cose.AlgorithmID;

/**
 * Tests the decryption of request and response messages.
 * Uses test vectors from the OSCORE draft for comparison.
 *
 */
public class DecryptorTest {

	// test vector OSCORE draft Appendix C.2.2
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] rid = new byte[] { 0x00 };
	private final static byte[] sid = new byte[] { 0x01 };
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	private static OSCoreCtx ctx = null;

	@After
	public void tearDown() throws Exception {
	}

	/**
	 * Tests decryption of a CoAP Request.
	 * Test vector is from OSCORE draft. (Test Vector 5)
	 *
	 * @throws OSException if decryption fails
	 */
	@Test
	public void testRequestDecryptor() throws OSException {
		//Set up OSCORE context
		ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, null, null);
		
		OSCoreCtxDB db = HashMapCtxDB.getInstance();
		db.addContext(ctx);

		//Create the encrypted request message from raw byte array
		byte[] encryptedRequestBytes = new byte[] { 0x44, 0x02, 0x71, (byte) 0xc3, 0x00, 0x00, (byte) 0xb9, 0x32,
				0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x63, 0x09, 0x14, 0x00,
				(byte) 0xff, 0x4e, (byte) 0xd3, 0x39, (byte) 0xa5, (byte) 0xa3, 0x79, (byte) 0xb0,
				(byte) 0xb8, (byte) 0xbc, 0x73, 0x1f, (byte) 0xff, (byte) 0xb0 };
		
		UdpDataParser parser = new UdpDataParser();
		Message mess = parser.parseMessage(encryptedRequestBytes);
		
		Request r = null;
		if(mess instanceof Request) {
			r = (Request)mess;
		}
		
		//Decrypt the request message
		Request decrypted = RequestDecryptor.decrypt(r);
		decrypted.getOptions().removeOscore();
		
		//Serialize the request message to byte array
		UdpDataSerializer serializer = new UdpDataSerializer();
		byte[] decryptedBytes = serializer.getByteArray(decrypted);

		//Check the whole decrypted request
		byte[] predictedBytes = { 0x44, 0x01, 0x71, (byte) 0xc3, 0x00, 0x00, (byte) 0xb9, 0x32,
				0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, (byte) 0x83, 0x74, 0x76, 0x31 };
		
		assertArrayEquals(predictedBytes, decryptedBytes);
		
	}
	
	/**
	 * Tests decryption of a CoAP Response with partial IV.
	 * Test vector is from OSCORE draft. (Test Vector 8)
	 * FIXME
	 * @throws OSException if decryption fails
	 */
	@Test
	public void testResponseDecryptor() throws OSException {
		//Set up OSCORE context
		// test vector OSCORE draft Appendix C.1.1
		byte[] master_salt = new byte[] { (byte) 0x9e, 0x7c, (byte) 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40 };
		byte[] sid = new byte[0];
		byte[] rid = new byte[] { 0x01 };
		int seq = 20;
		
		ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null);

		//Create the encrypted response message from raw byte array
		byte[] encryptedResponseBytes = new byte[] { 0x64, 0x44, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
				(byte) 0x92, 0x01, 0x00, (byte) 0xff, 0x4d, 0x4c, 0x13, 0x66, (byte) 0x93,
				(byte) 0x84, (byte) 0xb6, 0x73, 0x54, (byte) 0xb2, (byte)0xb6, 0x17, 0x5f,
				(byte) 0xf4, (byte) 0xb8, 0x65, (byte) 0x8c, 0x66, 0x6a, 0x6c, (byte) 0xf8,
				(byte) 0x8e };
		
		UdpDataParser parser = new UdpDataParser();
		Message mess = parser.parseMessage(encryptedResponseBytes);
		
		Response r = null;
		if(mess instanceof Response) {
			r = (Response)mess;
		}
		
		//Set up some state information simulating the original outgoing request
		OSCoreCtxDB db = HashMapCtxDB.getInstance();
		db.addContext(r.getToken(), ctx);
		db.addSeqByToken(r.getToken(), seq);
		
		//Decrypt the response message
		Response decrypted = ResponseDecryptor.decrypt(r);
		decrypted.getOptions().removeOscore();
		
		//Check the decrypted response payload
		String predictedPayload = "Hello World!"; 
		
		assertEquals(predictedPayload, decrypted.getPayloadString());
		
		//Serialize the response message to byte array
		UdpDataSerializer serializer = new UdpDataSerializer();
		byte[] decryptedBytes = serializer.getByteArray(decrypted);

		//Check the whole decrypted response
		byte[] predictedBytes = { 0x64, 0x45, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74,
				(byte) 0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21 };
		
		assertArrayEquals(predictedBytes, decryptedBytes);
		
	}

}
