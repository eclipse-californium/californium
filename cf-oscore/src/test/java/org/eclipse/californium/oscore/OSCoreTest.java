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
 *    Joakim Brorsson
 *    Ludwig Seitz (RISE SICS)
 *    Tobias Andersson (RISE SICS)
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import static org.junit.Assert.*;

import java.util.ArrayList;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.RandomTokenGenerator;
import org.eclipse.californium.core.network.TokenGenerator;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.oscore.Encryptor;
import org.eclipse.californium.oscore.HashMapCtxDB;
import org.eclipse.californium.oscore.OSCoreCtx;
import org.eclipse.californium.oscore.OSCoreCtxDB;
import org.eclipse.californium.oscore.OSException;
import org.eclipse.californium.oscore.OSSerializer;
import org.eclipse.californium.oscore.ObjectSecurityLayer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.eclipse.californium.elements.util.Bytes;

/**
 * Tests various functionality of OSCORE message handling
 * and generation of cryptographic material.
 *
 */
public class OSCoreTest {

	private OSCoreCtxDB db;
	private String uriId = "coap://localhost/";
	private String uriFull = "coap://localhost:5683";
	private byte[] key = { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41 };
	private OSCoreCtx clientCtx;
	private OSCoreCtx serverCtx;
	private TokenGenerator tokenGenerator = new RandomTokenGenerator(NetworkConfig.getStandard());
	private ArrayList<Token> allTokens = new ArrayList<Token>();
	private final static OptionSet options = new OptionSet();
	
	@Before
	public void setUp() throws Exception {
		db = HashMapCtxDB.getInstance();
		clientCtx = new OSCoreCtx(key, true);
		db.addContext(uriId, clientCtx);
		serverCtx = new OSCoreCtx(key, false);
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testSimple() throws OSException {
		Request request = null;
		Token token = generateToken();
		try {
			request = sendRequest(uriFull, db, token);
		} catch (OSException e) {
			e.printStackTrace();
			assertTrue(false);
		}
		try {
			int seq = db.getSeqByToken(token);
			dbClientToServer();
			ObjectSecurityLayer.prepareReceive(request);
			Response response = sendResponse("it is thursday, citizen", serverCtx, token);
			dbServerToClient(token, seq);
			ObjectSecurityLayer.prepareReceive(response);
		} catch (OSException e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testEndcodingObjectSecurityValueCompression() {
		byte[] objectSecurityRequest = Encryptor.encodeOSCoreRequest(clientCtx);

		assertArrayEquals(objectSecurityRequest, new byte[] { 0x09, 0x00, 0x00 });

		byte[] objectSecurityResponse = Encryptor.encodeOSCoreResponse(serverCtx, false);

		assertArrayEquals(objectSecurityResponse, Bytes.EMPTY);
	}

	/**
	 * Tests generation of nonce.
	 *
	 * @throws OSException if nonce generation fails
	 */
	@Test
	public void testNonceGeneration() throws OSException {

		byte[] partialIV = new byte[] { 3, 4, 5, 6 };
		byte[] senderID = new byte[] { 12, 11, 10, 9, 8, 7 };
		byte[] commonIV = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };

		int nonceLength = 13;

		byte[] nonce = OSSerializer.nonceGeneration(partialIV, senderID, commonIV, nonceLength);
		byte[] predictedNonce = new byte[] { 6, 0, 12, 11, 11, 11, 11, 3, 5, 5, 3, 13, 15 };

		System.out.println("The generated nonce:");
		for (byte b : nonce) {
			System.out.print(Integer.toHexString(b & 0xff) + " ");
		}

		System.out.println();

		System.out.println("The predicted nonce:");
		for (byte b : predictedNonce) {
			System.out.print(Integer.toHexString(b & 0xff) + " ");
		}

		System.out.println();

		assertArrayEquals(predictedNonce, nonce);
	}
	
	/**
	 * Tests generation of nonce.
	 * Test vector is from OSCORE draft. (Test Vector 5)
	 *
	 * @throws OSException if nonce generation fails
	 */
	@Test
	public void testNonceGenerationVector() throws OSException {

		byte[] partialIV = new byte[] { 0x14 };
		byte[] senderID = new byte[] { 0x00 };
		byte[] commonIV = new byte[] { (byte) 0xbe, 0x35, (byte) 0xae, 0x29, 0x7d, 0x2d, (byte) 0xac, (byte) 0xe9,
				0x10, (byte) 0xc5, 0x2e, (byte) 0x99, (byte) 0xf9 };

		int nonceLength = 13;

		byte[] nonce = OSSerializer.nonceGeneration(partialIV, senderID, commonIV, nonceLength);
		byte[] predictedNonce = new byte[] { (byte) 0xbf, 0x35, (byte) 0xae, 0x29, 0x7d, 0x2d, (byte) 0xac, (byte) 0xe9,
				0x10, (byte) 0xc5, 0x2e, (byte) 0x99, (byte) 0xed  };

		System.out.println("The generated nonce:");
		for (byte b : nonce) {
			System.out.print(Integer.toHexString(b & 0xff) + " ");
		}

		System.out.println();

		System.out.println("The predicted nonce:");
		for (byte b : predictedNonce) {
			System.out.print(Integer.toHexString(b & 0xff) + " ");
		}

		System.out.println();

		assertArrayEquals(predictedNonce, nonce);
	}

	/**
	 * Tests generation of (external) AAD.
	 *
	 * @throws OSException if AAD generation fails
	 */
	@Test
	public void testAADGeneration() throws OSException {

		byte[] AAD = OSSerializer.serializeAAD(CoAP.VERSION, clientCtx.getAlg(), clientCtx.getSenderSeq(), clientCtx.getSenderId(), options);
		
		byte[] predictedAAD = new byte[] { (byte) 0x85, 0x01, (byte) 0x81, 0x0a, 0x41, 0x00, 0x41, 0x00, 0x40 };

		System.out.println("The generated AAD:");
		for (byte b : AAD) {
			System.out.print(Integer.toHexString(b & 0xff) + " ");
		}

		System.out.println();

		System.out.println("The predicted AAD:");
		for (byte b : predictedAAD) {
			System.out.print(Integer.toHexString(b & 0xff) + " ");
		}

		System.out.println();

		assertArrayEquals(predictedAAD, AAD);
	}

	/**
	 * Tests generation of (external) AAD.
	 * Test vector is from OSCORE draft. (Test Vector 5)
	 *
	 * @throws OSException if AAD generation fails
	 */
	@Test
	public void testAADGenerationVector() throws OSException {

		Integer senderSeq = 0x14;
		byte[] senderID = { 0x00 };

		byte[] AAD = OSSerializer.serializeAAD(CoAP.VERSION, clientCtx.getAlg(), senderSeq, senderID, options);

		byte[] predictedAAD = new byte[] { (byte) 0x85, 0x01, (byte) 0x81, 0x0a, 0x41, 0x00, 0x41, 0x14, 0x40 };

		System.out.println("The generated AAD:");
		for (byte b : AAD) {
			System.out.print(Integer.toHexString(b & 0xff) + " ");
		}

		System.out.println();

		System.out.println("The predicted AAD:");
		for (byte b : predictedAAD) {
			System.out.print(Integer.toHexString(b & 0xff) + " ");
		}

		System.out.println();

		assertArrayEquals(predictedAAD, AAD);
	}

	@Test
	public void testSeqByToken() {
		Token token = generateToken();
		Integer inputSeq = 7;
		try {
			db.addSeqByToken(token, inputSeq);
		} catch (NullPointerException e) {
			assertTrue(false);
		}
		Integer outputSeq = db.getSeqByToken(token);

		assertTrue(outputSeq.compareTo(inputSeq) == 0);
	}

	@Test
	public void testSeqByNullToken() {
		try {
			db.addSeqByToken(null, 3);
		} catch (Exception e) {
			assertTrue(e.getMessage().equals(ErrorDescriptions.TOKEN_NULL));
		}
	}

	@Test
	public void testSeqByTokenInvalidSeq() {
		Token token = generateToken();
		try {
			db.addSeqByToken(token, -2);
		} catch (NullPointerException e) {
			assertTrue(e.getMessage().equals(ErrorDescriptions.SEQ_NBR_INVALID));
		}
	}

	@Test
	public void testSeqByTokenRemove() {
		Token token = generateToken();
		Integer inputSeq = 7;
		try {
			db.addSeqByToken(token, inputSeq);
		} catch (NullPointerException e) {
			assertTrue(false);
		}

		db.removeSeqByToken(token);
		try {
			db.getSeqByToken(token);
		} catch (Exception e) {
			assertFalse(e instanceof NullPointerException);
		}
	}

	@Test
	public void testSeqByTokenUpdate() {
		Token token = generateToken();
		Integer inputSeq = 7;
		Integer updateSeq = 42;
		try {
			db.addSeqByToken(token, inputSeq);
			db.updateSeqByToken(token, updateSeq);
		} catch (Exception e) {
			assertTrue(false);
		}

		assertTrue(db.getSeqByToken(token) == updateSeq);
	}

	@Test
	public void testEncryptedNoOptionsNoPayload() {
		Request request = Request.newGet().setURI("coap://localhost:5683");
		try {
			ObjectSecurityLayer.prepareSend(request, db.getContext("coap://localhost:5683"));
		} catch (OSException e) {
			e.printStackTrace();
			assertTrue(false);
		}
	}

	/**
	 * Tests that protected options are encrypted and moved to OSOption-value
	 * after encryption and restored after decryption.
	 * 
	 * @throws OSException if encryption or decryption fails
	 */
	@Test
	public void testEncryptDecryptOptions() throws OSException {
		Request request = Request.newGet().setURI("coap://localhost:5683");
		request.getOptions().setLocationPath("/test/path");
		request.getOptions().addOption(new Option(OptionNumberRegistry.OSCORE));
		assertEquals(2, request.getOptions().getLocationPathCount());
		try {
			request = ObjectSecurityLayer.prepareSend(request, db.getContext("coap://localhost:5683"));
		} catch (OSException e) {
			e.printStackTrace();
			assertTrue(false);
		}
		assertEquals(0, request.getOptions().getLocationPathCount());

		dbClientToServer();

		try {
			request = ObjectSecurityLayer.prepareReceive(request);
		} catch (OSException e) {
			e.printStackTrace();
			assertTrue(false);
		}
		assertEquals(2, request.getOptions().getLocationPathCount());
	}

	@Test
	public void testsEncryptDecryptPayloadInPayload() throws OSException {
		Request request = Request.newPost().setURI("coap://localhost:5683");
		request.setPayload("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
		assertTrue("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".equals(request.getPayloadString()));
		try {
			request = ObjectSecurityLayer.prepareSend(request, db.getContext("coap://localhost:5683"));
		} catch (OSException e) {
			e.printStackTrace();
			assertTrue(false);
		}
		assertFalse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".equals(request.getPayloadString()));
		assertEquals("should be only 2 options (Object Security, Uri-host)", 2,
				request.getOptions().asSortedList().size());
		assertEquals("option payload not moved to message", 3, request.getOptions().getOscore().length);

		dbClientToServer();

		try {
			ObjectSecurityLayer.prepareReceive(request);
		} catch (OSException e) {
			e.printStackTrace();
			assertTrue(false);
		}
		assertTrue("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".equals(request.getPayloadString()));
	}

	@Test
	public void testSequenceNumbers() throws OSException {
		Request request1 = null;
		Token tokReq1 = generateToken();
		Token tokReq2 = generateToken();
		try {
			request1 = sendRequest("coap://localhost", db, tokReq1);
			sendRequest("coap://localhost", db, tokReq2);
		} catch (OSException e) {
			e.printStackTrace();
			assertTrue(false);
		}
		assertTrue("seq no:s incorrect", assertCtxState(clientCtx, 2, -1));

		Integer sentSeq = db.getSeqByToken(tokReq1);

		dbClientToServer();

		try {
			ObjectSecurityLayer.prepareReceive(request1);
			assertTrue("seq no:s incorrect", assertCtxState(serverCtx, 0, 0));
			Response response1 = sendResponse("it is thursday, citizen", serverCtx, tokReq1);
			assertTrue("seq no:s incorrect", assertCtxState(serverCtx, 0, 0));

			dbServerToClient(tokReq1, sentSeq);

			ObjectSecurityLayer.prepareReceive(response1);
			assertTrue("seq no:s incorrect", assertCtxState(clientCtx, 2, -1));

		} catch (OSException e) {
			e.printStackTrace();
			assertTrue(false);
		}
	}

	@Test
	public void testSequenceNumbersReplayReject() throws Exception {
		// Test Receive replay of request
		Request request = Request.newPost().setURI("coap://localhost:5683");
		Request request2 = Request.newPost().setURI("coap://localhost:5683");
		request.setMID(99);
		Token t1 = generateToken();
		request.setToken(t1);
		db.addSeqByToken(t1, 0);
		Token t2 = generateToken();
		db.addSeqByToken(t2, 0);
		request2.setToken(t2);
		try {
			// sending seq 0
			request = ObjectSecurityLayer.prepareSend(request, db.getContext("coap://localhost:5683"));
			db.getContext("coap://localhost:5683").setSenderSeq(0);
			request2 = ObjectSecurityLayer.prepareSend(request2, db.getContext("coap://localhost:5683"));
		} catch (OSException e) {
			e.printStackTrace();
			fail();
		}

		dbClientToServer();

		// receiving seq 0 twice
		try {
			ObjectSecurityLayer.prepareReceive(request);
			ObjectSecurityLayer.prepareReceive(request2);
			fail("duplicate seq 0 not detected!");
		} catch (OSException e) {
		}

		// Test receive replay of response
		setUp();// reset sequence number counters
		Response response1 = null;
		Response response2 = null;
		try {
			serverCtx.setReceiverSeq(0);
			response1 = sendResponse("response", serverCtx, t1);
			response1.setType(CoAP.Type.ACK);
			response1.setMID(34);
			serverCtx.setReceiverSeq(0);
			response2 = sendResponse("response", serverCtx, t1);
			response2.setType(CoAP.Type.ACK);
			response2.setMID(34);
		} catch (OSException e) {
			e.printStackTrace();
			fail();
		}
		try {
			db.addContext(t1, clientCtx);
			db.getContext("coap://localhost:5683").setSenderSeq(0);
			db.addSeqByToken(t1, 0);
			ObjectSecurityLayer.prepareReceive(response1);
			ObjectSecurityLayer.prepareReceive(response2);
			fail("invalid token not detected!");
		} catch (OSException e) {
			assertEquals(ErrorDescriptions.TOKEN_INVALID, e.getMessage());
		}
	}

	@Test
	public void testSendSequenceNumberWrap() throws OSException {
		db.getContext("coap://localhost:5683").setSeqMax(2);
		Token t1 = generateToken();
		Token t2 = generateToken();
		Token t3 = generateToken();
		// Test send
		try {
			sendRequest("coap://localhost:5683", db, t1);
			sendRequest("coap://localhost:5683", db, t2);
		} catch (OSException e) {
			e.printStackTrace();
		}
		try {
			sendRequest("coap://localhost:5683", db, t3);
			fail("expected OSException");
		} catch (OSException e) {
		}
	}

	@Test
	public void testReceiveSequenceNumberWrap() throws OSException {

		Token t1 = generateToken();
		Token t2 = generateToken();
		Token t3 = generateToken();

		sendRequest(uriFull, db, t1);
		sendRequest(uriFull, db, t2);
		Request req = sendRequest(uriFull, db, t3);

		dbClientToServer();
		serverCtx.setSeqMax(2);

		// Test receive
		boolean detectWrap = false;
		try {
			ObjectSecurityLayer.prepareReceive(req);
		} catch (OSException e) {
			detectWrap = true;
		}
		assertTrue(detectWrap);
	}

	@Test
	public void testFakeCode() throws OSException {
		Token t1 = generateToken();
		Request request1 = sendRequest(uriFull, db, t1);

		assertEquals(CoAP.Code.POST, request1.getCode());
	}

	private Request sendRequest(String uri, OSCoreCtxDB db, Token token) throws OSException {
		OSCoreCtx ctx = db.getContext(uri);
		Request request = Request.newPost().setURI(uri);
		request.setToken(token);
		db.addContext(token, ctx);
		request.getOptions().addOption(new Option(OptionNumberRegistry.OSCORE));
		db.addSeqByToken(token, ctx.getSenderSeq());
		return ObjectSecurityLayer.prepareSend(request, ctx);
	}

	private boolean assertCtxState(OSCoreCtx ctx, int send, int receive) {
		boolean equal = true;
		if (ctx.getSenderSeq() != send)
			equal = false;
		if (ctx.getReceiverSeq() != receive)
			equal = false;
		return equal;
	}

	private void dbClientToServer() throws OSException {
		db.purge();
		db.addContext(uriId, serverCtx);
	}

	private void dbServerToClient(Token token, Integer seq) throws OSException {
		db.purge();
		db.addContext(uriId, clientCtx);
		db.addContext(token, clientCtx);
		db.addSeqByToken(token, seq);
	}

	private static Response sendResponse(String responsePayload, OSCoreCtx tid, Token token) throws OSException {

		Response response = null;

		if (responsePayload == null || responsePayload.length() <= 0) {
			response = new Response(CoAP.ResponseCode.VALID);
		} else {
			response = new Response(CoAP.ResponseCode.CONTENT);
			response.setPayload(responsePayload);
			response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		}
		response.getOptions().addOption(new Option(OptionNumberRegistry.OSCORE));
		response.setToken(token);

		return ObjectSecurityLayer.prepareSend(response, tid, false);
	}

	public Token generateToken() {
		Token token;
		do {
			token = tokenGenerator.createToken(false);
		} while (tokenExist(token));
		return token;
	}

	public boolean tokenExist(Token token) {
		return allTokens.contains(token);
	}
}
