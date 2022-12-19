/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
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
 *    Joakim Brorsson
 *    Ludwig Seitz (RISE SICS)
 *    Tobias Andersson (RISE SICS)
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.core.network.RandomTokenGenerator;
import org.eclipse.californium.core.network.TokenGenerator;
import org.eclipse.californium.core.network.TokenGenerator.Scope;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.Bytes;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests various functionality of OSCORE message handling
 * and generation of cryptographic material.
 *
 */
public class OSCoreTest {

	private final static int MAX_UNFRAGMENTED_SIZE = 4096;

	private OSCoreCtxDB dbClient;
	private OSCoreCtxDB dbServer;
	private String uriId = "coap://localhost/";
	private String uriFull = "coap://localhost:5683";
	private byte[] key = { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41 };
	private OSCoreCtx clientCtx;
	private OSCoreCtx serverCtx;
	private TokenGenerator tokenGenerator = new RandomTokenGenerator(Configuration.createStandardWithoutFile());
	private ArrayList<Token> allTokens = new ArrayList<Token>();
	private final static OptionSet options = new OptionSet();
	
	@Before
	public void setUp() throws Exception {
		dbClient = new HashMapCtxDB();
		clientCtx = new OSCoreCtx(key, true);
		dbClient.addContext(uriId, clientCtx);
		serverCtx = new OSCoreCtx(key, false);
		dbServer = new HashMapCtxDB();
		dbServer.addContext(serverCtx);
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testSimple() throws OSException {
		Request request = null;
		Token token = generateToken();
		try {
			request = sendRequest(uriFull, dbClient, token);
		} catch (OSException e) {
			e.printStackTrace();
			assertTrue(false);
		}
		try {
			int seq = clientCtx.getSenderSeq();
			dbClientToServer();
			ObjectSecurityLayer.prepareReceive(dbServer, request, serverCtx);
			Response response = sendResponse("it is thursday, citizen", serverCtx, token);
			dbServerToClient(token, seq);
			ObjectSecurityLayer.prepareReceive(dbClient, response, seq);
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
	public void testEncryptedNoOptionsNoPayload() {
		Request request = Request.newGet().setURI("coap://localhost:5683");
		try {
			ObjectSecurityLayer.prepareSend(dbClient, request);
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
		request.getOptions().addOption(StandardOptionRegistry.OSCORE.create(Bytes.EMPTY));
		assertEquals(2, request.getOptions().getLocationPathCount());
		try {
			request = ObjectSecurityLayer.prepareSend(dbClient, request);
		} catch (OSException e) {
			e.printStackTrace();
			assertTrue(false);
		}
		assertEquals(0, request.getOptions().getLocationPathCount());

		dbClientToServer();

		try {
			request = ObjectSecurityLayer.prepareReceive(dbServer, request, serverCtx);
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
			request = ObjectSecurityLayer.prepareSend(dbClient, request);
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
			ObjectSecurityLayer.prepareReceive(dbServer, request, serverCtx);
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
			request1 = sendRequest("coap://localhost", dbClient, tokReq1);
			sendRequest("coap://localhost", dbClient, tokReq2);
		} catch (OSException e) {
			e.printStackTrace();
			assertTrue(false);
		}
		assertTrue("seq no:s incorrect", assertCtxState(clientCtx, 2, 0));

		Integer sentSeq = clientCtx.getSenderSeq();

		dbClientToServer();

		try {
			ObjectSecurityLayer.prepareReceive(dbServer, request1, serverCtx);
			assertTrue("seq no:s incorrect", assertCtxState(serverCtx, 0, 0));
			Response response1 = sendResponse("it is thursday, citizen", serverCtx, tokReq1);
			assertTrue("seq no:s incorrect", assertCtxState(serverCtx, 0, 0));

			dbServerToClient(tokReq1, sentSeq);

			ObjectSecurityLayer.prepareReceive(dbClient, response1, sentSeq);
			assertTrue("seq no:s incorrect", assertCtxState(clientCtx, 2, 0));

		} catch (OSException e) {
			e.printStackTrace();
			assertTrue(false);
		}
	}

	/**
	 * Tests shifting of the replay window considering different window sizes.
	 * Simulates receiving 100 requests with incrementing sequence numbers.
	 * 
	 * @param replayWindowSize the desired size of the replay window
	 * @throws OSException on test failure
	 */
	private void replayWindowShiftTester(int replayWindowSize) throws OSException {

		byte[] rid = new byte[] { 0x00 };
		byte[] sid = new byte[] { 0x01 };

		serverCtx = new OSCoreCtx(key, false, AlgorithmID.AES_CCM_16_64_128, sid, rid, AlgorithmID.HKDF_HMAC_SHA_256,
				replayWindowSize, null, null, MAX_UNFRAGMENTED_SIZE);

		int lastSeq = 100;
		for (int seq = 0; seq < lastSeq; seq++) {
			serverCtx.checkIncomingSeq(seq);
		}

		assertEquals("Failed test case with replay window size: " + replayWindowSize, lastSeq - replayWindowSize,
				serverCtx.getLowestRecipientSeq());
	}

	/**
	 * Tests shifting of the replay window with replay window sizes of 1 to 32.
	 * 
	 */
	@Test
	public void testReplayWindowShifts() {
		for (int windowSize = 1; windowSize <= 32; windowSize++) {
			try {
				replayWindowShiftTester(windowSize);
			} catch (OSException e) {
				String msg = "Failed test case with replay window size: " + windowSize;
				System.err.println(msg);
				fail(msg);
				e.printStackTrace();
			}
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
		Token t2 = generateToken();
		request2.setToken(t2);
		try {
			// sending seq 0
			request = ObjectSecurityLayer.prepareSend(dbClient, request);
			dbClient.getContext("coap://localhost:5683").setSenderSeq(0);
			request2 = ObjectSecurityLayer.prepareSend(dbClient, request2);
		} catch (OSException e) {
			e.printStackTrace();
			fail();
		}

		dbClientToServer();

		// receiving seq 0 twice
		try {
			ObjectSecurityLayer.prepareReceive(dbServer, request, serverCtx);
			ObjectSecurityLayer.prepareReceive(dbServer, request2, serverCtx);
			fail("duplicate seq 0 not detected!");
		} catch (OSException e) {
		}

		// Test receive replay of response
		setUp();// reset sequence number counters
		Response response1 = null;
		Response response2 = null;
		try {
			serverCtx.setRecipientSeq(0);
			response1 = sendResponse("response", serverCtx, t1);
			response1.setType(CoAP.Type.ACK);
			response1.setMID(34);
			serverCtx.setRecipientSeq(0);
			response2 = sendResponse("response", serverCtx, t1);
			response2.setType(CoAP.Type.ACK);
			response2.setMID(34);
		} catch (OSException e) {
			e.printStackTrace();
			fail();
		}
		try {
			dbClient.addContext(t1, clientCtx);
			dbClient.getContext("coap://localhost:5683").setSenderSeq(0);
			ObjectSecurityLayer.prepareReceive(dbClient, response1, 0);
			ObjectSecurityLayer.prepareReceive(dbClient, response2, 0);
			fail("invalid token not detected!");
		} catch (OSException e) {
			assertEquals(ErrorDescriptions.TOKEN_INVALID, e.getMessage());
		}
	}

	@Test
	public void testSendSequenceNumberWrap() throws OSException {
		dbClient.getContext("coap://localhost:5683").setSeqMax(2);
		Token t1 = generateToken();
		Token t2 = generateToken();
		Token t3 = generateToken();
		// Test send
		try {
			sendRequest("coap://localhost:5683", dbClient, t1);
			sendRequest("coap://localhost:5683", dbClient, t2);
		} catch (OSException e) {
			e.printStackTrace();
		}
		try {
			sendRequest("coap://localhost:5683", dbClient, t3);
			fail("expected OSException");
		} catch (OSException e) {
		}
	}

	@Test
	public void testReceiveSequenceNumberWrap() throws OSException {

		Token t1 = generateToken();
		Token t2 = generateToken();
		Token t3 = generateToken();

		sendRequest(uriFull, dbClient, t1);
		sendRequest(uriFull, dbClient, t2);
		Request req = sendRequest(uriFull, dbClient, t3);

		dbClientToServer();
		serverCtx.setSeqMax(2);

		// Test receive
		boolean detectWrap = false;
		try {
			ObjectSecurityLayer.prepareReceive(dbServer, req, serverCtx);
		} catch (OSException e) {
			detectWrap = true;
		}
		assertTrue(detectWrap);
	}

	@Test
	public void testFakeCode() throws OSException {
		Token t1 = generateToken();
		Request request1 = sendRequest(uriFull, dbClient, t1);

		assertEquals(CoAP.Code.POST, request1.getCode());
	}

	private Request sendRequest(String uri, OSCoreCtxDB db, Token token) throws OSException {
		OSCoreCtx ctx = db.getContext(uri);
		Request request = Request.newPost().setURI(uri);
		request.setToken(token);
		db.addContext(token, ctx);
		request.getOptions().addOption(StandardOptionRegistry.OSCORE.create(Bytes.EMPTY));
		return ObjectSecurityLayer.prepareSend(db, request);
	}

	private boolean assertCtxState(OSCoreCtx ctx, int send, int receive) {
		boolean equal = true;
		if (ctx.getSenderSeq() != send)
			equal = false;
		if (ctx.getLowestRecipientSeq() != receive)
			equal = false;
		return equal;
	}

	private void dbClientToServer() throws OSException {
		dbClient.purge();
		dbClient.addContext(uriId, serverCtx);
	}

	private void dbServerToClient(Token token, Integer seq) throws OSException {
		dbClient.purge();
		dbClient.addContext(uriId, clientCtx);
		dbClient.addContext(token, clientCtx);
	}

	private Response sendResponse(String responsePayload, OSCoreCtx tid, Token token) throws OSException {

		Response response = null;

		if (responsePayload == null || responsePayload.length() <= 0) {
			response = new Response(CoAP.ResponseCode.VALID);
		} else {
			response = new Response(CoAP.ResponseCode.CONTENT);
			response.setPayload(responsePayload);
			response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		}
		response.getOptions().addOption(StandardOptionRegistry.OSCORE.create(Bytes.EMPTY));
		response.setToken(token);

		return ObjectSecurityLayer.prepareSend(null, response, tid, false, false, clientCtx.getSenderSeq());
	}

	public Token generateToken() {
		Token token;
		do {
			token = tokenGenerator.createToken(Scope.SHORT_TERM);
		} while (tokenExist(token));
		return token;
	}

	public boolean tokenExist(Token token) {
		return allTokens.contains(token);
	}
}
