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
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import java.io.IOException;
import java.util.Arrays;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.cose.CoseException;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.oscore.ContextRederivation.PHASE;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

/**
 * Class that implements test of functionality for re-derivation of contexts. As
 * detailed in Appendix B.2. of the OSCORE RFC:
 * https://tools.ietf.org/html/rfc8613#appendix-B.2
 *
 * This can for instance be used when one device has lost power and information
 * about the mutable parts of a context (e.g. sequence number) but retains
 * information about static parts (e.g. master secret)
 * 
 * This class tests both when the server initiates the context re-derivation
 * procedure and when it is the server that initiates it. Note that even when
 * the server initiates it, it is triggered by an incoming request from the
 * client.
 * 
 */
public class ContextRederivationTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);
	
	private CoapServer server;
	private Endpoint serverEndpoint;

	private static String SERVER_RESPONSE = "Hello World!";

	private final static HashMapCtxDB dbClient = new HashMapCtxDB();
	private final static HashMapCtxDB dbServer = new HashMapCtxDB();
	private final static String hello1 = "/hello";
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;

	// test vector OSCORE draft Appendix C.1.1
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	private final static byte[] sid = new byte[0];
	private final static byte[] rid = new byte[] { 0x01 };
	private final static byte[] context_id = { 0x74, 0x65, 0x73, 0x74, 0x74, 0x65, 0x73, 0x74 };

	private static int SEGMENT_LENGTH = ContextRederivation.SEGMENT_LENGTH;

	@Before
	public void initLogger() {
		System.out.println(System.lineSeparator() + "Start " + getClass().getSimpleName());
		EndpointManager.clear();
	}

	// Use the OSCORE stack factory with the client context DB
	@BeforeClass
	public static void setStackFactory() {
		OSCoreCoapStackFactory.useAsDefault(dbClient);
	}

	@After
	public void after() {
		if (null != server) {
			server.destroy();
		}
		System.out.println("End " + getClass().getSimpleName());
	}

	/**
	 * Test context re-derivation followed by a normal message exchange. This
	 * test simulates a client losing the mutable parts of the OSCORE context,
	 * and then explicitly initiating the context re-derivation procedure.
	 * 
	 * Note that the asserts in this test check things regarding request #2 and
	 * response #2 as request #1 and response #1 are taken care of in the OSCORE
	 * library code (so the application does not need to worry about them).
	 * 
	 * @throws OSException
	 * @throws ConnectorException
	 * @throws IOException
	 * @throws CoseException
	 * @throws InterruptedException
	 */
	@Test
	public void testClientInitiatedRederivation()
			throws OSException, ConnectorException, IOException, CoseException, InterruptedException {
		
		// Create a server that will not initiate the context re-derivation
		// procedure. (But perform the procedure if the client initiates.)
		createServer(false);

		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null);
		String serverUri = serverEndpoint.getUri().toASCIIString();

		// Enable context re-derivation functionality (in general)
		ctx.setContextRederivationEnabled(true);
		// Explicitly initiate the context re-derivation procedure
		ctx.setContextRederivationPhase(PHASE.CLIENT_INITIATE);

		dbClient.addContext(serverUri, ctx);

		CoapClient c = new CoapClient(serverUri + hello1);
		Request r = new Request(Code.GET);
		r.getOptions().setOscore(Bytes.EMPTY);
		RequestTestObserver requestTestObserver = new RequestTestObserver();
		r.addMessageObserver(requestTestObserver);
		CoapResponse resp = c.advanced(r);

		System.out.println((Utils.prettyPrint(resp)));

		OSCoreCtx currCtx = dbClient.getContext(serverUri);
		assertEquals(ContextRederivation.PHASE.INACTIVE, currCtx.getContextRederivationPhase()); // Phase
		assertFalse(currCtx.getIncludeContextId()); // Do not include Context ID

		// Length of Context ID in context (R2 || R3)
		int contextIdLen = currCtx.getIdContext().length;
		assertEquals(3 * SEGMENT_LENGTH, contextIdLen);
		// Check length of Context ID in the request (R2 || R3)
		assertEquals(3 * SEGMENT_LENGTH, requestTestObserver.requestIdContext.length);

		// Check R2 value derived by server using its key with received one
		// The R2 value is composed of S2 || HMAC(K_HMAC, S2).
		OSCoreCtx serverCtx = dbServer.getContext(sid);
		byte[] srvContextRederivationKey = serverCtx.getContextRederivationKey();
		byte[] contextS2 = Arrays.copyOfRange(currCtx.getIdContext(), 0, SEGMENT_LENGTH);
		byte[] hmacOutput = OSCoreCtx.deriveKey(srvContextRederivationKey, srvContextRederivationKey, SEGMENT_LENGTH,
				"SHA256", contextS2);
		byte[] messageHmacValue = Arrays.copyOfRange(currCtx.getIdContext(), SEGMENT_LENGTH, SEGMENT_LENGTH * 2);
		assertArrayEquals(hmacOutput, messageHmacValue);

		// Empty OSCORE option in response
		assertArrayEquals(Bytes.EMPTY, resp.getOptions().getOscore());

		assertEquals(ResponseCode.CONTENT, resp.getCode());
		assertEquals(SERVER_RESPONSE, resp.getResponseText());

		// 2nd request for testing
		r = new Request(Code.GET);
		r.getOptions().setOscore(Bytes.EMPTY);
		resp = c.advanced(r);
		System.out.println((Utils.prettyPrint(resp)));

		assertEquals(ResponseCode.CONTENT, resp.getCode());
		assertEquals(SERVER_RESPONSE, resp.getResponseText());

		resp = c.advanced(r);
		System.out.println((Utils.prettyPrint(resp)));

		c.shutdown();
	}

	/**
	 * Test context re-derivation followed by a normal message exchange. This
	 * test simulates a server losing the mutable parts of the OSCORE context.
	 * When a request from the client arrives this will initiate the context
	 * re-derivation procedure. Note that the client does not explicitly
	 * initiate the procedure before the request as it still has the context
	 * information. It does not know the server has lost this information.
	 * 
	 * Note that the asserts in this test check things regarding request #1 &
	 * response #1 and also response #2 as request #1. This is because in this
	 * case the client does not initially know that a context re-derivation
	 * procedure will take place. So the application code ends up explicitly
	 * sending both request #1 and request #2.
	 * 
	 * @throws OSException
	 * @throws ConnectorException
	 * @throws IOException
	 * @throws CoseException
	 * @throws InterruptedException
	 */
	@Test
	public void testServerInitiatedRederivation()
			throws OSException, ConnectorException, IOException, CoseException, InterruptedException {

		// Create a server that will initiate the context re-derivation (on
		// reception of a request)
		createServer(true);

		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, context_id);
		// Enable context re-derivation functionality (for client)
		ctx.setContextRederivationEnabled(true);
		String serverUri = serverEndpoint.getUri().toASCIIString();
		dbClient.addContext(serverUri, ctx);

		// Create first request (for request #1 and response #1 exchange)
		CoapClient c = new CoapClient(serverUri + hello1);
		Request r = new Request(Code.GET);
		r.getOptions().setOscore(Bytes.EMPTY);
		RequestTestObserver requestTestObserver = new RequestTestObserver();
		r.addMessageObserver(requestTestObserver);
		CoapResponse resp = c.advanced(r);

		System.out.println((Utils.prettyPrint(resp)));

		OSCoreCtx currCtx = dbClient.getContext(serverUri);
		assertEquals(ContextRederivation.PHASE.CLIENT_PHASE_2, currCtx.getContextRederivationPhase()); // Phase
		assertFalse(currCtx.getIncludeContextId()); // Do not include Context ID

		// Length of Context ID in context (R2 || ID1)
		int contextIdLen = currCtx.getIdContext().length;
		assertEquals(3 * SEGMENT_LENGTH, contextIdLen);
		// Check length of Context ID in the request (ID1)
		assertEquals(1 * SEGMENT_LENGTH, requestTestObserver.requestIdContext.length);

		// Check R2 value derived by server using its key with received one
		// The R2 value is composed of S2 || HMAC(K_HMAC, S2).
		OSCoreCtx serverCtx = dbServer.getContext(sid);
		byte[] srvContextRederivationKey = serverCtx.getContextRederivationKey();
		byte[] contextS2 = Arrays.copyOfRange(currCtx.getIdContext(), 0, SEGMENT_LENGTH);
		byte[] hmacOutput = OSCoreCtx.deriveKey(srvContextRederivationKey, srvContextRederivationKey, SEGMENT_LENGTH,
				"SHA256", contextS2);
		byte[] messageHmacValue = Arrays.copyOfRange(currCtx.getIdContext(), SEGMENT_LENGTH, SEGMENT_LENGTH * 2);

		// The OSCORE option in the response should include the correct R2 value
		byte[] contextR2 = Bytes.concatenate(contextS2, hmacOutput);
		byte[] oscoreOption = resp.getOptions().getOscore();
		byte[] oscoreOptionR2 = Arrays.copyOfRange(oscoreOption, oscoreOption.length - 2 * SEGMENT_LENGTH,
				oscoreOption.length);
		assertArrayEquals(contextR2, oscoreOptionR2);
		assertArrayEquals(hmacOutput, messageHmacValue);

		assertEquals(ResponseCode.CONTENT, resp.getCode());
		assertEquals(SERVER_RESPONSE, resp.getResponseText());

		// 2nd request (for request #2 and response #2 exchange)
		r = new Request(Code.GET);
		r.getOptions().setOscore(Bytes.EMPTY);
		requestTestObserver = new RequestTestObserver();
		r.addMessageObserver(requestTestObserver);
		resp = c.advanced(r);
		System.out.println((Utils.prettyPrint(resp)));

		currCtx = dbClient.getContext(serverUri);
		assertEquals(ContextRederivation.PHASE.INACTIVE, currCtx.getContextRederivationPhase()); // Phase
		assertFalse(currCtx.getIncludeContextId()); // Do not include Context ID

		// Length of Context ID in context (R2 || R3)
		contextIdLen = currCtx.getIdContext().length;
		assertEquals(3 * SEGMENT_LENGTH, contextIdLen);
		// Check length of Context ID in the request (R2 || R3)
		assertEquals(3 * SEGMENT_LENGTH, requestTestObserver.requestIdContext.length);

		// Check R2 value derived by server using its key with received one
		// The R2 value is composed of S2 || HMAC(K_HMAC, S2).
		serverCtx = dbServer.getContext(sid);
		srvContextRederivationKey = serverCtx.getContextRederivationKey();
		contextS2 = Arrays.copyOfRange(currCtx.getIdContext(), 0, SEGMENT_LENGTH);
		hmacOutput = OSCoreCtx.deriveKey(srvContextRederivationKey, srvContextRederivationKey, SEGMENT_LENGTH, "SHA256",
				contextS2);
		messageHmacValue = Arrays.copyOfRange(currCtx.getIdContext(), SEGMENT_LENGTH, SEGMENT_LENGTH * 2);
		assertArrayEquals(hmacOutput, messageHmacValue);

		// Empty OSCORE option in response
		assertArrayEquals(Bytes.EMPTY, resp.getOptions().getOscore());

		assertEquals(ResponseCode.CONTENT, resp.getCode());
		assertEquals(SERVER_RESPONSE, resp.getResponseText());

		c.shutdown();
	}

	/**
	 * Message observer that will save the ID Context used in the outgoing
	 * request from the client for comparison.
	 *
	 */
	private static class RequestTestObserver extends MessageObserverAdapter {

		public byte[] requestIdContext;

		@Override
		public void onContextEstablished(EndpointContext endpointContext) {
			requestIdContext = StringUtil
					.hex2ByteArray(endpointContext.getString(OSCoreEndpointContextInfo.OSCORE_CONTEXT_ID));
		}
	}

	/**
	 * Creates server with resources for test
	 * 
	 * @param initiateRederivation if the server will initiate the context
	 *            re-derivation procedure
	 * 
	 * @throws InterruptedException if resource update task fails
	 * @throws OSException
	 */
	public void createServer(boolean initiateRederivation) throws InterruptedException, OSException {

		// Purge any old existing values from the server context database
		dbServer.purge();

		//Do not create server if it is already running
		if(server != null) {
			return;
		}

		byte[] contextId = null;
		if (initiateRederivation) {
			contextId = context_id;
		}

		//Set up OSCORE context information for response (server)
		byte[] sid = new byte[] { 0x01 };
		byte[] rid = new byte[0];
		OSCoreCtx ctx = new OSCoreCtx(master_secret, false, alg, sid, rid, kdf, 32, master_salt, contextId);
		String clientUri = "coap://" + TestTools.LOCALHOST_EPHEMERAL.getAddress().getHostAddress();

		// Enable context re-derivation functionality in general
		ctx.setContextRederivationEnabled(true);

		// If the server is to initiate the context re-derivation procedure, set
		// accordingly in the context
		if (initiateRederivation) {
			ctx.setContextRederivationPhase(PHASE.SERVER_INITIATE);
		}

		dbServer.addContext(clientUri, ctx);

		//Create server
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCustomCoapStackArgument(dbServer);
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		serverEndpoint = builder.build();
		server = new CoapServer();
		server.addEndpoint(serverEndpoint);

		/** --- Resources for tests follow --- **/

		//Create Hello World-resource
		OSCoreResource hello = new OSCoreResource("hello", true) {

			@Override
			public void handleGET(CoapExchange exchange) {
				System.out.println("Accessing hello resource");
				Response r = new Response(ResponseCode.CONTENT);
				r.setPayload(SERVER_RESPONSE);
				exchange.respond(r);
			}
		};
		
		//Creating resource hierarchy
		server.add(hello);

		/** --- End of resources for tests **/

		//Start server
		server.start();
	}
}
