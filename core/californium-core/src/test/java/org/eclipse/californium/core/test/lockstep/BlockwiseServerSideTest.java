/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import static org.eclipse.californium.core.coap.CoAP.Code.GET;
import static org.eclipse.californium.core.coap.CoAP.Code.POST;
import static org.eclipse.californium.core.coap.CoAP.Code.PUT;
import static org.eclipse.californium.core.coap.OptionNumberRegistry.OBSERVE;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CHANGED;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTINUE;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.REQUEST_ENTITY_INCOMPLETE;
import static org.eclipse.californium.core.coap.CoAP.Type.ACK;
import static org.eclipse.californium.core.coap.CoAP.Type.CON;
import static org.eclipse.californium.core.coap.CoAP.Type.NON;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Random;

import org.junit.Assert;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.test.EndpointSurveillant;
import org.eclipse.californium.core.test.BlockwiseTransferTest.ServerBlockwiseInterceptor;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;


/**
 * This test implements all examples from the blockwise draft 14 for a server.
 */
public class BlockwiseServerSideTest {
	public static final int TEST_EXCHANGE_LIFETIME = 247; // 0.247 seconds
	public static final int TEST_SWEEP_DEDUPLICATOR_INTERVAL = 100; // 1 second

	private static boolean RANDOM_PAYLOAD_GENERATION = true;
	
	private CoapServer server;
	private EndpointSurveillant serverSurveillant;
	private int serverPort;
	
	private int mid = 7000;
	
	private TestResource testResource;
	private String respPayload;
	private String reqtPayload;
	
	private ServerBlockwiseInterceptor serverInterceptor = new ServerBlockwiseInterceptor();
	
	@Before
	public void setupServer() {
		System.out.println("\nStart "+getClass().getSimpleName());

		LockstepEndpoint.DEFAULT_VERBOSE = false;		
		
		testResource = new TestResource("test");
		
		NetworkConfig config = new NetworkConfig()
			.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 128)
			.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 128)
			.setInt(NetworkConfig.Keys.BLOCKWISE_STATUS_LIFETIME, 100)
			.setInt(NetworkConfig.Keys.MARK_AND_SWEEP_INTERVAL, TEST_EXCHANGE_LIFETIME)
			.setLong(NetworkConfig.Keys.EXCHANGE_LIFETIME, TEST_SWEEP_DEDUPLICATOR_INTERVAL);
		server = new CoapServer(config, 0);
		server.add(testResource);
		server.getEndpoints().get(0).addInterceptor(serverInterceptor);
		
		serverSurveillant = new EndpointSurveillant("server", (CoapEndpoint) (server.getEndpoints().get(0)));
		
		server.start();
		serverPort = server.getEndpoints().get(0).getAddress().getPort();
		System.out.println("Server binds to port "+serverPort);
	}
	
	@After
	public void shutdownServer() {
		System.out.println();
		server.destroy();
		System.out.println("End "+getClass().getSimpleName());
	}
	
	@Test
	public void test() throws Throwable {
		try {
			testGET();
			testIncompleteGET();
			testGETEarlyNegotion();
			testGETLateNegotion();
			testGETLateNegotionalLostACK();
			testSimpleAtomicBlockwisePUT();
			testSimpleAtomicBlockwisePUTWithLostAck();
			testSimpleAtomicBlockwisePUTWithRestartOfTransfer();
			testAtomicBlockwisePOSTWithBlockwiseResponse();
			testAtomicBlockwisePOSTWithBlockwiseResponseLateNegotiation();
			testAtomicBlockwisePOSTWithBlockwiseResponseEarlyNegotiation();
			testRandomAccessPUTAttemp();
			testRandomAccessGET();
			testObserveWithBlockwiseResponse();
			testObserveWithBlockwiseResponseEarlyNegotiation();
			
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		} catch (Throwable t) {
			System.err.println(t);
			throw t;
		}
	}
	
	/**
	 * The first example shows a GET request that is split into three blocks.
	 * The server proposes a block size of 128, and the client agrees. The first
	 * two ACKs contain 128 bytes of payload each, and third ACK contains
	 * between 1 and 128 bytes.
	 * <pre>
	 * CLIENT                                                     SERVER
     * |                                                            |
     * | CON [MID=1234], GET, /status                       ------> |
     * |                                                            |
     * | <------   ACK [MID=1234], 2.05 Content, 2:0/1/128          |
     * |                                                            |
     * | CON [MID=1235], GET, /status, 2:1/0/128            ------> |
     * |                                                            |
     * | <------   ACK [MID=1235], 2.05 Content, 2:1/1/128          |
     * |                                                            |
     * | CON [MID=1236], GET, /status, 2:2/0/128            ------> |
     * |                                                            |
     * | <------   ACK [MID=1236], 2.05 Content, 2:2/0/128          |
     * </pre>
	 */
	private void testGET() throws Exception {
		System.out.println("Simple blockwise GET:");
		respPayload = generatePayload(300);
		byte[] tok = generateNextToken();
		String path = "test";
		
		LockstepEndpoint client = createLockstepEndpoint();
		client.sendRequest(CON, GET, tok, ++mid).path(path).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, 128).payload(respPayload.substring(0, 128)).go();
		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(1, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(1, true, 128).payload(respPayload.substring(128, 256)).go();
		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(2, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(2, false,  128).payload(respPayload.substring(256,300)).go();
		
		printServerLog();
	}
	
	/**
	 * 
	 */
	private void testIncompleteGET() throws Exception {
		System.out.println("Incomplete blockwise GET:");
		respPayload = generatePayload(300);
		byte[] tok = generateNextToken();
		String path = "test";
		
		LockstepEndpoint client = createLockstepEndpoint();
		client.sendRequest(CON, GET, tok, ++mid).path(path).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, 128).payload(respPayload.substring(0, 128)).go();
		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(1, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(1, true, 128).payload(respPayload.substring(128, 256)).go();
		serverInterceptor.log("\n//////// Missing last GET ////////");
		
		serverSurveillant.waitUntilDeduplicatorShouldBeEmpty();
		
		printServerLog();
		
		serverSurveillant.assertHashMapsEmpty();
		
	}
	
	/**
	 * In the second example, the client anticipates the blockwise transfer
	 * (e.g., because of a size indication in the link- format description
	 * [RFC6690]) and sends a size proposal. All ACK messages except for the
	 * last carry 64 bytes of payload; the last one carries between 1 and 64
	 * bytes.
	 * <pre>
	 * CLIENT                                                     SERVER
	 * |                                                          |
	 * | CON [MID=1234], GET, /status, 2:0/0/64           ------> |
	 * |                                                          |
	 * | <------   ACK [MID=1234], 2.05 Content, 2:0/1/64         |
	 * |                                                          |
	 * | CON [MID=1235], GET, /status, 2:1/0/64           ------> |
	 * |                                                          |
	 * | <------   ACK [MID=1235], 2.05 Content, 2:1/1/64         |
	 * :                                                          :
	 * :                          ...                             :
	 * :                                                          :
	 * | CON [MID=1238], GET, /status, 2:4/0/64           ------> |
	 * |                                                          |
	 * | <------   ACK [MID=1238], 2.05 Content, 2:4/1/64         |
	 * |                                                          |
	 * | CON [MID=1239], GET, /status, 2:5/0/64           ------> |
	 * |                                                          |
	 * | <------   ACK [MID=1239], 2.05 Content, 2:5/0/64         |
	 * </pre>
	 */
	private void testGETEarlyNegotion() throws Exception {
		System.out.println("Blockwise GET with early negotiation");
		respPayload = generatePayload(350);
		byte[] tok = generateNextToken();
		String path = "test";
		
		LockstepEndpoint client = createLockstepEndpoint();
		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(0, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, 64).payload(respPayload.substring(0, 64)).go();
		
		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(1, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(1, true, 64).payload(respPayload.substring(64, 128)).go();
		
		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(2, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(2, true, 64).payload(respPayload.substring(128, 192)).go();
		
		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(3, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(3, true, 64).payload(respPayload.substring(192, 256)).go();
		
		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(4, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(4, true, 64).payload(respPayload.substring(256, 320)).go();
		
		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(5, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(5, false,  64).payload(respPayload.substring(320,350)).go();
		
		printServerLog();
	}
	
	/**
	 * In the third example, the client is surprised by the need for a blockwise
	 * transfer, and unhappy with the size chosen unilaterally by the server. As
	 * it did not send a size proposal initially, the negotiation only
	 * influences the size from the second message exchange onward. Since the
	 * client already obtained both the first and second 64-byte block in the
	 * first 128-byte exchange, it goes on requesting the third 64-byte block
	 * ("2/0/64"). None of this is (or needs to be) understood by the server,
	 * which simply responds to the requests as it best can.
	 * <pre>
	 * CLIENT                                                     SERVER
     * |                                                          |
     * | CON [MID=1234], GET, /status                     ------> |
     * |                                                          |
     * | <------   ACK [MID=1234], 2.05 Content, 2:0/1/128        |
     * |                                                          |
     * | CON [MID=1235], GET, /status, 2:2/0/64           ------> |
     * |                                                          |
     * | <------   ACK [MID=1235], 2.05 Content, 2:2/1/64         |
     * |                                                          |
     * | CON [MID=1236], GET, /status, 2:3/0/64           ------> |
     * |                                                          |
     * | <------   ACK [MID=1236], 2.05 Content, 2:3/1/64         |
     * |                                                          |
     * | CON [MID=1237], GET, /status, 2:4/0/64           ------> |
     * |                                                          |
     * | <------   ACK [MID=1237], 2.05 Content, 2:4/1/64         |
     * |                                                          |
     * | CON [MID=1238], GET, /status, 2:5/0/64           ------> |
     * |                                                          |
     * | <------   ACK [MID=1238], 2.05 Content, 2:5/0/64         |
     * </pre>
	 */
	private void testGETLateNegotion() throws Exception {
		System.out.println("Blockwise GET with late negotiation:");
		respPayload = generatePayload(350);
		byte[] tok = generateNextToken();
		String path = "test";
		
		LockstepEndpoint client = createLockstepEndpoint();
		client.sendRequest(CON, GET, tok, ++mid).path(path).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, 128).payload(respPayload.substring(0, 128)).go();
		
		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(2, false, 64).go(); // late negotiation
		client.expectResponse(ACK, CONTENT, tok, mid).block2(2, true, 64).payload(respPayload.substring(128, 192)).go();
		
		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(3, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(3, true, 64).payload(respPayload.substring(192, 256)).go();
		
		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(4, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(4, true, 64).payload(respPayload.substring(256, 320)).go();
		
		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(5, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(5, false,  64).payload(respPayload.substring(320,350)).go();
		
		printServerLog();
	}
	
	/**
	 * <pre>
	 * CLIENT                                                     SERVER
     * |                                                          |
     * | CON [MID=1234], GET, /status                     ------> |
     * |                                                          |
     * | <------   ACK [MID=1234], 2.05 Content, 2:0/1/128        |
     * |                                                          |
     * | CON [MID=1235], GET, /status, 2:2/0/64           ------> |
     * |                                                          |
     * | //////////////////////////////////tent, 2:2/1/64         |
     * |                                                          |
     * | (timeout)                                                |
     * |                                                          |
     * | CON [MID=1235], GET, /status, 2:2/0/64           ------> |
     * |                                                          |
     * | <------   ACK [MID=1235], 2.05 Content, 2:2/1/64         |
     * :                                                          :
     * :                          ...                             :
     * :                                                          :
     * | CON [MID=1238], GET, /status, 2:5/0/64           ------> |
     * |                                                          |
     * | <------   ACK [MID=1238], 2.05 Content, 2:5/0/64         |
     * </pre>
	 */
	private void testGETLateNegotionalLostACK() throws Exception {
		System.out.println("Blockwise GET with late negotiation and lost ACK:");
		respPayload = generatePayload(220);
		byte[] tok = generateNextToken();
		String path = "test";
		
		LockstepEndpoint client = createLockstepEndpoint();
		client.sendRequest(CON, GET, tok, ++mid).path(path).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, 128).payload(respPayload.substring(0, 128)).go();
		
		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(2, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(2, true, 64).payload(respPayload.substring(128, 192)).go();
		// We lose this ACK, and therefore retransmit the CON
		serverInterceptor.log(" // lost");
		client.sendRequest(CON, GET, tok, mid).path(path).block2(2, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(2, true, 64).payload(respPayload.substring(128, 192)).go();
		
		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(3, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(3, false, 64).payload(respPayload.substring(192, 220)).go();
		
		printServerLog();
	}
	
	/**
	 * The following examples demonstrate a PUT exchange; a POST exchange looks
	 * the same, with different requirements on atomicity/idempotence. Note
	 * that, similar to GET, the responses to the requests that have a more bit
	 * in the request Block1 Option are provisional and carry the response code
	 * 2.31 (Continue); only the final response tells the client that the PUT
	 * did succeed.
	 * <pre>
	 * CLIENT                                                     SERVER
     * |                                                          |
     * | CON [MID=1234], PUT, /options, 1:0/1/128    ------>      |
     * |                                                          |
     * | <------   ACK [MID=1234], 2.31 Continue, 1:0/1/128       |
     * |                                                          |
     * | CON [MID=1235], PUT, /options, 1:1/1/128    ------>      |
     * |                                                          |
     * | <------   ACK [MID=1235], 2.31 Continue, 1:1/1/128       |
     * |                                                          |
     * | CON [MID=1236], PUT, /options, 1:2/0/128    ------>      |
     * |                                                          |
     * | <------   ACK [MID=1236], 2.04 Changed, 1:2/0/128        |
	 * </pre>
	 */
	private void testSimpleAtomicBlockwisePUT() throws Exception {
		System.out.println("Simple atomic blockwise PUT");
		respPayload = generatePayload(50);
		byte[] tok = generateNextToken();
		String path = "test";
		reqtPayload = generatePayload(300);

		LockstepEndpoint client = createLockstepEndpoint();
		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(0, true, 128).payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).payload("").go();
		
		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(1, true, 128).payload(reqtPayload.substring(128, 256)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(1, true, 128).payload("").go();
		
		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(2, false, 128).payload(reqtPayload.substring(256, 300)).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block1(2, false, 128).payload(respPayload).go();
		
		printServerLog();
	}
	
	private void testSimpleAtomicBlockwisePUTWithLostAck() throws Exception {
		System.out.println("Simple atomic blockwise PUT with lost ACK");
		respPayload = generatePayload(50);
		byte[] tok = generateNextToken();
		String path = "test";
		reqtPayload = generatePayload(300);

		LockstepEndpoint client = createLockstepEndpoint();
		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(0, true, 128).payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).payload("").go();
		serverInterceptor.log("// lost");
		// ACK goes lost => retransmission
		client.sendRequest(CON, PUT, tok, mid).path(path).block1(0, true, 128).payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).payload("").go();
		
		// and continue normally
		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(1, true, 128).payload(reqtPayload.substring(128, 256)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(1, true, 128).payload("").go();
		
		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(2, false, 128).payload(reqtPayload.substring(256, 300)).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block1(2, false, 128).payload(respPayload).go();
		
		printServerLog();
	}
	
	private void testSimpleAtomicBlockwisePUTWithRestartOfTransfer() throws Exception {
		System.out.println("Simple atomic blockwise PUT restart of the blockwise transfer");
		respPayload = generatePayload(50);
		byte[] tok = generateNextToken();
		String path = "test";
		reqtPayload = generatePayload(300);

		LockstepEndpoint client = createLockstepEndpoint();
		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(0, true, 128).payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).payload("").go();
		
		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(1, true, 128).payload(reqtPayload.substring(128, 256)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(1, true, 128).payload("").go();
		
		serverInterceptor.log("\n... client crashes or whatever and restarts transfer");
		
		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(0, true, 128).payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).payload("").go();
		
		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(1, true, 128).payload(reqtPayload.substring(128, 256)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(1, true, 128).payload("").go();
		
		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(2, false, 128).payload(reqtPayload.substring(256, 300)).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block1(2, false, 128).payload(respPayload).go();
		
		printServerLog();
	}
	
	/**
	 * Block options may be used in both directions of a single exchange. The
	 * following example demonstrates a blockwise POST request, resulting in a
	 * separate blockwise response.
	 * <pre>
	 * CLIENT                                                     SERVER
     * |                                                              |
     * | CON [MID=1234], POST, /soap, 1:0/1/128      ------>          |
     * |                                                              |
     * | <------   ACK [MID=1234], 2.31 Continue, 1:0/1/128           |
     * |                                                              |
     * | CON [MID=1235], POST, /soap, 1:1/1/128      ------>          |
     * |                                                              |
     * | <------   ACK [MID=1235], 2.31 Continue, 1:1/1/128           |
     * |                                                              |
     * | CON [MID=1236], POST, /soap, 1:2/0/128      ------>          |
     * |                                                              |
     * | <------   ACK [MID=1236], 2.04 Changed, 2:0/1/128, 1:2/0/128 |
     * |                                                              |
     * | CON [MID=1237], POST, /soap, 2:1/0/128      ------>          |
     * |                                                              |
     * | <------   ACK [MID=1237], 2.04 Changed, 2:1/1/128            |
     * |                                                              |
     * | CON [MID=1238], POST, /soap, 2:2/0/128      ------>          |
     * |                                                              |
     * | <------   ACK [MID=1238], 2.04 Changed, 2:2/1/128            |
     * |                                                              |
     * | CON [MID=1239], POST, /soap, 2:3/0/128      ------>          |
     * |                                                              |
     * | <------   ACK [MID=1239], 2.04 Changed, 2:3/0/128            |
	 * </pre>
	 */
	private void testAtomicBlockwisePOSTWithBlockwiseResponse() throws Exception {
		System.out.println("Atomic blockwise POST with blockwise response:");
		respPayload = generatePayload(500);
		byte[] tok = generateNextToken();
		String path = "test";
		reqtPayload = generatePayload(300);

		LockstepEndpoint client = createLockstepEndpoint();
		client.sendRequest(CON, POST, tok, ++mid).path(path).block1(0, true, 128).payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).go();
		
		client.sendRequest(CON, POST, tok, ++mid).path(path).block1(1, true, 128).payload(reqtPayload.substring(128, 256)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(1, true, 128).go();
		
		client.sendRequest(CON, POST, tok, ++mid).path(path).block1(2, false, 128).payload(reqtPayload.substring(256, 300)).go();
		client.expectResponse(ACK, CHANGED, tok, mid).payload(respPayload.substring(0, 128))
				.block1(2, false, 128).block2(0, true, 128).go();
		
		client.sendRequest(CON, POST, tok, ++mid).path(path).block2(1, false, 128).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block2(1, true, 128).payload(respPayload.substring(128, 256)).go();
		
		client.sendRequest(CON, POST, tok, ++mid).path(path).block2(2, false, 128).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block2(2, true, 128).payload(respPayload.substring(256, 384)).go();
		
		client.sendRequest(CON, POST, tok, ++mid).path(path).block2(3, false, 128).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block2(3, false, 128).payload(respPayload.substring(384, 500)).go();
		
		printServerLog();
	}

	/**
	 * The above example with late negotiation by requesting e.g. 2:2/0/64.
	 */
	private void testAtomicBlockwisePOSTWithBlockwiseResponseLateNegotiation() throws Exception {
		System.out.println("Atomic blockwise POST with blockwise response:");
		respPayload = generatePayload(300);
		byte[] tok = generateNextToken();
		String path = "test";
		reqtPayload = generatePayload(300);

		LockstepEndpoint client = createLockstepEndpoint();
		client.sendRequest(CON, POST, tok, ++mid).path(path).block1(0, true, 128).payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).go();
		
		client.sendRequest(CON, POST, tok, ++mid).path(path).block1(1, true, 128).payload(reqtPayload.substring(128, 256)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(1, true, 128).go();
		
		client.sendRequest(CON, POST, tok, ++mid).path(path).block1(2, false, 128).payload(reqtPayload.substring(256, 300)).go();
		client.expectResponse(ACK, CHANGED, tok, mid).payload(respPayload.substring(0, 128))
				.block1(2, false, 128).block2(0, true, 128).go();
		
		client.sendRequest(CON, POST, tok, ++mid).path(path).block2(2, false, 64).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block2(2, true, 64).payload(respPayload.substring(128, 192)).go();
		serverInterceptor.log("// late negotiation");
		
		client.sendRequest(CON, POST, tok, ++mid).path(path).block2(3, false, 64).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block2(3, true, 64).payload(respPayload.substring(192, 256)).go();
		
		client.sendRequest(CON, POST, tok, ++mid).path(path).block2(4, false, 64).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block2(4, false, 64).payload(respPayload.substring(256, 300)).go();
		
		printServerLog();
	}
	
	/**
	 * This model does provide for early negotiation input to the Block2
	 * blockwise transfer, as shown below.
	 * <pre>
	 *    CLIENT                                                     SERVER
	 *      |                                                              |
	 *      | CON [MID=1234], POST, /soap, 1:0/1/128 ------>               |
	 *      |                                                              |
	 *      | <------   ACK [MID=1234], 2.31 Continue, 1:0/1/128           |
	 *      |                                                              |
	 *      | CON [MID=1235], POST, /soap, 1:1/1/128 ------>               |
	 *      |                                                              |
	 *      | <------   ACK [MID=1235], 2.31 Continue, 1:1/1/128           |
	 *      |                                                              |
	 *      | CON [MID=1236], POST, /soap, 1:2/0/128, 2:0/0/64 ------>     |
	 *      |                                                              |
	 *      | <------   ACK [MID=1236], 2.04 Changed, 1:2/0/128, 2:0/1/64 |
	 *      |                                                              |
	 *      | CON [MID=1237], POST, /soap, 2:1/0/64      ------>           |
	 *      | (no payload for requests with Block2 with NUM != 0)          |
	 *      |                                                              |
	 *      | <------   ACK [MID=1237], 2.04 Changed, 2:1/1/64             |
	 *      |                                                              |
	 *      | CON [MID=1238], POST, /soap, 2:2/0/64      ------>           |
	 *      |                                                              |
	 *      | <------   ACK [MID=1238], 2.04 Changed, 2:2/1/64             |
	 *      |                                                              |
	 *      | CON [MID=1239], POST, /soap, 2:3/0/64      ------>           |
	 *      |                                                              |
	 *      | <------   ACK [MID=1239], 2.04 Changed, 2:3/0/64             |
	 * </pre>
	 */
	private void testAtomicBlockwisePOSTWithBlockwiseResponseEarlyNegotiation() throws Exception {
		System.out.println("Atomic blockwise POST with blockwise response:");
		respPayload = generatePayload(250);
		byte[] tok = generateNextToken();
		String path = "test";
		reqtPayload = generatePayload(300);

		LockstepEndpoint client = createLockstepEndpoint();
		client.sendRequest(CON, POST, tok, ++mid).path(path).block1(0, true, 128).payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).go();
		
		client.sendRequest(CON, POST, tok, ++mid).path(path).block1(1, true, 128).payload(reqtPayload.substring(128, 256)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(1, true, 128).go();
		
		client.sendRequest(CON, POST, tok, ++mid).path(path).payload(reqtPayload.substring(256, 300))
				.block1(2, false, 128).block2(0, false, 64).go();
		client.expectResponse(ACK, CHANGED, tok, mid).payload(respPayload.substring(0, 64))
				.block1(2, false, 128).block2(0, true, 64).go();
		serverInterceptor.log("// early negotiation");
		
		client.sendRequest(CON, POST, tok, ++mid).path(path).block2(1, false, 64).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block2(1, true, 64).payload(respPayload.substring(64, 128)).go();
		
		client.sendRequest(CON, POST, tok, ++mid).path(path).block2(2, false, 64).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block2(2, true, 64).payload(respPayload.substring(128, 192)).go();
		
		client.sendRequest(CON, POST, tok, ++mid).path(path).block2(3, false, 64).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block2(3, false, 64).payload(respPayload.substring(192, 250)).go();
		
		printServerLog();
	}
	
	private void testRandomAccessPUTAttemp() throws Exception {
		System.out.println("Random access PUT attempt: (try to put block 2 first is now allowed)");
		respPayload = generatePayload(50);
		reqtPayload = generatePayload(300);
		byte[] tok = generateNextToken();
		String path = "test";
		
		LockstepEndpoint client = createLockstepEndpoint();
		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(2, true, 64).payload(reqtPayload.substring(2*64, 3*64)).go();
		client.expectResponse(ACK, REQUEST_ENTITY_INCOMPLETE, tok, mid).block1(2, true, 64).go();

		printServerLog();
	}
	
	private void testRandomAccessGET() throws Exception {
		System.out.println("Random access GET: (only access block 2 and 4 of response)");
		respPayload = generatePayload(300);
		byte[] tok = generateNextToken();
		String path = "test";
		
		LockstepEndpoint client = createLockstepEndpoint();
		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(2, true, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(2, true, 64).payload(respPayload.substring(2*64, 3*64)).go();

		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(4, true, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(4, false, 64).payload(respPayload.substring(4*64, 300)).go();
		
		printServerLog();
	}
	
	private void testObserveWithBlockwiseResponse() throws Exception {
		System.out.println("Observe sequence with blockwise response:");
		respPayload = generatePayload(300);
		byte[] tok = generateNextToken();
		String path = "test1";
		TestResource test1 = new TestResource(path);
		test1.setObservable(true);
		server.add(test1);
		
		/*
		 * Notice that only the first GET request contains the observe option
		 * but not the GET requests for the remaining blocks of the transfer.
		 * I do not yet know, if all response blocks are allowed to have an
		 * observe option if the client uses the same token or only the first
		 * block.
		 * Currently, Cf does not understand the following code as one exchange
		 * because, we change the token in the middle. After the server sends 
		 * the first block of the notification the consequent request with a new
		 * token looks like a random access GET request to the server. There is
		 * no way for the server to differentiate these cases.
		 */
		System.out.println("Establish observe relation to "+path);
		
		LockstepEndpoint client = createLockstepEndpoint();
		client.sendRequest(CON, GET, tok, ++mid).path(path).observe(0).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, 128).observe(0).block2(0, true, 128).payload(respPayload.substring(0, 128)).go();

		byte[] tok1 = generateNextToken();
		client.sendRequest(CON, GET, tok1, ++mid).path(path).block2(1, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok1, mid).block2(1, true, 128).noOption(OBSERVE).payload(respPayload.substring(128, 256)).go();

		client.sendRequest(CON, GET, tok1, ++mid).path(path).block2(2, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok1, mid).block2(2, false, 128).noOption(OBSERVE).payload(respPayload.substring(256, 300)).go();

		serverInterceptor.log("\n... time passes ...");
		System.out.println("Send first notification");
		respPayload = generatePayload(280);
		test1.changed();
		
		client.expectResponse().responseType("T", CON, NON).code(CONTENT).token(tok).storeMID("A").observe(1).block2(0, true, 128).payload(respPayload.substring(0, 128)).go();
		if (client.get("T") == CON)
			client.sendEmpty(ACK).loadMID("A").go();

		byte[] tok2 = generateNextToken();
		client.sendRequest(CON, GET, tok2, ++mid).path(path).block2(1, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok2, mid).block2(1, true, 128).noOption(OBSERVE).payload(respPayload.substring(128, 256)).go();
		
		client.sendRequest(CON, GET, tok2, ++mid).path(path).block2(2, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok2, mid).block2(2, false, 128).noOption(OBSERVE).payload(respPayload.substring(256, 280)).go();
		
		System.out.println("Send second notification");
		serverInterceptor.log("\n... time passes ...");
		respPayload = generatePayload(290);
		test1.changed();
		
		client.expectResponse().responseType("T", CON, NON).code(CONTENT).token(tok).storeMID("A").observe(2).block2(0, true, 128).payload(respPayload.substring(0, 128)).go();
		if (client.get("T") == CON)
			client.sendEmpty(ACK).loadMID("A").go();

		byte[] tok3 = generateNextToken();
		client.sendRequest(CON, GET, tok3, ++mid).path(path).block2(1, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok3, mid).block2(1, true, 128).noOption(OBSERVE).payload(respPayload.substring(128, 256)).go();
		
		client.sendRequest(CON, GET, tok3, ++mid).path(path).block2(2, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok3, mid).block2(2, false, 128).noOption(OBSERVE).payload(respPayload.substring(256, 290)).go();
		
		printServerLog();
	}
	
	private void testObserveWithBlockwiseResponseEarlyNegotiation() throws Exception {
		System.out.println("Observe sequence with early negotiation:");
		respPayload = generatePayload(150);
		byte[] tok = generateNextToken();
		String path = "test2";
		TestResource test2 = new TestResource(path);
		test2.setObservable(true);
		server.add(test2);
		System.out.println("Establish observe relation to "+path);
		
		LockstepEndpoint client = createLockstepEndpoint();
		client.sendRequest(CON, GET, tok, ++mid).path(path).observe(0).block2(0, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, 64).observe(0).block2(0, true, 64).payload(respPayload.substring(0, 64)).go();
		
		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(1, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(1, true, 64).noOption(OBSERVE).payload(respPayload.substring(64, 128)).go();

		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(2, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(2, false, 64).noOption(OBSERVE).payload(respPayload.substring(128, 150)).go();
		
		System.out.println("Send first notification");
		serverInterceptor.log("\n... time passes ...");
		respPayload = generatePayload(140);
		test2.changed(); // First notification
		
		client.expectResponse().responseType("T", CON, NON).code(CONTENT).token(tok).storeMID("A").observe(1).block2(0, true, 64).payload(respPayload.substring(0, 64)).go();
		if (client.get("T") == CON)
			client.sendEmpty(ACK).loadMID("A").go();

		byte[] tok2 = generateNextToken();
		client.sendRequest(CON, GET, tok2, ++mid).path(path).block2(1, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok2, mid).block2(1, true, 64).noOption(OBSERVE).payload(respPayload.substring(64, 128)).go();
		
		client.sendRequest(CON, GET, tok2, ++mid).path(path).block2(2, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok2, mid).block2(2, false, 64).noOption(OBSERVE).payload(respPayload.substring(128, 140)).go();
		
		System.out.println("Send second notification");
		serverInterceptor.log("\n... time passes ...");
		respPayload = generatePayload(145);
		test2.changed(); // Second notification
		
		client.expectResponse().responseType("T", CON, NON).code(CONTENT).token(tok).storeMID("A").observe(2).block2(0, true, 64).payload(respPayload.substring(0, 64)).go();
		if (client.get("T") == CON)
			client.sendEmpty(ACK).loadMID("A").go();

		byte[] tok3 = generateNextToken();
		client.sendRequest(CON, GET, tok3, ++mid).path(path).block2(1, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok3, mid).block2(1, true, 64).noOption(OBSERVE).payload(respPayload.substring(64, 128)).go();
		
		client.sendRequest(CON, GET, tok3, ++mid).path(path).block2(2, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok3, mid).block2(2, false, 64).noOption(OBSERVE).payload(respPayload.substring(128, 145)).go();
		
		printServerLog();
	}
	
	private LockstepEndpoint createLockstepEndpoint() {
		try {
			LockstepEndpoint endpoint = new LockstepEndpoint();
			endpoint.setDestination(new InetSocketAddress(InetAddress.getByName("localhost"), serverPort));
			return endpoint;
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	
	private void printServerLog() {
		System.out.println(serverInterceptor.toString());
		serverInterceptor.clear();
	}
	
	private static int currentToken = 10;
	private static byte[] generateNextToken() {
		return b(++currentToken);
	}
	
	private static byte[] b(int... is) {
		byte[] bytes = new byte[is.length];
		for (int i=0;i<bytes.length;i++)
			bytes[i] = (byte) is[i];
		return bytes;
	}
	
	private static String generatePayload(int length) {
		StringBuffer buffer = new StringBuffer();
		if (RANDOM_PAYLOAD_GENERATION) {
			Random rand = new Random();
			while(buffer.length() < length) {
				buffer.append(rand.nextInt());
			}
		} else { // Deterministic payload
			int n = 1;
			while(buffer.length() < length) {
				buffer.append(n++);
			}
		}
		return buffer.substring(0, length);
	}
	
	// All tests are made with this resource
	private class TestResource extends CoapResource {
		
		public TestResource(String name) { 
			super(name);
		}
		
		public void handleGET(CoapExchange exchange) {
			exchange.respond(ResponseCode.CONTENT, respPayload);
		}
		
		public void handlePUT(CoapExchange exchange) {
			System.out.println("Server has received request payload: "+exchange.getRequestText());
			Assert.assertEquals(reqtPayload, exchange.getRequestText());
			exchange.respond(ResponseCode.CHANGED, respPayload);
		}
		
		public void handlePOST(CoapExchange exchange) {
			System.out.println("Server has received request payload: "+exchange.getRequestText());
			Assert.assertEquals(reqtPayload, exchange.getRequestText());
			exchange.respond(ResponseCode.CHANGED, respPayload);
		}
	}
}
