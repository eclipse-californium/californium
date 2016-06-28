/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Bosch Software Innovations GmbH - reduce code duplication, split up into
 *                                      separate test cases, remove wait cycles
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import static org.eclipse.californium.core.coap.CoAP.Code.GET;
import static org.eclipse.californium.core.coap.CoAP.Code.POST;
import static org.eclipse.californium.core.coap.CoAP.Code.PUT;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CHANGED;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTINUE;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.REQUEST_ENTITY_INCOMPLETE;
import static org.eclipse.californium.core.coap.CoAP.Type.ACK;
import static org.eclipse.californium.core.coap.CoAP.Type.CON;
import static org.eclipse.californium.core.coap.CoAP.Type.NON;
import static org.eclipse.californium.core.coap.OptionNumberRegistry.OBSERVE;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.createLockstepEndpoint;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.generateNextToken;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.generateRandomPayload;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.printServerLog;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.waitUntilDeduplicatorShouldBeEmpty;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.category.Large;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.InMemoryMessageExchangeStore;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.MessageExchangeStore;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.test.BlockwiseTransferTest.ServerBlockwiseInterceptor;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * This test implements all examples from the blockwise draft 14 for a server.
 */
@Category(Large.class)
public class BlockwiseServerSideTest {

	static final int TEST_EXCHANGE_LIFETIME = 247; // milliseconds
	static final int TEST_SWEEP_DEDUPLICATOR_INTERVAL = 100; // milliseconds
	static final int TEST_PREFERRED_BLOCK_SIZE = 128; // bytes

	private static NetworkConfig CONFIG;

	private CoapServer server;
	private LockstepEndpoint client;
	private int mid = 7000;
	private TestResource testResource;
	private String respPayload;
	private String reqtPayload;
	private ServerBlockwiseInterceptor serverInterceptor = new ServerBlockwiseInterceptor();
	String path;
	MessageExchangeStore exchangeStore;

	@BeforeClass
	public static void init() {
		System.out.println(System.lineSeparator() + "Start " + BlockwiseServerSideTest.class.getSimpleName());
		LockstepEndpoint.DEFAULT_VERBOSE = false;		
		CONFIG = new NetworkConfig()
				.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 128)
				.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, TEST_PREFERRED_BLOCK_SIZE)
				.setInt(NetworkConfig.Keys.BLOCKWISE_STATUS_LIFETIME, 100)
				.setInt(NetworkConfig.Keys.MARK_AND_SWEEP_INTERVAL, TEST_SWEEP_DEDUPLICATOR_INTERVAL)
				.setLong(NetworkConfig.Keys.EXCHANGE_LIFETIME, TEST_EXCHANGE_LIFETIME);
	}

	@Before
	public void setupEndpoints() throws Exception {

		path = "test";
		testResource = new TestResource(path);
		exchangeStore = new InMemoryMessageExchangeStore(CONFIG);
		// bind to loopback address using an ephemeral port
		CoapEndpoint udpEndpoint = new CoapEndpoint(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), CONFIG, exchangeStore);
		server = new CoapServer();
		server.addEndpoint(udpEndpoint);
		server.add(testResource);
		server.getEndpoints().get(0).addInterceptor(serverInterceptor);
		server.start();
		InetSocketAddress serverAddress = server.getEndpoints().get(0).getAddress();
		System.out.println("Server binds to port " + serverAddress.getPort());
		client = createLockstepEndpoint(serverAddress);
	}

	@After
	public void shutdownEndpoints() {
		printServerLog(serverInterceptor);
		System.out.println();
		client.destroy();
		server.destroy();
	}

	@AfterClass
	public static void finish() {
		System.out.println("End " + BlockwiseServerSideTest.class.getSimpleName());
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
	@Test
	public void testGET() throws Exception {
		System.out.println("Simple blockwise GET:");
		respPayload = generateRandomPayload(300);
		byte[] tok = generateNextToken();

		client.sendRequest(CON, GET, tok, ++mid).path(path).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, 128).payload(respPayload.substring(0, 128)).go();
		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(1, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(1, true, 128).payload(respPayload.substring(128, 256)).go();
		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(2, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(2, false,  128).payload(respPayload.substring(256,300)).go();
	}

	/**
	 * Shows an incomplete transfer of a resource that would require
	 * three GET requests. The client, however, only retrieves the first
	 * two blocks. The test verifies, that after EXCHANGE_LIFETIME all state
	 * regarding the blockwise transfer has been cleared from the server.
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
	 */
	@Test
	public void testIncompleteGET() throws Exception {
		System.out.println("Incomplete blockwise GET:");
		respPayload = generateRandomPayload(300);
		byte[] tok = generateNextToken();

		client.sendRequest(CON, GET, tok, ++mid).path(path).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, 128).payload(respPayload.substring(0, 128)).go();
		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(1, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(1, true, 128).payload(respPayload.substring(128, 256)).go();
		serverInterceptor.log(System.lineSeparator() + "//////// Missing last GET ////////");

		waitUntilDeduplicatorShouldBeEmpty(TEST_EXCHANGE_LIFETIME, TEST_SWEEP_DEDUPLICATOR_INTERVAL);
		Assert.assertTrue(
				"Incomplete ongoing blockwise exchange should have been evicted from message exchange store",
				exchangeStore.isEmpty());
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
	@Test
	public void testGETEarlyNegotion() throws Exception {
		System.out.println("Blockwise GET with early negotiation");
		respPayload = generateRandomPayload(350);
		byte[] tok = generateNextToken();

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
	@Test
	public void testGETLateNegotion() throws Exception {
		System.out.println("Blockwise GET with late negotiation:");
		respPayload = generateRandomPayload(350);
		byte[] tok = generateNextToken();

		client.sendRequest(CON, GET, tok, ++mid).path(path).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, TEST_PREFERRED_BLOCK_SIZE)
			.payload(respPayload.substring(0, TEST_PREFERRED_BLOCK_SIZE)).go();

		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(2, false, 64).go(); // late negotiation
		client.expectResponse(ACK, CONTENT, tok, mid).block2(2, true, 64).payload(respPayload.substring(128, 192)).go();

		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(3, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(3, true, 64).payload(respPayload.substring(192, 256)).go();

		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(4, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(4, true, 64).payload(respPayload.substring(256, 320)).go();

		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(5, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(5, false,  64).payload(respPayload.substring(320)).go();
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
	@Test
	public void testGETLateNegotionalLostACK() throws Exception {
		System.out.println("Blockwise GET with late negotiation and lost ACK:");
		respPayload = generateRandomPayload(220);
		byte[] tok = generateNextToken();

		client.sendRequest(CON, GET, tok, ++mid).path(path).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, TEST_PREFERRED_BLOCK_SIZE)
			.payload(respPayload.substring(0, TEST_PREFERRED_BLOCK_SIZE)).go();

		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(2, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(2, true, 64).payload(respPayload.substring(128, 192)).go();
		// We lose this ACK, and therefore the client retransmits the CON GET
		serverInterceptor.log(" // lost");
		client.sendRequest(CON, GET, tok, mid).path(path).block2(2, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(2, true, 64).payload(respPayload.substring(128, 192)).go();

		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(3, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(3, false, 64).payload(respPayload.substring(192)).go();
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
	@Test
	public void testSimpleAtomicBlockwisePUT() throws Exception {
		System.out.println("Simple atomic blockwise PUT");
		respPayload = generateRandomPayload(50);
		byte[] tok = generateNextToken();
		reqtPayload = generateRandomPayload(300);

		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(0, true, 128).payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).payload("").go();

		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(1, true, 128).payload(reqtPayload.substring(128, 256)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(1, true, 128).payload("").go();

		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(2, false, 128).payload(reqtPayload.substring(256)).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block1(2, false, 128).payload(respPayload).go();
	}

	@Test
	public void testSimpleAtomicBlockwisePUTWithLostAck() throws Exception {
		System.out.println("Simple atomic blockwise PUT with lost ACK");
		respPayload = generateRandomPayload(50);
		byte[] tok = generateNextToken();
		reqtPayload = generateRandomPayload(300);

		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(0, true, 128).payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).payload("").go();
		serverInterceptor.log("// lost");
		// ACK goes lost => retransmission
		client.sendRequest(CON, PUT, tok, mid).path(path).block1(0, true, 128).payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).payload("").go();

		// and continue normally
		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(1, true, 128).payload(reqtPayload.substring(128, 256)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(1, true, 128).payload("").go();

		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(2, false, 128).payload(reqtPayload.substring(256)).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block1(2, false, 128).payload(respPayload).go();
	}

	@Test
	public void testSimpleAtomicBlockwisePUTWithRestartOfTransfer() throws Exception {
		System.out.println("Simple atomic blockwise PUT restart of the blockwise transfer");
		respPayload = generateRandomPayload(50);
		byte[] tok = generateNextToken();
		reqtPayload = generateRandomPayload(300);

		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(0, true, 128).payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).payload("").go();

		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(1, true, 128).payload(reqtPayload.substring(128, 256)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(1, true, 128).payload("").go();

		serverInterceptor.log(System.lineSeparator() + "... client crashes or whatever and restarts transfer");

		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(0, true, 128).payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).payload("").go();

		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(1, true, 128).payload(reqtPayload.substring(128, 256)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(1, true, 128).payload("").go();

		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(2, false, 128).payload(reqtPayload.substring(256, 300)).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block1(2, false, 128).payload(respPayload).go();
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
	@Test
	public void testAtomicBlockwisePOSTWithBlockwiseResponse() throws Exception {
		System.out.println("Atomic blockwise POST with blockwise response:");
		respPayload = generateRandomPayload(500);
		byte[] tok = generateNextToken();
		reqtPayload = generateRandomPayload(300);

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
	}

	/**
	 * The above example with late negotiation by requesting e.g. 2:2/0/64.
	 */
	@Test
	public void testAtomicBlockwisePOSTWithBlockwiseResponseLateNegotiation() throws Exception {
		System.out.println("Atomic blockwise POST with blockwise response:");
		respPayload = generateRandomPayload(300);
		byte[] tok = generateNextToken();
		reqtPayload = generateRandomPayload(300);

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
	@Test
	public void testAtomicBlockwisePOSTWithBlockwiseResponseEarlyNegotiation() throws Exception {
		System.out.println("Atomic blockwise POST with blockwise response:");
		respPayload = generateRandomPayload(250);
		byte[] tok = generateNextToken();
		reqtPayload = generateRandomPayload(300);

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
	}

	@Test
	public void testRandomAccessPUTAttemp() throws Exception {
		System.out.println("Random access PUT attempt: (try to put block 2 first is now allowed)");
		respPayload = generateRandomPayload(50);
		reqtPayload = generateRandomPayload(300);
		byte[] tok = generateNextToken();

		client.sendRequest(CON, PUT, tok, ++mid).path(path).block1(2, true, 64).payload(reqtPayload.substring(2*64, 3*64)).go();
		client.expectResponse(ACK, REQUEST_ENTITY_INCOMPLETE, tok, mid).block1(2, true, 64).go();
	}

	@Test
	public void testRandomAccessGET() throws Exception {
		System.out.println("Random access GET: (only access block 2 and 4 of response)");
		respPayload = generateRandomPayload(300);
		byte[] tok = generateNextToken();

		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(2, true, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(2, true, 64).payload(respPayload.substring(2*64, 3*64)).go();

		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(4, true, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(4, false, 64).payload(respPayload.substring(4*64, 300)).go();
	}

	@Test
	public void testObserveWithBlockwiseResponse() throws Exception {
		System.out.println("Observe sequence with blockwise response:");
		respPayload = generateRandomPayload(300);
		byte[] tok = generateNextToken();
		path = "test1";
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
		System.out.println("Establish observe relation to " + path);

		client.sendRequest(CON, GET, tok, ++mid).path(path).observe(0).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, 128).observe(0).block2(0, true, 128).payload(respPayload.substring(0, 128)).go();

		byte[] tok1 = generateNextToken();
		client.sendRequest(CON, GET, tok1, ++mid).path(path).block2(1, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok1, mid).block2(1, true, 128).noOption(OBSERVE).payload(respPayload.substring(128, 256)).go();

		client.sendRequest(CON, GET, tok1, ++mid).path(path).block2(2, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok1, mid).block2(2, false, 128).noOption(OBSERVE).payload(respPayload.substring(256, 300)).go();

		serverInterceptor.log(System.lineSeparator() + "... time passes ...");
		System.out.println("Send first notification");
		respPayload = generateRandomPayload(280);
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
		serverInterceptor.log(System.lineSeparator() + "... time passes ...");
		respPayload = generateRandomPayload(290);
		test1.changed();

		client.expectResponse().responseType("T", CON, NON).code(CONTENT).token(tok).storeMID("A").observe(2).block2(0, true, 128).payload(respPayload.substring(0, 128)).go();
		if (client.get("T") == CON)
			client.sendEmpty(ACK).loadMID("A").go();

		byte[] tok3 = generateNextToken();
		client.sendRequest(CON, GET, tok3, ++mid).path(path).block2(1, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok3, mid).block2(1, true, 128).noOption(OBSERVE).payload(respPayload.substring(128, 256)).go();

		client.sendRequest(CON, GET, tok3, ++mid).path(path).block2(2, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok3, mid).block2(2, false, 128).noOption(OBSERVE).payload(respPayload.substring(256, 290)).go();
	}

	@Test
	public void testObserveWithBlockwiseResponseEarlyNegotiation() throws Exception {
		System.out.println("Observe sequence with early negotiation:");
		respPayload = generateRandomPayload(150);
		byte[] tok = generateNextToken();
		path = "test2";
		TestResource test2 = new TestResource(path);
		test2.setObservable(true);
		server.add(test2);
		System.out.println("Establish observe relation to "+path);

		client.sendRequest(CON, GET, tok, ++mid).path(path).observe(0).block2(0, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, 64).observe(0).block2(0, true, 64).payload(respPayload.substring(0, 64)).go();

		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(1, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(1, true, 64).noOption(OBSERVE).payload(respPayload.substring(64, 128)).go();

		client.sendRequest(CON, GET, tok, ++mid).path(path).block2(2, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(2, false, 64).noOption(OBSERVE).payload(respPayload.substring(128, 150)).go();

		System.out.println("Send first notification");
		serverInterceptor.log(System.lineSeparator() + "... time passes ...");
		respPayload = generateRandomPayload(140);
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
		serverInterceptor.log(System.lineSeparator() + "... time passes ...");
		respPayload = generateRandomPayload(145);
		test2.changed(); // Second notification

		client.expectResponse().responseType("T", CON, NON).code(CONTENT).token(tok).storeMID("A").observe(2).block2(0, true, 64).payload(respPayload.substring(0, 64)).go();
		if (client.get("T") == CON)
			client.sendEmpty(ACK).loadMID("A").go();

		byte[] tok3 = generateNextToken();
		client.sendRequest(CON, GET, tok3, ++mid).path(path).block2(1, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok3, mid).block2(1, true, 64).noOption(OBSERVE).payload(respPayload.substring(64, 128)).go();

		client.sendRequest(CON, GET, tok3, ++mid).path(path).block2(2, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok3, mid).block2(2, false, 64).noOption(OBSERVE).payload(respPayload.substring(128, 145)).go();
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
