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
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CoapNetworkRule for
 *                                                    setup of test-network
 *    Achim Kraus (Bosch Software Innovations GmbH) - use waitForCondition
 *    Achim Kraus (Bosch Software Innovations GmbH) - split responseType in
 *                                                    type(Type... types) and
 *                                                    storeType(String var)
 *    Achim Kraus (Bosch Software Innovations GmbH) - use MessageExchangeStoreTool
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 *    Achim Kraus (Bosch Software Innovations GmbH) - relax timing for eclipse jenkins
 *    Achim Kraus (Bosch Software Innovations GmbH) - add partial support for TimeAssume
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import static org.eclipse.californium.TestTools.*;
import static org.eclipse.californium.core.coap.CoAP.Code.*;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.*;
import static org.eclipse.californium.core.coap.CoAP.Type.*;
import static org.eclipse.californium.core.coap.OptionNumberRegistry.OBSERVE;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.*;
import static org.eclipse.californium.core.test.MessageExchangeStoreTool.*;
import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.category.Large;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.test.MessageExchangeStoreTool.CoapTestEndpoint;
import org.eclipse.californium.elements.assume.TimeAssume;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * Test cases verifying the server side behavior of the examples from
 * <a href="https://tools.ietf.org/html/rfc7959#section-3">RFC 7958, Section 3</em>.
 */
@Category(Large.class)
public class BlockwiseServerSideTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	private static final int TEST_EXCHANGE_LIFETIME = 247; // milliseconds
	private static final int TEST_SWEEP_DEDUPLICATOR_INTERVAL = 100; // milliseconds
	private static final int TEST_PREFERRED_BLOCK_SIZE = 128; // bytes
	private static final int TEST_BLOCKWISE_STATUS_LIFETIME = 500;
	private static final int MAX_RESOURCE_BODY_SIZE = 1024;
	private static final String RESOURCE_PATH = "test";

	private static NetworkConfig CONFIG;

	private CoapServer server;
	private CoapTestEndpoint serverEndpoint;
	private LockstepEndpoint client;
	private int mid = 7000;
	private TestResource testResource;
	private String respPayload;
	private String reqtPayload;
	private byte[] etag;
	private Integer expectedMid;
	private Token expectedToken;
	private ServerBlockwiseInterceptor serverInterceptor = new ServerBlockwiseInterceptor();

	@BeforeClass
	public static void init() {
		System.out.println(System.lineSeparator() + "Start " + BlockwiseServerSideTest.class.getSimpleName());
		CONFIG = network.createTestConfig()
				.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 128)
				.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, TEST_PREFERRED_BLOCK_SIZE)
				.setInt(NetworkConfig.Keys.MAX_RESOURCE_BODY_SIZE, MAX_RESOURCE_BODY_SIZE)
				.setInt(NetworkConfig.Keys.MARK_AND_SWEEP_INTERVAL, TEST_SWEEP_DEDUPLICATOR_INTERVAL)
				.setLong(NetworkConfig.Keys.EXCHANGE_LIFETIME, TEST_EXCHANGE_LIFETIME)
				.setLong(NetworkConfig.Keys.BLOCKWISE_STATUS_LIFETIME, TEST_BLOCKWISE_STATUS_LIFETIME);
	}

	@Before
	public void setupEndpoints() throws Exception {

		etag = null;
		expectedMid = null;
		expectedToken = null;
		testResource = new TestResource(RESOURCE_PATH);
		testResource.setObservable(true);
		// bind to loopback address using an ephemeral port
		serverEndpoint = new CoapTestEndpoint(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), CONFIG);
		serverEndpoint.addInterceptor(serverInterceptor);
		server = new CoapServer();
		server.addEndpoint(serverEndpoint);
		server.add(testResource);
		server.start();
		InetSocketAddress serverAddress = serverEndpoint.getAddress();
		System.out.println("Server binds to port " + serverAddress.getPort());
		client = createLockstepEndpoint(serverAddress);
	}

	@After
	public void shutdownEndpoints() {
		try {
			assertAllExchangesAreCompleted(serverEndpoint);
		} finally {
			printServerLog(serverInterceptor);

			System.out.println();
			client.destroy();
			server.destroy();
		}
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
	 * <p>
	 * The server includes an ETag in its initial response which is used throughout
	 * the remainder of the blockwise transfer to retrieve blocks of the same
	 * tagged resource.
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
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testGETWithETag() throws Exception {
		System.out.println("Simple blockwise GET:");
		respPayload = generateRandomPayload(300);
		Token tok = generateNextToken();
		etag = new byte[]{ 0x00, 0x01 };

		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, 128).size2(300).storeETag("ET").payload(respPayload.substring(0, 128)).go();
		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).block2(1, false, 128).loadETag("ET").go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(1, true, 128).sameETag("ET").payload(respPayload.substring(128, 256)).go();
		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).block2(2, false, 128).loadETag("ET").go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(2, false,  128).sameETag("ET").payload(respPayload.substring(256,300)).go();
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
	 * | CON [MID=1234], GET, /status, 2:0/0/32           ------> |
	 * |                                                          |
	 * | <------   ACK [MID=1234], 2.05 Content, 2:0/1/32         |
	 * |                                                          |
	 * | CON [MID=1235], GET, /status, 2:1/0/32           ------> |
	 * |                                                          |
	 * | <------   ACK [MID=1235], 2.05 Content, 2:1/1/32         |
	 * |                                                          |
	 * | CON [MID=1239], GET, /status, 2:2/0/32           ------> |
	 * |                                                          |
	 * | <------   ACK [MID=1239], 2.05 Content, 2:2/0/32         |
	 * </pre>
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testGETEarlyNegotiation() throws Exception {

		System.out.println("Blockwise GET with early negotiation");
		respPayload = generateRandomPayload(76); // smaller than MAX MESSAGE SIZE
		Token tok = generateNextToken();

		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).block2(0, false, 32).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, 32).size2(respPayload.length())
			.payload(respPayload.substring(0, 32)).go();

		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).block2(1, false, 32).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(1, true, 32).payload(respPayload.substring(32, 64)).go();

		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).block2(2, false, 32).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(2, false, 32).payload(respPayload.substring(64)).go();
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
     * | <------   ACK [MID=1235], 2.05 Content, 2:2/0/64         |
     * </pre>
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testGETLateNegotiation() throws Exception {
		System.out.println("Blockwise GET with late negotiation:");
		respPayload = generateRandomPayload(170);
		Token tok = generateNextToken();

		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, TEST_PREFERRED_BLOCK_SIZE).size2(respPayload.length())
			.payload(respPayload.substring(0, TEST_PREFERRED_BLOCK_SIZE)).go();

		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).block2(2, false, 64).go(); // late negotiation
		client.expectResponse(ACK, CONTENT, tok, mid).block2(2, false, 64).payload(respPayload, 128, 170).go();
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
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testGETLateNegotiationLostACK() throws Exception {
		System.out.println("Blockwise GET with late negotiation and lost ACK:");
		respPayload = generateRandomPayload(220);
		Token tok = generateNextToken();

		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, TEST_PREFERRED_BLOCK_SIZE).size2(respPayload.length())
			.payload(respPayload.substring(0, TEST_PREFERRED_BLOCK_SIZE)).go();

		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).block2(2, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(2, true, 64).payload(respPayload.substring(128, 192)).go();
		// We lose this ACK, and therefore the client retransmits the CON GET
		serverInterceptor.log(" // lost");
		client.sendRequest(CON, GET, tok, mid).path(RESOURCE_PATH).block2(2, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(2, true, 64).payload(respPayload.substring(128, 192)).go();

		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).block2(3, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(3, false, 64).payload(respPayload.substring(192)).go();
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
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testIncompleteGET() throws Exception {
		System.out.println("Incomplete blockwise GET:");
		respPayload = generateRandomPayload(300);
		Token tok = generateNextToken();

		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, 128).size2(respPayload.length())
			.payload(respPayload.substring(0, 128)).go();
		Thread.sleep((long) (TEST_BLOCKWISE_STATUS_LIFETIME * 0.75));
		
		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).block2(1, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(1, true, 128).payload(respPayload.substring(128, 256)).go();
		Thread.sleep((long) (TEST_BLOCKWISE_STATUS_LIFETIME * 0.75));
		
		assertTrue(!serverEndpoint.getStack().getBlockwiseLayer().isEmpty());
		serverInterceptor.logNewLine("//////// Missing last GET ////////");
	}

	/**
	 * Shows an incomplete transfer of a resource that would require
	 * three PUT requests. The client, however, only sends the first
	 * two blocks. The test verifies, that after EXCHANGE_LIFETIME all state
	 * regarding the blockwise transfer has been cleared from the server.
	 * <pre>
	 * CLIENT                                                     SERVER
     * |                                                            |
     * | CON [MID=1234], PUT, /status, 1:0/1/128            ------> |
     * |                                                            |
     * | <------   ACK [MID=1234], 2.31 Continue, 1:0/1/128         |
     * |                                                            |
     * | CON [MID=1235], PUT, /status, 1:1/1/128            ------> |
     * |                                                            |
     * | <------   ACK [MID=1235], 2.31 Continue, 1:1/1/128         |
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testIncompletePUT() throws Exception {

		System.out.println("Incomplete blockwise PUT:");

		reqtPayload = generateRandomPayload(300);
		Token tok = generateNextToken();

		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(0, true, 128).size1(reqtPayload.length())
			.payload(reqtPayload.substring(0,  128)).go();
		client.expectResponse(ACK, ResponseCode.CONTINUE, tok, mid).block1(0, true, 128).go();
		Thread.sleep((long) (TEST_BLOCKWISE_STATUS_LIFETIME * 0.75));

		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(1, true, 128).payload(reqtPayload.substring(128,  256)).go();
		client.expectResponse(ACK, ResponseCode.CONTINUE, tok, mid).block1(1, true, 128).go();
		Thread.sleep((long) (TEST_BLOCKWISE_STATUS_LIFETIME * 0.75));

		assertTrue(!serverEndpoint.getStack().getBlockwiseLayer().isEmpty());
		serverInterceptor.logNewLine("//////// Missing last PUT ////////");
	}

	/**
	 * Shows 2 successful complete transfers. The second one should not
	 * terminate before TEST_BLOCKWISE_STATUS_LIFETIME. The idea is to ensure
	 * than cleaning task is well canceled at the end of the first block
	 * transfer.
	 * 
	 * <pre>
	 * CLIENT                                                     SERVER
	 * 
	 * CON [MID=7001, T=[0b]], PUT, /test, 1:0/1/128, size1(300) ----->
	 * <-----   ACK [MID=7001, T=[0b]], 2.31, 1:0/1/128
	 * CON [MID=7002, T=[0b]], PUT, /test, 1:1/1/128    ----->
	 * <-----   ACK [MID=7002, T=[0b]], 2.31, 1:1/1/128
	 * CON [MID=7003, T=[0b]], PUT, /test, 1:2/0/128    ----->
	 * <-----   ACK [MID=7003, T=[0b]], 2.04, 1:2/0/128
	 * // next transfer
	 * CON [MID=7004, T=[0c]], PUT, /test, 1:0/1/128, size1(300)    ----->
	 * <-----   ACK [MID=7004, T=[0c]], 2.31, 1:0/1/128
	 * CON [MID=7005, T=[0c]], PUT, /test, 1:1/1/128    ----->
	 * <-----   ACK [MID=7005, T=[0c]], 2.31, 1:1/1/128
	 * CON [MID=7006, T=[0c]], PUT, /test, 1:2/0/128    ----->
	 * <-----   ACK [MID=7006, T=[0c]], 2.04, 1:2/0/128
	 * 
	 * </pre>
	 */
	@Test
	public void test2ConsecutiveCompletePUT() throws Exception {

		System.out.println("2 consecutive complete PUT with block1 transfer:");

		TimeAssume assume = new TimeAssume();
		reqtPayload = generateRandomPayload(300);
		Token tok = generateNextToken();

		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(0, true, 128).size1(reqtPayload.length())
				.payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, ResponseCode.CONTINUE, tok, mid).block1(0, true, 128).go();
		assume.sleep((long) (TEST_BLOCKWISE_STATUS_LIFETIME * 0.75));

		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(1, true, 128)
				.payload(reqtPayload.substring(128, 256)).go();
		client.expectResponse(ACK, ResponseCode.CONTINUE, tok, mid).block1(1, true, 128).go(assume);
		assume.sleep((long) (TEST_BLOCKWISE_STATUS_LIFETIME * 0.75));

		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(2, false, 128)
				.payload(reqtPayload.substring(256, 300)).go();
		client.expectResponse(ACK, ResponseCode.CHANGED, tok, mid).block1(2, false, 128).go(assume);
		assume.sleep((long) (TEST_BLOCKWISE_STATUS_LIFETIME * 0.75));

		// Transfer is complete : ensure BlockwiseLayer is empty.
		assertTrue("BlockwiseLayer should be empty", serverEndpoint.getStack().getBlockwiseLayer().isEmpty());

		// Try another BlockwiseLayer transfer from same peer, same URL, same
		// option.
		serverInterceptor.logNewLine("// next transfer");
		reqtPayload = generateRandomPayload(300);
		tok = generateNextToken();
		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(0, true, 128).size1(reqtPayload.length())
				.payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, ResponseCode.CONTINUE, tok, mid).block1(0, true, 128).go();
		assume.sleep((long) (TEST_BLOCKWISE_STATUS_LIFETIME * 0.75));

		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(1, true, 128)
				.payload(reqtPayload.substring(128, 256)).go();
		client.expectResponse(ACK, ResponseCode.CONTINUE, tok, mid).block1(1, true, 128).go(assume);
		assume.sleep((long) (TEST_BLOCKWISE_STATUS_LIFETIME * 0.75));

		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(2, false, 128)
				.payload(reqtPayload.substring(256, 300)).go();
		client.expectResponse(ACK, ResponseCode.CHANGED, tok, mid).block1(2, false, 128).go(assume);
		assume.sleep((long) (TEST_BLOCKWISE_STATUS_LIFETIME * 0.75));

		assertTrue("blockwise layer should be empty", serverEndpoint.getStack().getBlockwiseLayer().isEmpty());
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
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testSimpleAtomicBlockwisePUT() throws Exception {
		System.out.println("Simple atomic blockwise PUT");
		respPayload = generateRandomPayload(50);
		reqtPayload = generateRandomPayload(300);

		Token tok = generateNextToken();
		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(0, true, 128).size1(reqtPayload.length()).payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).payload("").go();

		tok = generateNextToken();
		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(1, true, 128).payload(reqtPayload.substring(128, 256)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(1, true, 128).payload("").go();

		expectedToken = generateNextToken();
		expectedMid = ++mid;
		client.sendRequest(CON, PUT, expectedToken, expectedMid).path(RESOURCE_PATH).block1(2, false, 128).payload(reqtPayload.substring(256)).go();
		client.expectResponse(ACK, CHANGED, expectedToken, expectedMid).block1(2, false, 128).payload(respPayload).go();
	}

	@Test
	public void testSimpleAtomicBlockwisePUTWithLostAck() throws Exception {
		System.out.println("Simple atomic blockwise PUT with lost ACK");
		respPayload = generateRandomPayload(50);
		Token tok = generateNextToken();
		reqtPayload = generateRandomPayload(300);

		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(0, true, 128).size1(reqtPayload.length()).payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).payload("").go();
		serverInterceptor.log("// lost");
		// ACK goes lost => retransmission
		client.sendRequest(CON, PUT, tok, mid).path(RESOURCE_PATH).block1(0, true, 128).payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).payload("").go();

		// and continue normally
		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(1, true, 128).payload(reqtPayload.substring(128, 256)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(1, true, 128).payload("").go();

		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(2, false, 128).payload(reqtPayload.substring(256)).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block1(2, false, 128).payload(respPayload).go();
	}

	@Test
	public void testSimpleAtomicBlockwisePUTWithRestartOfTransfer() throws Exception {
		System.out.println("Simple atomic blockwise PUT restart of the blockwise transfer");
		respPayload = generateRandomPayload(50);
		Token tok = generateNextToken();
		reqtPayload = generateRandomPayload(300);

		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(0, true, 128).size1(reqtPayload.length()).payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).payload("").go();

		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(1, true, 128).payload(reqtPayload.substring(128, 256)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(1, true, 128).payload("").go();

		serverInterceptor.logNewLine("... client crashes or whatever and restarts transfer");

		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(0, true, 128).size1(reqtPayload.length()).payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).payload("").go();

		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(1, true, 128).payload(reqtPayload.substring(128, 256)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(1, true, 128).payload("").go();

		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(2, false, 128).payload(reqtPayload.substring(256, 300)).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block1(2, false, 128).payload(respPayload).go();
	}

	/**
	 * Verifies that a block1 transfer fails with a 4.13 code if the body size exceeds
	 * MAX_RESOURCE_BODY_SIZE.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testPUTFailsWith413IfBodyExceedsMaxBodySize() throws Exception {

		System.out.println("Blockwise PUT fails for excessive body size");
		Token tok = generateNextToken();
		reqtPayload = generateRandomPayload(MAX_RESOURCE_BODY_SIZE + 10);

		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(0, true, 128).size1(reqtPayload.length()).payload(reqtPayload, 0, 128).go();
		client.expectResponse(ACK, REQUEST_ENTITY_TOO_LARGE, tok, mid).size1(MAX_RESOURCE_BODY_SIZE).go();
	}

	/**
	 * Verifies that a block1 transfer fails with a 4.08 code if not all blocks are transferred.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testPUTFailsWith408OnIncompleteTransfer() throws Exception {

		System.out.println("Blockwise PUT fails for incomplete transfer");
		Token tok = generateNextToken();
		reqtPayload = generateRandomPayload(300);

		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(0, true, 128).size1(reqtPayload.length()).payload(reqtPayload, 0, 128).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).go();

		// now send last block without having sent middle block altogether
		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(2, false, 128).payload(reqtPayload, 256, 300).go();
		client.expectResponse(ACK, REQUEST_ENTITY_INCOMPLETE, tok, mid).go();
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
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testAtomicBlockwisePOSTWithBlockwiseResponse() throws Exception {
		System.out.println("Atomic blockwise POST with blockwise response:");
		respPayload = generateRandomPayload(500);
		Token tok = generateNextToken();
		reqtPayload = generateRandomPayload(300);
		etag = new byte[]{ 0x00, 0x01 };

		client.sendRequest(CON, POST, tok, ++mid).path(RESOURCE_PATH).block1(0, true, 128).size1(reqtPayload.length()).payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).go();

		client.sendRequest(CON, POST, tok, ++mid).path(RESOURCE_PATH).block1(1, true, 128).payload(reqtPayload.substring(128, 256)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(1, true, 128).go();

		client.sendRequest(CON, POST, tok, ++mid).path(RESOURCE_PATH).block1(2, false, 128).payload(reqtPayload.substring(256)).go();
		client.expectResponse(ACK, CHANGED, tok, mid).payload(respPayload.substring(0, 128)).block1(2, false, 128).block2(0, true, 128).storeETag("tag").size2(respPayload.length()).go();

		client.sendRequest(CON, POST, tok, ++mid).path(RESOURCE_PATH).loadETag("tag").block2(1, false, 128).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block2(1, true, 128).payload(respPayload.substring(128, 256)).go();

		client.sendRequest(CON, POST, tok, ++mid).path(RESOURCE_PATH).loadETag("tag").block2(2, false, 128).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block2(2, true, 128).payload(respPayload.substring(256, 384)).go();

		client.sendRequest(CON, POST, tok, ++mid).path(RESOURCE_PATH).loadETag("tag").block2(3, false, 128).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block2(3, false, 128).payload(respPayload.substring(384, 500)).go();
	}

	/**
	 * The above example with late negotiation by requesting e.g. 2:2/0/64.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testAtomicBlockwisePOSTWithBlockwiseResponseLateNegotiation() throws Exception {
		System.out.println("Atomic blockwise POST with blockwise response using late negotiation:");
		respPayload = generateRandomPayload(300);
		Token tok = generateNextToken();
		reqtPayload = generateRandomPayload(300);
		etag = new byte[]{ 0x00, 0x01 };

		client.sendRequest(CON, POST, tok, ++mid).path(RESOURCE_PATH).block1(0, true, 128).size1(reqtPayload.length()).payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).go();

		client.sendRequest(CON, POST, tok, ++mid).path(RESOURCE_PATH).block1(1, true, 128).payload(reqtPayload.substring(128, 256)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(1, true, 128).go();

		client.sendRequest(CON, POST, tok, ++mid).path(RESOURCE_PATH).block1(2, false, 128).payload(reqtPayload.substring(256, 300)).go();
		client.expectResponse(ACK, CHANGED, tok, mid).payload(respPayload.substring(0, 128)).block1(2, false, 128).block2(0, true, 128).storeETag("tag").size2(respPayload.length()).go();

		client.sendRequest(CON, POST, tok, ++mid).path(RESOURCE_PATH).loadETag("tag").block2(2, false, 64).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block2(2, true, 64).payload(respPayload.substring(128, 192)).go();
		serverInterceptor.log("// late negotiation");

		client.sendRequest(CON, POST, tok, ++mid).path(RESOURCE_PATH).loadETag("tag").block2(3, false, 64).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block2(3, true, 64).payload(respPayload.substring(192, 256)).go();

		client.sendRequest(CON, POST, tok, ++mid).path(RESOURCE_PATH).loadETag("tag").block2(4, false, 64).go();
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
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testAtomicBlockwisePOSTWithBlockwiseResponseEarlyNegotiation() throws Exception {
		System.out.println("Atomic blockwise POST with blockwise response using early negotiation:");
		respPayload = generateRandomPayload(250);
		Token tok = generateNextToken();
		reqtPayload = generateRandomPayload(300);
		etag = new byte[]{ 0x00, 0x01 };

		client.sendRequest(CON, POST, tok, ++mid).path(RESOURCE_PATH).block1(0, true, 128).payload(reqtPayload.substring(0, 128)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(0, true, 128).go();

		client.sendRequest(CON, POST, tok, ++mid).path(RESOURCE_PATH).block1(1, true, 128).payload(reqtPayload.substring(128, 256)).go();
		client.expectResponse(ACK, CONTINUE, tok, mid).block1(1, true, 128).go();

		client.sendRequest(CON, POST, tok, ++mid).path(RESOURCE_PATH).payload(reqtPayload.substring(256, 300))
				.block1(2, false, 128).block2(0, false, 64).go();
		client.expectResponse(ACK, CHANGED, tok, mid).payload(respPayload.substring(0, 64))
				.block1(2, false, 128).block2(0, true, 64).storeETag("tag").size2(250).go();
		serverInterceptor.log("// early negotiation");

		client.sendRequest(CON, POST, tok, ++mid).path(RESOURCE_PATH).loadETag("tag").block2(1, false, 64).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block2(1, true, 64).payload(respPayload.substring(64, 128)).go();
		
		client.sendRequest(CON, POST, tok, ++mid).path(RESOURCE_PATH).loadETag("tag").block2(2, false, 64).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block2(2, true, 64).payload(respPayload.substring(128, 192)).go();

		client.sendRequest(CON, POST, tok, ++mid).path(RESOURCE_PATH).loadETag("tag").block2(3, false, 64).go();
		client.expectResponse(ACK, CHANGED, tok, mid).block2(3, false, 64).payload(respPayload.substring(192, 250)).go();
	}
	
	/**
	 * Check that new request block2 transfer is well interrupted by a new one.
	 * 
	 * <pre>
	 * ####### First GET with block2 response ########## 
	 * CON [MID=7001, T=0b], GET, /test    ----->
	 * <-----   ACK [MID=7001, T=0b], 2.05, 2:0/1/128, size2(386)
	 * CON [MID=7002, T=0c], GET, /test, 2:1/0/128    ----->
	 * <-----   ACK [MID=7002, T=0c], 2.05, 2:1/1/128
	 * ####### Interrupted by new  GET with block2 response ##########
	 * CON [MID=7003, T=0d], GET, /test    ----->
	 * <-----   ACK [MID=7003, T=0d], 2.05, 2:0/1/128, size2(256)
	 * CON [MID=7004, T=0e], GET, /test, 2:1/0/128    ----->
	 * <-----   ACK [MID=7004, T=0e], 2.05, 2:1/0/128
	 * </pre>
	 */
	@Test
	public void testInterruptBlock2WithNewBlock2GET() throws Exception {
		System.out.println("Block2 interrupted by new block2:");
		respPayload = generateRandomPayload(386);
		Token tok = generateNextToken();
		System.out.println("Begin block2 exchange on " + RESOURCE_PATH);

		// begin block2 transfer
		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, 128).payload(respPayload.substring(0, 128)).go();

		tok = generateNextToken();
		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).block2(1, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(1, true, 128).payload(respPayload.substring(128, 256))
				.go();

		// start a new one
		respPayload = generateRandomPayload(256);
		tok = generateNextToken();
		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, 128).payload(respPayload.substring(0, 128)).go();

		tok = generateNextToken();
		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).block2(1, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(1, false, 128).payload(respPayload.substring(128, 256))
				.go();
	}

	/**
	 * Verifies that a client cannot send a block with num &gt; 0 first in a blockwise PUT.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testRandomAccessPUTAttemp() throws Exception {
		System.out.println("Random access PUT attempt: (try to put block 2 first is now allowed)");
		respPayload = generateRandomPayload(50);
		reqtPayload = generateRandomPayload(300);
		Token tok = generateNextToken();

		client.sendRequest(CON, PUT, tok, ++mid).path(RESOURCE_PATH).block1(2, true, 64).payload(reqtPayload.substring(2*64, 3*64)).go();
		client.expectResponse(ACK, REQUEST_ENTITY_INCOMPLETE, tok, mid).block1(2, true, 64).go();
	}

	@Test
	public void testRandomAccessGET() throws Exception {
		System.out.println("Random access GET: (only access block 2 and 4 of response)");
		respPayload = generateRandomPayload(300);
		Token tok = generateNextToken();

		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).block2(2, true, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(2, true, 64).payload(respPayload.substring(2*64, 3*64)).go();

		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).block2(4, true, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(4, false, 64).payload(respPayload.substring(4*64, 300)).go();
	}

	@Test
	public void testObserveWithBlockwiseResponse() throws Exception {
		System.out.println("Observe sequence with blockwise response:");
		respPayload = generateRandomPayload(300);
		Token tok = generateNextToken();

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
		System.out.println("Establish observe relation to " + RESOURCE_PATH);

		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).observe(0).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, 128).size2(respPayload.length()).observe(0).block2(0, true, 128).payload(respPayload.substring(0, 128)).go();

		Token tok1 = generateNextToken();
		client.sendRequest(CON, GET, tok1, ++mid).path(RESOURCE_PATH).block2(1, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok1, mid).block2(1, true, 128).noOption(OBSERVE).payload(respPayload.substring(128, 256)).go();

		client.sendRequest(CON, GET, tok1, ++mid).path(RESOURCE_PATH).block2(2, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok1, mid).block2(2, false, 128).noOption(OBSERVE).payload(respPayload.substring(256, 300)).go();

		serverInterceptor.logNewLine("... time passes ...");
		System.out.println("Send first notification");
		respPayload = generateRandomPayload(280);
		testResource.changed();

		client.expectResponse().type(CON, NON).storeType("T").code(CONTENT).token(tok).storeMID("A").size2(respPayload.length()).observe(1).block2(0, true, 128).payload(respPayload.substring(0, 128)).go();
		if (client.get("T") == CON)
			client.sendEmpty(ACK).loadMID("A").go();

		Token tok2 = generateNextToken();
		client.sendRequest(CON, GET, tok2, ++mid).path(RESOURCE_PATH).block2(1, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok2, mid).block2(1, true, 128).noOption(OBSERVE).payload(respPayload.substring(128, 256)).go();

		client.sendRequest(CON, GET, tok2, ++mid).path(RESOURCE_PATH).block2(2, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok2, mid).block2(2, false, 128).noOption(OBSERVE).payload(respPayload.substring(256, 280)).go();

		System.out.println("Send second notification");
		serverInterceptor.logNewLine("... time passes ...");
		respPayload = generateRandomPayload(290);
		testResource.changed();

		client.expectResponse().type(CON, NON).storeType("T").code(CONTENT).token(tok).storeMID("A").size2(respPayload.length()).observe(2).block2(0, true, 128).payload(respPayload.substring(0, 128)).go();
		if (client.get("T") == CON)
			client.sendEmpty(ACK).loadMID("A").go();

		Token tok3 = generateNextToken();
		client.sendRequest(CON, GET, tok3, ++mid).path(RESOURCE_PATH).block2(1, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok3, mid).block2(1, true, 128).noOption(OBSERVE).payload(respPayload.substring(128, 256)).go();

		client.sendRequest(CON, GET, tok3, ++mid).path(RESOURCE_PATH).block2(2, false, 128).go();
		client.expectResponse(ACK, CONTENT, tok3, mid).block2(2, false, 128).noOption(OBSERVE).payload(respPayload.substring(256, 290)).go();

		testResource.clearObserveRelations();
	}

	@Test
	public void testObserveWithBlockwiseResponseEarlyNegotiation() throws Exception {
		System.out.println("Observe sequence with early negotiation:");
		respPayload = generateRandomPayload(150);
		Token tok = generateNextToken();
		System.out.println("Establish observe relation to " + RESOURCE_PATH);

		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).observe(0).block2(0, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(0, true, 64).observe(0).size2(respPayload.length()).block2(0, true, 64).payload(respPayload.substring(0, 64)).go();

		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).block2(1, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(1, true, 64).noOption(OBSERVE).payload(respPayload.substring(64, 128)).go();

		client.sendRequest(CON, GET, tok, ++mid).path(RESOURCE_PATH).block2(2, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok, mid).block2(2, false, 64).noOption(OBSERVE).payload(respPayload.substring(128, 150)).go();

		System.out.println("Send first notification");
		serverInterceptor.logNewLine("... time passes ...");
		respPayload = generateRandomPayload(140);
		testResource.changed(); // First notification

		client.expectResponse().type(CON, NON).storeType("T").code(CONTENT).token(tok).storeMID("A").observe(1).size2(respPayload.length()).block2(0, true, 64).payload(respPayload.substring(0, 64)).go();
		if (client.get("T") == CON)
			client.sendEmpty(ACK).loadMID("A").go();

		Token tok2 = generateNextToken();
		client.sendRequest(CON, GET, tok2, ++mid).path(RESOURCE_PATH).block2(1, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok2, mid).block2(1, true, 64).noOption(OBSERVE).payload(respPayload.substring(64, 128)).go();

		client.sendRequest(CON, GET, tok2, ++mid).path(RESOURCE_PATH).block2(2, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok2, mid).block2(2, false, 64).noOption(OBSERVE).payload(respPayload.substring(128, 140)).go();

		System.out.println("Send second notification");
		serverInterceptor.logNewLine("... time passes ...");
		respPayload = generateRandomPayload(145);
		testResource.changed(); // Second notification

		client.expectResponse().type(CON, NON).storeType("T").code(CONTENT).token(tok).storeMID("A").observe(2).size2(respPayload.length()).block2(0, true, 64).payload(respPayload.substring(0, 64)).go();
		if (client.get("T") == CON)
			client.sendEmpty(ACK).loadMID("A").go();

		Token tok3 = generateNextToken();
		client.sendRequest(CON, GET, tok3, ++mid).path(RESOURCE_PATH).block2(1, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok3, mid).block2(1, true, 64).noOption(OBSERVE).payload(respPayload.substring(64, 128)).go();

		client.sendRequest(CON, GET, tok3, ++mid).path(RESOURCE_PATH).block2(2, false, 64).go();
		client.expectResponse(ACK, CONTENT, tok3, mid).block2(2, false, 64).noOption(OBSERVE).payload(respPayload.substring(128, 145)).go();

		testResource.clearObserveRelations();
	}

	// All tests are made with this resource
	private class TestResource extends CoapResource {

		public TestResource(String name) { 
			super(name);
		}

		public void handleGET(final CoapExchange exchange) {
			Response resp = Response.createResponse(exchange.advanced().getRequest(), ResponseCode.CONTENT);
			resp.setPayload(respPayload);
			respond(exchange, resp);
		}

		public void handlePUT(final CoapExchange exchange) {
			assertThat("server did not receive expected request payload", exchange.getRequestText(), is(reqtPayload));
			if (expectedMid != null) {
				assertThat("request did not contain expected MID", exchange.advanced().getRequest().getMID(), is(expectedMid));
			}
			if (expectedToken != null) {
				assertThat("request did not contain expected token", exchange.advanced().getRequest().getToken(), is(expectedToken));
			}
			Response resp = Response.createResponse(exchange.advanced().getRequest(), ResponseCode.CHANGED);
			resp.setPayload(respPayload);
			respond(exchange, resp);
		}

		public void handlePOST(final CoapExchange exchange) {
			assertThat("server did not receive expected request payload", exchange.getRequestText(), is(reqtPayload));
			Response resp = Response.createResponse(exchange.advanced().getRequest(), ResponseCode.CHANGED);
			resp.setPayload(respPayload);
			respond(exchange, resp);
		}

		private void respond (final CoapExchange exchange, final Response response) {
			if (etag != null) {
				response.getOptions().addETag(etag);
			}
			exchange.respond(response);
		}
	}
}
