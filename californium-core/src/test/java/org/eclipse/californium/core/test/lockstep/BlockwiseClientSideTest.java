/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Bosch Software Innovations GmbH - reduce code duplication, split up into
 *                                      separate test cases, remove wait cycles
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CoapNetworkRule for
 *                                                    setup of test-network
 *    Achim Kraus (Bosch Software Innovations GmbH) - add testGETWithDisorderedResponses
 *                                                    (see hudson 2.0.x/146, issue #275)
 *    Achim Kraus (Bosch Software Innovations GmbH) - add MID expectation for
 *                                                    smart deduplication
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce fields for timeouts.
 *                                                    increase response timeout
 *                                                    for error tests. 50 ms 
 *                                                    seems to be too short on
 *                                                    slow hosts.
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import static org.eclipse.californium.TestTools.generateRandomPayload;
import static org.eclipse.californium.core.coap.CoAP.Code.GET;
import static org.eclipse.californium.core.coap.CoAP.Code.POST;
import static org.eclipse.californium.core.coap.CoAP.Code.PUT;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CHANGED;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTINUE;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.REQUEST_ENTITY_INCOMPLETE;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.REQUEST_ENTITY_TOO_LARGE;
import static org.eclipse.californium.core.coap.CoAP.Type.ACK;
import static org.eclipse.californium.core.coap.CoAP.Type.CON;
import static org.eclipse.californium.core.coap.OptionNumberRegistry.OBSERVE;
import static org.eclipse.californium.core.test.MessageExchangeStoreTool.assertAllExchangesAreCompleted;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.assertNumberOfReceivedNotifications;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.assertResponseContainsExpectedPayload;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.createLockstepEndpoint;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.createRequest;
import static org.eclipse.californium.core.test.lockstep.IntegrationTestTools.printServerLog;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.concurrent.TimeUnit;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.test.CountingCoapHandler;
import org.eclipse.californium.core.test.CountingMessageObserver;
import org.eclipse.californium.core.test.ErrorInjector;
import org.eclipse.californium.core.test.MessageExchangeStoreTool.CoapTestEndpoint;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.rule.TestTimeRule;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * Test cases verifying the client side behavior of the examples from
 * <a href="https://tools.ietf.org/html/rfc7959#section-3">RFC 7958, Section 3</em>.
 */
@Category(Medium.class)
public class BlockwiseClientSideTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestTimeRule time = new TestTimeRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final int TEST_EXCHANGE_LIFETIME = 247; // milliseconds
	private static final int TEST_SWEEP_DEDUPLICATOR_INTERVAL = 100; // milliseconds
	private static final int TEST_BLOCKWISE_STATUS_INTERVAL = 50;
	private static final int TEST_BLOCKWISE_STATUS_LIFETIME = 300;

	private static final int MAX_RESOURCE_BODY_SIZE = 1024;
	private static final int RESPONSE_TIMEOUT_IN_MS = 1000;
	private static final int ERROR_TIMEOUT_IN_MS = 500;
	// client retransmits after 200 ms
	private static final int ACK_TIMEOUT_IN_MS = 200;

	private NetworkConfig config;

	private LockstepEndpoint server;
	private CoapTestEndpoint client;
	private int mid = 8000;
	private String respPayload;
	private String reqtPayload;
	private ClientBlockwiseInterceptor clientInterceptor = new ClientBlockwiseInterceptor();

	@Before
	public void setup() throws Exception {
		config = network.createStandardTestConfig()
				.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 128)
				.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, 128)
				.setInt(NetworkConfig.Keys.MAX_RESOURCE_BODY_SIZE, MAX_RESOURCE_BODY_SIZE)
				.setInt(NetworkConfig.Keys.MARK_AND_SWEEP_INTERVAL, TEST_SWEEP_DEDUPLICATOR_INTERVAL)
				.setLong(NetworkConfig.Keys.EXCHANGE_LIFETIME, TEST_EXCHANGE_LIFETIME)
				.setInt(NetworkConfig.Keys.ACK_TIMEOUT, ACK_TIMEOUT_IN_MS)
				.setInt(NetworkConfig.Keys.ACK_RANDOM_FACTOR, 1)
				.setInt(NetworkConfig.Keys.MAX_RETRANSMIT, 2)
				.setInt(NetworkConfig.Keys.ACK_TIMEOUT_SCALE, 1)
				.setInt(NetworkConfig.Keys.BLOCKWISE_STATUS_INTERVAL, TEST_BLOCKWISE_STATUS_INTERVAL)
				.setInt(NetworkConfig.Keys.BLOCKWISE_STATUS_LIFETIME, TEST_BLOCKWISE_STATUS_LIFETIME);

		client = new CoapTestEndpoint(TestTools.LOCALHOST_EPHEMERAL, config);
		cleanup.add(client);
		client.addInterceptor(clientInterceptor);
		client.start();
		System.out.println("Client binds to port " + client.getAddress().getPort());
		server = createLockstepEndpoint(client.getAddress());
		cleanup.add(server);
	}

	@After
	public void shutdown() {
		try {
			assertAllExchangesAreCompleted(client, time);
		} finally {
			printServerLog(clientInterceptor);
		}
	}

	/**
	 * Verifies that a client's request is cancelled if the response body exceeds
	 * MAX_RESOURCE_BODY_SIZE.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testRequestIsCancelledIfBodyExceedsMaxBodySize() throws Exception {

		respPayload = generateRandomPayload(128);
		String path = "test";
		Request request = createRequest(GET, path, server);

		client.sendRequest(request);
		server.expectRequest(CON, GET, path).storeBoth("A").go();
		server.sendResponse(ACK, CONTENT).loadBoth("A").size2(MAX_RESOURCE_BODY_SIZE + 10).block2(0, true, 128).payload(respPayload).go();

		request.waitForResponse(ERROR_TIMEOUT_IN_MS);
		assertTrue("Request should have been cancelled", request.isCanceled());
		assertThat("Request should have failed with error", request.getOnResponseError(), is(notNullValue()));
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
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testGET() throws Exception {
		System.out.println("Simple blockwise GET:");
		respPayload = generateRandomPayload(300);
		String path = "test";
		byte[] etag = new byte[]{ 0x00, 0x01 };

		Request request = createRequest(GET, path, server);
		client.sendRequest(request);

		server.expectRequest(CON, GET, path).storeBoth("A").go();
		server.sendResponse(ACK, CONTENT).loadBoth("A").block2(0, true, 128).size2(respPayload.length())
			.etag(etag).payload(respPayload.substring(0, 128)).go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 128).go();
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 128).etag(etag).payload(respPayload.substring(128, 256)).go();
		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 128).go();
		server.sendResponse(ACK, CONTENT).loadBoth("C").block2(2, false, 128).etag(etag).payload(respPayload.substring(256, 300)).go();

		Response response = request.waitForResponse(RESPONSE_TIMEOUT_IN_MS);
		assertResponseContainsExpectedPayload(response, respPayload);
	}

	/**
	 * Shows 2 successful complete transfers. The second one should not
	 * terminate before TEST_BLOCKWISE_STATUS_LIFETIME. The idea is to ensure
	 * than cleaning task is well canceled at the end of the first block
	 * transfer.
	 * 
	 * <pre>
	 * CON [MID=1620, T=[2a7b3c2bcdb8b5d8]], GET, /test    ----->
	 * <-----   ACK [MID=1620, T=[2a7b3c2bcdb8b5d8]], 2.05, 2:0/1/128
	 * CON [MID=1621, T=[2a7b3c2bcdb8b5d8]], GET, /test, 2:1/0/128    ----->
	 * CON [MID=1621, T=[2a7b3c2bcdb8b5d8]], GET, /test, 2:1/0/128    ----->
	 * <-----   ACK [MID=1621, T=[2a7b3c2bcdb8b5d8]], 2.05, 2:1/1/128
	 * CON [MID=1622, T=[2a7b3c2bcdb8b5d8]], GET, /test, 2:2/0/128    ----->
	 * CON [MID=1622, T=[2a7b3c2bcdb8b5d8]], GET, /test, 2:2/0/128    ----->
	 * <-----   ACK [MID=1622, T=[2a7b3c2bcdb8b5d8]], 2.05, 2:2/0/128
	 * // next transfer 
	 * CON [MID=1623, T=[ce9a89078049f125]], GET, /test    ----->
	 * <-----   ACK [MID=1623, T=[ce9a89078049f125]], 2.05, 2:0/1/128
	 * CON [MID=1624, T=[ce9a89078049f125]], GET, /test, 2:1/0/128    ----->
	 * CON [MID=1624, T=[ce9a89078049f125]], GET, /test, 2:1/0/128    ----->
	 * <-----   ACK [MID=1624, T=[ce9a89078049f125]], 2.05, 2:1/1/128
	 * CON [MID=1625, T=[ce9a89078049f125]], GET, /test, 2:2/0/128    ----->
	 * CON [MID=1625, T=[ce9a89078049f125]], GET, /test, 2:2/0/128    ----->
	 * <-----   ACK [MID=1625, T=[ce9a89078049f125]], 2.05, 2:2/0/128
	 * </pre>
	 */
	@Test
	public void test2ConsecutiveCompleteGET() throws Exception {

		System.out.println("2 consecutive complete GET with block2 transfers:");
		respPayload = generateRandomPayload(300);
		String path = "test";

		// Send GET request
		Request request = createRequest(GET, path, server);
		client.sendRequest(request);
		server.expectRequest(CON, GET, path).storeBoth("A").go();

		server.sendResponse(ACK, CONTENT).loadBoth("A").block2(0, true, 128).payload(respPayload.substring(0, 128))
				.go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 128).go();
		Thread.sleep((long) (TEST_BLOCKWISE_STATUS_LIFETIME * 0.75));

		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 128).payload(respPayload.substring(128, 256))
				.go();
		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 128).go();
		Thread.sleep((long) (TEST_BLOCKWISE_STATUS_LIFETIME * 0.75));

		server.sendResponse(ACK, CONTENT).loadBoth("C").block2(2, false, 128).payload(respPayload.substring(256, 300))
				.go();

		// We get the response the transfer is complete : BlockwiseLayer should
		// be empty
		request.waitForResponse();
		assertTrue("BlockwiseLayer should be empty", client.getStack().getBlockwiseLayer().isEmpty());

		clientInterceptor.logNewLine("// next transfer");
		request = createRequest(GET, path, server);
		client.sendRequest(request);
		server.expectRequest(CON, GET, path).storeBoth("A").go();

		server.sendResponse(ACK, CONTENT).loadBoth("A").block2(0, true, 128).payload(respPayload.substring(0, 128))
				.go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 128).go();
		Thread.sleep((long) (TEST_BLOCKWISE_STATUS_LIFETIME * 0.75));

		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 128).payload(respPayload.substring(128, 256))
				.go();
		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 128).go();
		Thread.sleep((long) (TEST_BLOCKWISE_STATUS_LIFETIME * 0.75));

		server.sendResponse(ACK, CONTENT).loadBoth("C").block2(2, false, 128).payload(respPayload.substring(256, 300))
				.go();

		// We get the response the transfer is complete : BlockwiseLayer should
		// be empty
		request.waitForResponse();
		assertTrue("BlockwiseLayer should be empty", client.getStack().getBlockwiseLayer().isEmpty());

		printServerLog(clientInterceptor);
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
	 * |                                                          |
	 * | CON [MID=1236], GET, /status, 2:2/0/64           ------> |
	 * |                                                          |
	 * | <------   ACK [MID=1239], 2.05 Content, 2:2/0/64         |
	 * </pre>
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testGETEarlyNegotiation() throws Exception {
		System.out.println("Blockwise GET with early negotiation:");
		respPayload = generateRandomPayload(170);
		String path = "test";

		Request request = createRequest(GET, path, server);
		request.getOptions().setBlock2(BlockOption.size2Szx(64), false, 0);
		client.sendRequest(request);

		server.expectRequest(CON, GET, path).storeBoth("A").block2(0, false, 64).go();
		server.sendResponse(ACK, CONTENT).loadBoth("A").block2(0, true, 64).size2(respPayload.length()).payload(respPayload, 0, 64).go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 64).go();
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 64).payload(respPayload, 64, 128).go();
		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 64).go();
		server.sendResponse(ACK, CONTENT).loadBoth("C").block2(2, false, 64).payload(respPayload, 128, 170).go();

		Response response = request.waitForResponse(RESPONSE_TIMEOUT_IN_MS);
		assertResponseContainsExpectedPayload(response, respPayload);
	}

	/**
	 * Block1 late negotiation in the middle of the transfer.
	 */
	@Test
	public void testLateNegotiationInTheMiddle() throws Exception {
		System.out.println("Blockwise PUT with late negotiation in the middle");
		reqtPayload = generateRandomPayload(290);
		String path = "test";

		Request request = createRequest(PUT, path, server);
		request.setPayload(reqtPayload);
		client.sendRequest(request);

		server.expectRequest(CON, PUT, path).storeBoth("A").block1(0, true, 128).size1(reqtPayload.length())
				.payload(reqtPayload.substring(0, 128)).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("A").block1(0, true, 128).go();

		server.expectRequest(CON, PUT, path).storeBoth("B").block1(1, true, 128).payload(reqtPayload.substring(128, 256)).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("B").block1(1, true, 32).go(); // late negotiation

		server.expectRequest(CON, PUT, path).storeBoth("C").block1(8, true, 32).payload(reqtPayload.substring(256, 288)).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("C").block1(8, true, 32).go();

		server.expectRequest(CON, PUT, path).storeBoth("D").block1(9, false, 32)
				.payload(reqtPayload.substring(288, 290)).go();
		server.sendResponse(ACK, CHANGED).loadBoth("D").block1(9, false, 32).go();

		Response response = request.waitForResponse(RESPONSE_TIMEOUT_IN_MS);
		assertThat(response, is(notNullValue()));
		assertThat(response.getPayloadSize(), is(0));
		assertThat(response.getCode(), is(CHANGED));
		assertThat(response.getToken(), is(request.getToken()));
	}

	/**
	 * <pre>
	 * CLIENT                                                     SERVER
     * |                                                          |
     * | CON [MID=1234], GET, /status                     ------> |
     * |                                                          |
     * | <------   ACK [MID=1234], 2.05 Content, 2:0/1/256        |
     * |                                                          |
     * | CON [MID=1235], GET, /status, 2:2/0/128          ------> |
     * |                                                          |
     * | //////////////////////////////////tent, 2:2/1/128        |
     * |                                                          |
     * | (timeout)                                                |
     * |                                                          |
     * | CON [MID=1235], GET, /status, 2:2/0/128          ------> |
     * |                                                          |
     * | <------   ACK [MID=1235], 2.05 Content, 2:2/0/128        |
     * </pre>
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testGETLateNegotiationAndLostACK() throws Exception {

		System.out.println("Blockwise GET with late negotiation and lost ACK:");
		respPayload = generateRandomPayload(300);
		String path = "test";

		Request request = createRequest(GET, path, server);
		client.sendRequest(request);

		server.expectRequest(CON, GET, path).storeBoth("A").go();
		server.sendResponse(ACK, CONTENT).loadBoth("A").block2(0, true, 256).size2(respPayload.length()).payload(respPayload, 0, 256).go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(2, false, 128).go();

		// We lose this ACK, and therefore the client retransmits the CON
		clientInterceptor.log(" // lost");

		server.expectRequest(CON, GET, path).sameBoth("B").block2(2, false, 128).go();

		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(2, false, 128).payload(respPayload, 256, 300).go();

		Response response = request.waitForResponse(RESPONSE_TIMEOUT_IN_MS);
		assertResponseContainsExpectedPayload(response, respPayload);
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
	 * | {CON [MID=1234], GET, /status, 2:0/0/64 (repeat)  ---->} | (skipped, we just send 2 ACKs)
	 * | <------   ACK [MID=1234], 2.05 Content, 2:0/1/64         |
	 * |                                                          |
	 * | CON [MID=1235], GET, /status, 2:1/0/64           ------> |
	 * | <------   ACK [MID=1234], 2.05 Content, 2:0/1/64 (repeat)| (the wrong ACK for the repeat)
	 * |                                                          |
	 * | {<-----   ACK [MID=1235], 2.05 Content, 2:1/1/64 }       | (lost)
	 * |                                                          |
	 * | CON [MID=1235], GET, /status, 2:1/0/64           ------> | (should repeat, but currently missing!)
	 * | <------   ACK [MID=1235], 2.05 Content, 2:1/1/64         |
	 * |                                                          |
	 * | CON [MID=1236], GET, /status, 2:2/0/64           ------> |
	 * |                                                          |
	 * | <------   ACK [MID=1239], 2.05 Content, 2:2/0/64         |
	 * </pre>
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testGETWithDisorderedResponses() throws Exception {
		System.out.println("Blockwise GET with responses disordered:");
		respPayload = generateRandomPayload(170);
		String path = "test";

		Request request = createRequest(GET, path, server);
		request.getOptions().setBlock2(BlockOption.size2Szx(64), false, 0);
		client.sendRequest(request);

		server.expectRequest(CON, GET, path).storeBoth("A").block2(0, false, 64).go();
		// either wait for repeat, or just send two ACK :-)
		server.sendResponse(ACK, CONTENT).loadBoth("A").block2(0, true, 64).size2(respPayload.length()).payload(respPayload, 0, 64).go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 64).go();
		// retransmitted ACK, as if the GET 0 would have been repeated.
		server.sendResponse(ACK, CONTENT).loadBoth("A").block2(0, true, 64).size2(respPayload.length()).payload(respPayload, 0, 64).go();
		// lost ACK
		//server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 64).payload(respPayload, 64, 128).go();

		// repeat GET 1
		server.expectRequest(CON, GET, path).sameBoth("B").block2(1, false, 64).go();
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 64).payload(respPayload, 64, 128).go();

		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 64).go();
		server.sendResponse(ACK, CONTENT).loadBoth("C").block2(2, false, 64).payload(respPayload, 128, 170).go();

		Response response = request.waitForResponse(RESPONSE_TIMEOUT_IN_MS);
		assertResponseContainsExpectedPayload(response, respPayload);
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
		reqtPayload = generateRandomPayload(MAX_RESOURCE_BODY_SIZE + 10);
		String path = "test";

		Request request = createRequest(PUT, path, server);
		request.setPayload(reqtPayload);
		client.sendRequest(request);

		server.expectRequest(CON, PUT, path).storeBoth("A").block1(0, true, 128).size1(reqtPayload.length()).payload(reqtPayload, 0, 128).go();
		server.sendResponse(ACK, REQUEST_ENTITY_TOO_LARGE).loadBoth("A").size1(MAX_RESOURCE_BODY_SIZE).go();

		Response response = request.waitForResponse(ERROR_TIMEOUT_IN_MS);
		assertThat(response, is(notNullValue()));
		assertThat(response.getPayloadSize(), is(0));
		assertThat(response.getCode(), is(REQUEST_ENTITY_TOO_LARGE));
		assertThat(response.getToken(), is(request.getToken()));
		assertThat(response.getMID(), is(request.getMID()));
	}

	/**
	 * Verifies that a block1 transfer with a 4.13 code at beginning with a smaller size1 option is retried with a smaller blocksize.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testBlockwisePUTWithBegining413AndSmallerSZX() throws Exception {

		System.out.println("Block1 with  REQUEST_ENTITY_TOO_LARGE negotiation");
		reqtPayload = generateRandomPayload(128 + 10);
		String path = "test";

		Request request = createRequest(PUT, path, server);
		request.setPayload(reqtPayload);
		client.sendRequest(request);

		server.expectRequest(CON, PUT, path).storeBoth("A").block1(0, true, 128).size1(reqtPayload.length()).payload(reqtPayload, 0, 128).go();
		server.sendResponse(ACK, REQUEST_ENTITY_TOO_LARGE).loadBoth("A").block1(0, false, 64).go();
		server.expectRequest(CON, PUT, path).storeBoth("B").block1(0, true, 64).size1(reqtPayload.length()).payload(reqtPayload, 0, 64).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("B").block1(0, true, 64).go();
		server.expectRequest(CON, PUT, path).storeBoth("C").block1(1, true, 64).payload(reqtPayload, 64, 128).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("C").block1(1, true, 64).go();
		server.expectRequest(CON, PUT, path).storeBoth("D").block1(2, false, 64).payload(reqtPayload, 128, 138).go();
		server.sendResponse(ACK, CHANGED).loadBoth("D").block1(2, false, 64).go();

		Response response = request.waitForResponse(RESPONSE_TIMEOUT_IN_MS);
		assertThat(response, is(notNullValue()));
		assertThat(response.getPayloadSize(), is(0));
		assertThat(response.getCode(), is(CHANGED));
		assertThat(response.getToken(), is(request.getToken()));
	}

	/**
	 * Verifies that none block request will turn in block transfer if 4.13 code
	 * is received at beginning with a smaller size1 option.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testPUTWithBeginning413WithSize1TurnInBlockPUT() throws Exception {

		System.out.println("REQUEST_ENTITY_TOO_LARGE with smaller size1 turn PUT in blockwise transfer");
		reqtPayload = generateRandomPayload(128);
		String path = "test";

		Request request = createRequest(PUT, path, server);
		request.setPayload(reqtPayload);
		client.sendRequest(request);

		server.expectRequest(CON, PUT, path).storeBoth("A").payload(reqtPayload).go();
		server.sendResponse(ACK, REQUEST_ENTITY_TOO_LARGE).loadBoth("A").size1(90).go();
		server.expectRequest(CON, PUT, path).storeBoth("B").block1(0, true, 64).size1(reqtPayload.length()).payload(reqtPayload, 0, 64).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("B").block1(0, true, 64).go();
		server.expectRequest(CON, PUT, path).storeBoth("C").block1(1, false, 64).payload(reqtPayload, 64, 128).go();
		server.sendResponse(ACK, CHANGED).loadBoth("C").block1(1, false, 64).go();

		Response response = request.waitForResponse(RESPONSE_TIMEOUT_IN_MS);
		assertThat(response, is(notNullValue()));
		assertThat(response.getPayloadSize(), is(0));
		assertThat(response.getCode(), is(CHANGED));
		assertThat(response.getToken(), is(request.getToken()));
	}

	/**
	 * Verifies that none block request will turn in block transfer if 4.13 code
	 * is received at beginning with out option.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testPUTWithBeginning413WithoutOptionTurnInBlockPUT() throws Exception {

		System.out.println("REQUEST_ENTITY_TOO_LARGE without option turn PUT in blockwise transfer");
		reqtPayload = generateRandomPayload(128);
		String path = "test";

		Request request = createRequest(PUT, path, server);
		request.setPayload(reqtPayload);
		client.sendRequest(request);

		server.expectRequest(CON, PUT, path).storeBoth("A").payload(reqtPayload).go();
		server.sendResponse(ACK, REQUEST_ENTITY_TOO_LARGE).loadBoth("A").go();
		server.expectRequest(CON, PUT, path).storeBoth("B").block1(0, true, 64).size1(reqtPayload.length()).payload(reqtPayload, 0, 64).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("B").block1(0, true, 64).go();
		server.expectRequest(CON, PUT, path).storeBoth("C").block1(1, false, 64).payload(reqtPayload, 64, 128).go();
		server.sendResponse(ACK, CHANGED).loadBoth("C").block1(1, false, 64).go();

		Response response = request.waitForResponse(RESPONSE_TIMEOUT_IN_MS);
		assertThat(response, is(notNullValue()));
		assertThat(response.getPayloadSize(), is(0));
		assertThat(response.getCode(), is(CHANGED));
		assertThat(response.getToken(), is(request.getToken()));
	}

	/**
	 * Verifies that none block request will turn in block transfer if 4.13 code
	 * is received at beginning with out option, then failed when another 4.13 is raised
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testPUTWithBegining413WithoutOptionTurnInBlockPUTWith413Again() throws Exception {

		System.out.println("REQUEST_ENTITY_TOO_LARGE without option turn PUT in blockwise transfer, then REQUEST_ENTITY_TOO_LARGE again");
		reqtPayload = generateRandomPayload(128);
		String path = "test";

		Request request = createRequest(PUT, path, server);
		request.setPayload(reqtPayload);
		client.sendRequest(request);

		server.expectRequest(CON, PUT, path).storeBoth("A").payload(reqtPayload).go();
		server.sendResponse(ACK, REQUEST_ENTITY_TOO_LARGE).loadBoth("A").go();
		server.expectRequest(CON, PUT, path).storeBoth("B").block1(0, true, 64).size1(reqtPayload.length()).payload(reqtPayload, 0, 64).go();
		server.sendResponse(ACK, REQUEST_ENTITY_TOO_LARGE).loadBoth("B").go();

		Response response = request.waitForResponse(ERROR_TIMEOUT_IN_MS);
		assertThat(response, is(notNullValue()));
		assertThat(response.getPayloadSize(), is(0));
		assertThat(response.getCode(), is(REQUEST_ENTITY_TOO_LARGE));
		assertThat(response.getToken(), is(request.getToken()));
		assertThat(response.getMID(), is(request.getMID()));
	}

	/**
	 * Verifies that none block request will turn in block transfer if 4.13 code
	 * is received at beginning without option, then successfull size negotiation.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testPUTWithBegining413WithoutOptionTurnInBlockPUTWith413BlockSizeNegotiation() throws Exception {

		System.out.println(
				"REQUEST_ENTITY_TOO_LARGE without option turn PUT in blockwise transfer, then REQUEST_ENTITY_TOO_LARGE with block size negotiation");
		reqtPayload = generateRandomPayload(128);
		String path = "test";

		Request request = createRequest(PUT, path, server);
		request.setPayload(reqtPayload);
		client.sendRequest(request);

		server.expectRequest(CON, PUT, path).storeBoth("A").payload(reqtPayload).go();
		server.sendResponse(ACK, REQUEST_ENTITY_TOO_LARGE).loadBoth("A").go();
		server.expectRequest(CON, PUT, path).storeBoth("B").block1(0, true, 64).size1(reqtPayload.length()).payload(reqtPayload, 0, 64).go();
		server.sendResponse(ACK, REQUEST_ENTITY_TOO_LARGE).loadBoth("B").block1(0, true, 32).go(); // size negotiation
		server.expectRequest(CON, PUT, path).storeBoth("C").block1(0, true, 32).size1(reqtPayload.length()).payload(reqtPayload, 0, 32).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("C").block1(0, true, 32).go();
		server.expectRequest(CON, PUT, path).storeBoth("D").block1(1, true, 32).payload(reqtPayload, 32, 64).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("D").block1(1, true, 32).go();
		server.expectRequest(CON, PUT, path).storeBoth("E").block1(2, true, 32).payload(reqtPayload, 64, 96).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("E").block1(2, true, 32).go();
		server.expectRequest(CON, PUT, path).storeBoth("F").block1(3, false, 32).payload(reqtPayload, 96, 128).go();
		server.sendResponse(ACK, CHANGED).loadBoth("F").block1(3, false, 32).go();

		Response response = request.waitForResponse(RESPONSE_TIMEOUT_IN_MS);
		assertThat(response, is(notNullValue()));
		assertThat(response.getPayloadSize(), is(0));
		assertThat(response.getCode(), is(CHANGED));
		assertThat(response.getToken(), is(request.getToken()));
	}

	/**
	 * Verifies that none block request will turn in block transfer if 4.13 code
	 * is received at beginning with a smaller szx option.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testPUTWithBegining413AndSmallerSZXTurnInBlockPUT() throws Exception {

		System.out.println("REQUEST_ENTITY_TOO_LARGE with smaller block size turn PUT in blockwise transfer");
		reqtPayload = generateRandomPayload(128);
		String path = "test";

		Request request = createRequest(PUT, path, server);
		request.setPayload(reqtPayload);
		client.sendRequest(request);

		server.expectRequest(CON, PUT, path).storeBoth("A").payload(reqtPayload).go();
		server.sendResponse(ACK, REQUEST_ENTITY_TOO_LARGE).loadBoth("A").block1(0, false, 64).go();
		server.expectRequest(CON, PUT, path).storeBoth("B").block1(0, true, 64).size1(reqtPayload.length()).payload(reqtPayload, 0, 64).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("B").block1(0, true, 64).go();
		server.expectRequest(CON, PUT, path).storeBoth("C").block1(1, false, 64).payload(reqtPayload, 64, 128).go();
		server.sendResponse(ACK, CHANGED).loadBoth("C").block1(1, false, 64).go();

		Response response = request.waitForResponse(RESPONSE_TIMEOUT_IN_MS);
		assertThat(response, is(notNullValue()));
		assertThat(response.getPayloadSize(), is(0));
		assertThat(response.getCode(), is(CHANGED));
		assertThat(response.getToken(), is(request.getToken()));
	}

	/**
	 * Verifies that a block1 transfer with a 4.13 code in the middle with a smaller szx option is a failure.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testBlockwisePUTWithMiddle413AndSmallerSZX() throws Exception {

		System.out.println("REQUEST_ENTITY_TOO_LARGE with smaller block size received in the middle of block1");
		reqtPayload = generateRandomPayload(260);
		String path = "test";

		Request request = createRequest(PUT, path, server);
		request.setPayload(reqtPayload);
		client.sendRequest(request);

		server.expectRequest(CON, PUT, path).storeBoth("A").block1(0, true, 128).size1(reqtPayload.length()).payload(reqtPayload, 0, 128).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("A").block1(0, false, 128).go();
		server.expectRequest(CON, PUT, path).storeBoth("B").block1(1, true, 128).payload(reqtPayload, 128, 256).go();
		server.sendResponse(ACK, REQUEST_ENTITY_TOO_LARGE).loadBoth("B").block1(1, false, 64).go();

		Response response = request.waitForResponse(ERROR_TIMEOUT_IN_MS);
		assertThat(response, is(notNullValue()));
		assertThat(response.getPayloadSize(), is(0));
		assertThat(response.getCode(), is(REQUEST_ENTITY_TOO_LARGE));
		assertThat(response.getToken(), is(request.getToken()));
		assertThat(response.getMID(), is(request.getMID()));
	}

	/**
	 * Verifies that a block1 transfer with a 4.13 code in the end with a smaller szx option is a failure.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testBlockwisePUTWithEnding413AndSmallerSZX() throws Exception {

		System.out.println("REQUEST_ENTITY_TOO_LARGE with smaller block size received in the middle of block1");
		reqtPayload = generateRandomPayload(250);
		String path = "test";

		Request request = createRequest(PUT, path, server);
		request.setPayload(reqtPayload);
		client.sendRequest(request);

		server.expectRequest(CON, PUT, path).storeBoth("A").block1(0, true, 128).size1(reqtPayload.length()).payload(reqtPayload, 0, 128).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("A").block1(0, false, 128).go();
		server.expectRequest(CON, PUT, path).storeBoth("B").block1(1, false, 128).payload(reqtPayload, 128, 250).go();
		server.sendResponse(ACK, REQUEST_ENTITY_TOO_LARGE).loadBoth("B").block1(1, false, 64).go();

		Response response = request.waitForResponse(ERROR_TIMEOUT_IN_MS);
		assertThat(response, is(notNullValue()));
		assertThat(response.getPayloadSize(), is(0));
		assertThat(response.getCode(), is(REQUEST_ENTITY_TOO_LARGE));
		assertThat(response.getToken(), is(request.getToken()));
		assertThat(response.getMID(), is(request.getMID()));
	}
	/**
	 * Verifies that a block1 transfer with a 4.13 code with an equals szx option failed
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testBlockwisePUTWith413AndEqualsSZX() throws Exception {

		System.out.println("REQUEST_ENTITY_TOO_LARGE with same block size");
		reqtPayload = generateRandomPayload(128 + 10);
		respPayload = generateRandomPayload(30);
		String path = "test";

		Request request = createRequest(PUT, path, server);
		request.setPayload(reqtPayload);
		client.sendRequest(request);

		server.expectRequest(CON, PUT, path).storeBoth("A").block1(0, true, 128).size1(reqtPayload.length()).payload(reqtPayload, 0, 128).go();
		server.sendResponse(ACK, REQUEST_ENTITY_TOO_LARGE).loadBoth("A").block1(0, false, 128).go();
		
		Response response = request.waitForResponse(ERROR_TIMEOUT_IN_MS);
		assertThat(response, is(notNullValue()));
		assertThat(response.getPayloadSize(), is(0));
		assertThat(response.getCode(), is(REQUEST_ENTITY_TOO_LARGE));
		assertThat(response.getToken(), is(request.getToken()));
		assertThat(response.getMID(), is(request.getMID()));
	}

	/**
	 * Verifies that a block1 transfer fails with a 4.08 code if not all blocks are uploaded.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testPUTFailsWith408OnIncompleteTransfer() throws Exception {

		System.out.println("Blockwise PUT fails for incomplete transfer");
		reqtPayload = generateRandomPayload(300);
		String path = "test";

		Request request = createRequest(PUT, path, server);
		request.setPayload(reqtPayload);
		client.sendRequest(request);

		server.expectRequest(CON, PUT, path).storeBoth("A").block1(0, true, 128).size1(reqtPayload.length()).payload(reqtPayload, 0, 128).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("A").block1(0, true, 128).go();

		server.expectRequest(CON, PUT, path).storeBoth("A").block1(1, true, 128).payload(reqtPayload, 128, 256).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("A").block1(1, true, 128).go();

		// now let's assume that the transfer of the previous block did not happen
		// but the client instead sends the last block without having sent the middle one at all
		server.expectRequest(CON, PUT, path).storeBoth("A").block1(2, false, 128).payload(reqtPayload, 256, 300).go();
		server.sendResponse(ACK, REQUEST_ENTITY_INCOMPLETE).loadBoth("A").go();

		Response response = request.waitForResponse(ERROR_TIMEOUT_IN_MS);
		assertThat(response, is(notNullValue()));
		assertThat(response.getPayloadSize(), is(0));
		assertThat(response.getCode(), is(REQUEST_ENTITY_INCOMPLETE));
		assertThat(response.getToken(), is(request.getToken()));
		assertThat(response.getMID(), is(request.getMID()));
	}

	/**
	 * Verifies that a second concurrent block1 transfer to the same resource cancels the original
	 * request and transfer and starts a new block1 transfer.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testConcurrentBlock1TransferCancelsOriginalRequest() throws Exception {

		System.out.println("Concurrent blockwise PUT cancels original request/transfer");
		reqtPayload = generateRandomPayload(300);
		String path = "test";

		Request request = createRequest(PUT, path, server);
		request.setPayload(reqtPayload);
		client.sendRequest(request);

		server.expectRequest(CON, PUT, path).storeBoth("A").block1(0, true, 128).size1(reqtPayload.length()).payload(reqtPayload, 0, 128).go();

		// now a second concurrent request is issued
		Request concurrentRequest = createRequest(PUT, path, server);
		concurrentRequest.setPayload(reqtPayload);
		client.sendRequest(concurrentRequest);

		server.expectRequest(CON, PUT, path).storeBoth("B").block1(0, true, 128).size1(reqtPayload.length()).payload(reqtPayload, 0, 128).go();

		// acknowledgement of first block of original request is discarded
		server.sendResponse(ACK, CONTINUE).loadBoth("A").block1(0, true, 128).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("B").block1(0, true, 128).go();

		server.expectRequest(CON, PUT, path).storeBoth("B").block1(1, true, 128).payload(reqtPayload, 128, 256).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("B").block1(1, true, 128).go();

		server.expectRequest(CON, PUT, path).storeBoth("B").block1(2, false, 128).payload(reqtPayload, 256, 300).go();
		server.sendResponse(ACK, CHANGED).loadBoth("B").go();

		Response response = concurrentRequest.waitForResponse(ERROR_TIMEOUT_IN_MS);
		assertThat(response, is(notNullValue()));
		assertThat(response.getPayloadSize(), is(0));
		assertThat(response.getCode(), is(CHANGED));
		assertThat(response.getToken(), is(concurrentRequest.getToken()));
		assertTrue(request.isCanceled());
	}

	/**
	 * The following examples demonstrate a PUT exchange; a POST exchange looks
	 * the same, with different requirements on atomicity/idempotency. Note
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
		reqtPayload = generateRandomPayload(300);
		respPayload = generateRandomPayload(50);
		String path = "test";

		Request request = createRequest(PUT, path, server);
		request.setPayload(reqtPayload);
		client.sendRequest(request);

		server.expectRequest(CON, PUT, path).storeBoth("A").block1(0, true, 128).size1(reqtPayload.length()).payload(reqtPayload.substring(0, 128)).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("A").block1(0, true, 128).go();

		server.expectRequest(CON, PUT, path).storeBoth("B").block1(1, true, 128).payload(reqtPayload.substring(128, 256)).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("B").block1(1, true, 128).go();

		server.expectRequest(CON, PUT, path).storeBoth("C").block1(2, false, 128).go();
		server.sendResponse(ACK, CHANGED).loadBoth("C").block1(2, false, 128).payload(respPayload).go();

		Response response = request.waitForResponse(RESPONSE_TIMEOUT_IN_MS);
		assertResponseContainsExpectedPayload(response, CHANGED, respPayload);
	}

	/**
	 * A server receiving a block-wise PUT indicates a smaller block size
	 * preference. In this case, the client SHOULD continue with a smaller block
	 * size; if it does, it MUST adjust the block number to properly count in
	 * that smaller size.
	 * 
	 * <pre>
	 * CLIENT                                                     SERVER
	 * |                                                          |
	 * | CON [MID=1234], PUT, /options, 1:0/1/128    ------>      |
	 * |                                                          |
	 * | <------   ACK [MID=1234], 2.31 Continue, 1:0/1/32        |
	 * |                                                          |
	 * | CON [MID=1235], PUT, /options, 1:4/1/32     ------>      |
	 * |                                                          |
	 * | <------   ACK [MID=1235], 2.31 Continue, 1:4/1/32        |
	 * |                                                          |
	 * | CON [MID=1236], PUT, /options, 1:5/1/32     ------>      |
	 * |                                                          |
	 * | <------   ACK [MID=1235], 2.31 Continue, 1:5/1/32        |
	 * |                                                          |
	 * | CON [MID=1237], PUT, /options, 1:6/0/32     ------>      |
	 * |                                                          |
	 * | <------   ACK [MID=1236], 2.04 Changed, 1:6/0/32         |
	 * </pre>
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testSimpleAtomicBlockwisePUTWithSmallerNegotiation() throws Exception {
		System.out.println("Simple atomic blockwise PUT with smaller size negotiation");
		reqtPayload = generateRandomPayload(200);
		respPayload = generateRandomPayload(50);
		String path = "test";

		Request request = createRequest(PUT, path, server);
		request.setPayload(reqtPayload);
		client.sendRequest(request);

		server.expectRequest(CON, PUT, path).storeBoth("A").block1(0, true, 128).size1(reqtPayload.length())
				.payload(reqtPayload.substring(0, 128)).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("A").block1(0, true, 32).go();

		server.expectRequest(CON, PUT, path).storeBoth("B").block1(4, true, 32).payload(reqtPayload.substring(128, 160)).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("B").block1(4, true, 32).go();

		server.expectRequest(CON, PUT, path).storeBoth("C").block1(5, true, 32).payload(reqtPayload.substring(160, 192)).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("C").block1(5, true, 32).go();

		server.expectRequest(CON, PUT, path).storeBoth("D").block1(6, false, 32)
				.payload(reqtPayload.substring(192, 200)).go();
		server.sendResponse(ACK, CHANGED).loadBoth("D").block1(6, false, 32).payload(respPayload).go();

		Response response = request.waitForResponse(RESPONSE_TIMEOUT_IN_MS);
		assertResponseContainsExpectedPayload(response, CHANGED, respPayload);
	}

	/**
	 * A server receiving a block-wise PUT and indicates a bigger block size
	 * preference. In this case, the client SHOULD continue with the same block
	 * size as requesting a bigger size is not allowed.
	 * 
	 * <pre>
	 * CLIENT                                                     SERVER
	 * |                                                          |
	 * | CON [MID=1234], PUT, /options, 1:0/1/128    ------>      |
	 * |                                                          |
	 * | <------   ACK [MID=1234], 2.31 Continue, 1:0/1/256       |
	 * |                                                          |
	 * | CON [MID=1235], PUT, /options, 1:1/1/128    ------>      |
	 * |                                                          |
	 * | <------   ACK [MID=1235], 2.31 Continue, 1:1/1/256       |
	 * |                                                          |
	 * | CON [MID=1236], PUT, /options, 1:2/0/128    ------>      |
	 * |                                                          |
	 * | <------   ACK [MID=1236], 2.04 Changed, 1:2/0/256        |
	 * </pre>
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testSimpleAtomicBlockwisePUTWithBiggerNegotiation() throws Exception {
		System.out.println("Simple atomic blockwise PUT with bigger size negotiation");
		reqtPayload = generateRandomPayload(300);
		respPayload = generateRandomPayload(50);
		String path = "test";

		Request request = createRequest(PUT, path, server);
		request.setPayload(reqtPayload);
		client.sendRequest(request);

		server.expectRequest(CON, PUT, path).storeBoth("A").block1(0, true, 128).size1(reqtPayload.length())
				.payload(reqtPayload.substring(0, 128)).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("A").block1(0, true, 256).go();

		server.expectRequest(CON, PUT, path).storeBoth("B").block1(1, true, 128)
				.payload(reqtPayload.substring(128, 256)).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("B").block1(1, true, 256).go();

		server.expectRequest(CON, PUT, path).storeBoth("C").block1(2, false, 128)
				.payload(reqtPayload.substring(256, 300)).go();
		server.sendResponse(ACK, CHANGED).loadBoth("C").block1(2, false, 256).payload(respPayload).go();

		Response response = request.waitForResponse(RESPONSE_TIMEOUT_IN_MS);
		assertResponseContainsExpectedPayload(response, CHANGED, respPayload);
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
		reqtPayload = generateRandomPayload(300);
		respPayload = generateRandomPayload(500);
		String path = "test";
		byte[] tag = new byte[]{0x00, 0x01};

		Request request = createRequest(POST, path, server);
		request.setPayload(reqtPayload);
		client.sendRequest(request);

		server.expectRequest(CON, POST, path).storeBoth("A").block1(0, true, 128).size1(reqtPayload.length())
				.payload(reqtPayload.substring(0, 128)).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("A").block1(0, true, 128).go();

		server.expectRequest(CON, POST, path).storeBoth("B").block1(1, true, 128).payload(reqtPayload.substring(128, 256)).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("B").block1(1, true, 128).go();

		server.expectRequest(CON, POST, path).storeBoth("C").block1(2, false, 128).payload(reqtPayload.substring(256, 300)).go();
		server.sendResponse(ACK, CHANGED).loadBoth("C").block1(2, false, 128).block2(0, true, 128).size2(respPayload.length())
				.etag(tag).payload(respPayload.substring(0, 128)).go();

		server.expectRequest(CON, POST, path).storeBoth("D").block2(1, false, 128).go();
		server.sendResponse(ACK, CHANGED).loadBoth("D").block2(1, true, 128).etag(tag).payload(respPayload.substring(128, 256)).go();

		server.expectRequest(CON, POST, path).storeBoth("E").block2(2, false, 128).go();
		server.sendResponse(ACK, CHANGED).loadBoth("E").block2(2, true, 128).etag(tag).payload(respPayload.substring(256, 384)).go();

		server.expectRequest(CON, POST, path).storeBoth("F").block2(3, false, 128).go();
		server.sendResponse(ACK, CHANGED).loadBoth("F").block2(3, false, 128).etag(tag).payload(respPayload.substring(384, 500)).go();

		Response response = request.waitForResponse(RESPONSE_TIMEOUT_IN_MS);
		printServerLog(clientInterceptor);
		assertResponseContainsExpectedPayload(response, CHANGED, respPayload);
	}

	@Test
	public void testRandomAccessGET() throws Exception {

		System.out.println("Random access GET");
		respPayload = generateRandomPayload(300);
		String path = "test";

		Request request = createRequest(GET, path, server);
		request.getOptions().setBlock2(new BlockOption(BlockOption.size2Szx(128), false, 2));
		client.sendRequest(request);

		server.expectRequest(CON, GET, path).storeBoth("A").block2(2, false, 128).go();
		server.sendResponse(ACK, CONTENT).loadBoth("A").block2(2, false, 128).payload(respPayload.substring(256)).go();

		Response response = request.waitForResponse(RESPONSE_TIMEOUT_IN_MS);
		printServerLog(clientInterceptor);
		assertResponseContainsExpectedPayload(response, CONTENT, respPayload.substring(256));
	}

	@Test
	public void testObserveWithBlockwiseResponse() throws Exception {

		System.out.println("Observe sequence with blockwise response:");
		respPayload = generateRandomPayload(300);
		String path = "test1";

		Request request = createRequest(GET, path, server);
		request.setObserve();
		SynchronousNotificationListener notificationListener = new SynchronousNotificationListener(request);
		client.addNotificationListener(notificationListener);
		client.sendRequest(request);

		System.out.println("Establish observe relation to " + path);

		server.expectRequest(CON, GET, path).storeToken("At").storeMID("Am").observe(0).go();
		server.sendResponse(ACK, CONTENT).loadToken("At").loadMID("Am").observe(62350).block2(0, true, 128).size2(respPayload.length())
			.payload(respPayload.substring(0, 128)).go();

		server.expectRequest(CON, GET, path).storeBoth("B").noOption(OBSERVE).block2(1, false, 128).go();
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 128).payload(respPayload.substring(128, 256)).go();

		server.expectRequest(CON, GET, path).storeBoth("C").noOption(OBSERVE).block2(2, false, 128).go();
		server.sendResponse(ACK, CONTENT).loadBoth("C").block2(2, false, 128).payload(respPayload.substring(256)).go();

		Response response = request.waitForResponse(RESPONSE_TIMEOUT_IN_MS);
		assertResponseContainsExpectedPayload(response, respPayload);
		notificationListener.resetNotificationCount();

		System.out.println("Server sends first notification...");
		clientInterceptor.logNewLine("... time passes ...");
		respPayload = generateRandomPayload(280);

		server.sendResponse(CON, CONTENT).loadToken("At").mid(++mid).observe(62354).block2(0, true, 128).size2(respPayload.length())
			.payload(respPayload.substring(0, 128)).go();
		server.startMultiExpectation();
		server.expectEmpty(ACK, mid).go();

		server.expectRequest(CON, GET, path).storeBoth("D").noOption(OBSERVE).block2(1, false, 128).go();
		server.goMultiExpectation();
		server.sendResponse(ACK, CONTENT).loadBoth("D").block2(1, true, 128).payload(respPayload.substring(128, 256)).go();

		server.expectRequest(CON, GET, path).storeBoth("E").noOption(OBSERVE).block2(2, false, 128).go();
		server.sendResponse(ACK, CONTENT).loadBoth("E").block2(2, false, 128).payload(respPayload.substring(256)).go();

		Response notification1 = notificationListener.waitForResponse(RESPONSE_TIMEOUT_IN_MS);
		assertResponseContainsExpectedPayload(notification1, respPayload);
		assertNumberOfReceivedNotifications(notificationListener, 1, true);

		System.out.println("Server sends second notification...");
		clientInterceptor.logNewLine("... time passes ...");
		respPayload = generateRandomPayload(290);

		server.sendResponse(CON, CONTENT).loadToken("At").mid(++mid).observe(17).block2(0, true, 128).size2(respPayload.length())
			.payload(respPayload.substring(0, 128)).go();
		server.startMultiExpectation();
		server.expectEmpty(ACK, mid).go();

		// expect blockwise transfer for second notification (17)
		server.expectRequest(CON, GET, path).storeBoth("F").noOption(OBSERVE).block2(1, false, 128).go();
		server.goMultiExpectation();

		System.out.println("Server sends third notification during transfer ");
		server.sendResponse(CON, CONTENT).loadToken("At").mid(++mid).observe(19).block2(0, true, 128).size2(respPayload.length())
			.payload(respPayload.substring(0, 128)).go();

		// in between, server sends response for request for block 1 for observe 17
		// this response will be discarded by the client because a newer notification (19) has arrived in the meantime
		server.sendResponse(ACK, CONTENT).loadBoth("F").block2(1, true, 128).payload(respPayload.substring(128,  256)).go();

		server.startMultiExpectation();
		server.expectEmpty(ACK, mid).go();

		// expect blockwise transfer for third notification (19)
		server.expectRequest(CON, GET, path).storeBoth("G").noOption(OBSERVE).block2(1, false, 128).go();
		server.goMultiExpectation();

		System.out.println("Send old notification during transfer");
		// this old notification will be discarded by the client
		server.sendResponse(CON, CONTENT).loadToken("At").mid(++mid).observe(18).block2(0, true, 128).size2(respPayload.length())
			.payload(respPayload.substring(0, 128)).go();

		// response for 2nd block of notification 19
		server.sendResponse(ACK, CONTENT).loadBoth("G").block2(1, true, 128).payload(respPayload.substring(128, 256)).go();
		server.startMultiExpectation();
		server.expectEmpty(ACK, mid).go();
		// client retrieves rest of body
		server.expectRequest(CON, GET, path).storeBoth("I").noOption(OBSERVE).block2(2, false, 128).go();
		server.goMultiExpectation();

		server.sendResponse(ACK, CONTENT).loadBoth("I").block2(2, false, 128).payload(respPayload.substring(256)).go();

		Response notification2 = notificationListener.waitForResponse(RESPONSE_TIMEOUT_IN_MS);
		assertResponseContainsExpectedPayload(notification2, respPayload);
		assertNumberOfReceivedNotifications(notificationListener, 1, true);
	}

	@Test
	public void testObserveWithBlockwiseResponseEarlyNegotiation() throws Exception {
		System.out.println("TODO: Observe sequence with early negotiation: (low priority for Cf client)");
		// TODO: This is not really a problem for the Cf client because it has
		// no block size preference. We might only allow a developer to enforce
		// a specific block size but this currently has low priority.
	}

	/**
	 * This example shows a blockwise GET request which cannot get an
	 * intermediate ACK so the client should call CoapHandler#onError
	 *
	 * <pre>
	 * CLIENT                                                     SERVER
	 * |                                                            |
	 * | CON [MID=1234], GET, /status                       ------> |
	 * |                                                            |
	 * | <------   ACK [MID=1234], 2.05 Content, 2:0/1/128          |
	 * |                                                            |
	 * | CON [MID=1235], GET, /status, 2:1/0/128            ------> |
	 * |                                                            |
	 * |     X----   ACK [MID=1235], 2.05 Content, 2:1/1/128        |
	 * |                                                            |
	 * | CON [MID=1235], GET, /status, 2:1/0/128            ------> |
	 * |                                                            |
	 * |     X----   ACK [MID=1235], 2.05 Content, 2:1/1/128        |
	 * |__                                                          |
	 * |  |                                                         |
	 * |  |  calls CoapHandler#onError                              |
	 * |<-                                                          |
	 * |__                                                          |
	 * </pre>
	 */
	@Test
	public void testGETCallsOnErrorAfterLostACK() throws Exception {
		String path = "test";

		CountingCoapHandler handler = new CountingCoapHandler();
		System.out.println("Blockwise GET with Lost ACK:");

		respPayload = generateRandomPayload(300);

		CoapClient coapClient = new CoapClient("coap", server.getAddress().getHostAddress(), server.getPort(), path);
		coapClient.setEndpoint(client);
		Request request = createRequest(GET, path, server);

		coapClient.advanced(handler, request);

		server.expectRequest(CON, GET, path).storeBoth("A").go();
		server.sendResponse(ACK, CONTENT).loadBoth("A").block2(0, true, 128).payload(respPayload.substring(0, 128)).go();

		assertTrue(handler.waitOnErrorCalls(1, 3, TimeUnit.SECONDS));
		coapClient.shutdown();
	}
	
	/**
	 * Verifies, If a blockwise GET is interrupted by a new blockwise GET then we cancel the first one and handle the second one.
	 * 
	 * <pre>
	 * (actual used MIDs and Tokens my vary!)
	 * ####### send a GET request, the response uses block2  #############
	 * CON [MID=29825, T=8609f30de68aa280], GET, /test    ----->
	 * <-----   ACK [MID=29825, T=8609f30de68aa280], 2.05, 2:0/1/128
	 * CON [MID=29826, T=8609f30de68aa280], GET, /test, 2:1/0/128    ---->
	 * ####### the blockwise transfer is not finished  #############
     * ####### send a second GET request, the response uses block2 too  #############
	 * CON [MID=29827, T=2cf017b44e032b29], GET, /test    ----->
     * <-----   ACK [MID=29827, T=2cf017b44e032b29], 2.05, 2:0/1/128
     * CON [MID=29828, T=2cf017b44e032b29], GET, /test, 2:1/0/128    ----->
     * ####### send 2nd block of the 1st blockwise transfert (should be ignored) ########
     * <-----   ACK [MID=29826, T=8609f30de68aa280], 2.05, 2:1/0/128
     * ####### send the last block of the 2nd blockwise transfert  ########
	 * <-----   ACK [MID=29828, T=2cf017b44e032b29], 2.05, 2:1/0/128
     * ####### ensure we get the response of the second one and the first one is canceled ##########
	 * </pre>
	 * 
	 * @throws Exception
	 */
	@Test
	public void testBlockwiseGetInterruptedByBlockwiseGet() throws Exception {
		System.out.println("Blockwise Observe:");
		String path = "test";
		
		// Send first GET request
		Request firstRequest = createRequest(GET, path, server);
		client.sendRequest(firstRequest);
		server.expectRequest(CON, GET, path).storeBoth("FIRST_GET").go();
		// Send blockwise response
		respPayload = generateRandomPayload(256);
		server.sendResponse(ACK, CONTENT).loadBoth("FIRST_GET").block2(0, true, 128)
				.payload(respPayload.substring(0, 128)).go();
		// Expect next block request
		server.expectRequest(CON, GET, path).storeBoth("FIRST_GET_BLOCK").block2(1, false, 128).go();
		// Block transfert not completed.....
		
		// Send second GET Request
		Request secondRequest = createRequest(GET, path, server);
		client.sendRequest(secondRequest);
		server.expectRequest(CON, GET, path).storeBoth("SECOND_GET").go();
		// Send blockwise response
		String secondPayload = generateRandomPayload(256);
		server.sendResponse(ACK, CONTENT).loadBoth("SECOND_GET").block2(0, true, 128)
				.payload(secondPayload.substring(0, 128)).go();
		// Expect next block request
		server.expectRequest(CON, GET, path).storeBoth("SECOND_GET_BLOCK").block2(1, false, 128).go();
		
		// Send 2nd block from the first blockwise transfer
		server.sendResponse(ACK, CONTENT).loadBoth("FIRST_GET_BLOCK").block2(1, false, 128)
		.payload(respPayload.substring(128, 256)).go();
		// Send 2nd block (last) from the second blockwise transfer
		server.sendResponse(ACK, CONTENT).loadBoth("SECOND_GET_BLOCK").block2(1, false, 128).payload(secondPayload.substring(128, 256))
				.go();
				
		// Check that we get the response of the second request
		Response response = secondRequest.waitForResponse(2000);
		assertResponseContainsExpectedPayload(response, secondPayload);
		
		// Check the first request is canceled.
		assertTrue(firstRequest.isCanceled());
	}
	
	/**
	 * Verifies incomplete block2 exchange (missing last piggyback response)
	 * does not leak.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testIncompleteBlock2NoAckNoResponse() throws Exception {

		System.out.println("Incomplete  block2 transfer:");
		respPayload = generateRandomPayload(300);
		String path = "test";

		// Send GET request
		Request request = createRequest(GET, path, server);
		client.sendRequest(request);
		server.expectRequest(CON, GET, path).storeBoth("A").go();

		server.sendResponse(ACK, CONTENT).loadBoth("A").block2(0, true, 128).payload(respPayload.substring(0, 128))
				.go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 128).go();
		Thread.sleep((long) (TEST_BLOCKWISE_STATUS_LIFETIME * 0.75));

		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 128).payload(respPayload.substring(128, 256))
				.go();
		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 128).go();
		Thread.sleep((long) (TEST_BLOCKWISE_STATUS_LIFETIME * 0.75));

		assertTrue(!client.getStack().getBlockwiseLayer().isEmpty());
		// we don't answer to the last request, @after should check is there is
		// no leak.

		printServerLog(clientInterceptor);
	}

	/**
	 * Verifies incomplete block1 exchange (missing piggyback response) does not
	 * leak.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testIncompleteBlock1NoAckNoResponse() throws Exception {

		System.out.println("Incomplete  block1 transfer:");
		reqtPayload = generateRandomPayload(400);
		String path = "test";

		// Send PUT request
		Request request = createRequest(PUT, path, server);
		request.setPayload(reqtPayload);
		client.sendRequest(request);
		server.expectRequest(CON, PUT, path).storeBoth("A").block1(0, true, 128).payload(reqtPayload, 0, 128).go();

		server.sendResponse(ACK, CONTINUE).loadBoth("A").block1(1, false, 128).go();
		server.expectRequest(CON, PUT, path).storeBoth("B").block1(1, true, 128).payload(reqtPayload, 128, 256).go();
		Thread.sleep((long) (TEST_BLOCKWISE_STATUS_LIFETIME * 0.75));
		
		server.sendResponse(ACK, CONTINUE).loadBoth("B").block1(2, false, 128).go();
		server.expectRequest(CON, PUT, path).storeBoth("C").block1(2, true, 128).payload(reqtPayload, 256, 384).go();
		Thread.sleep((long) (TEST_BLOCKWISE_STATUS_LIFETIME * 0.75));
		
		assertTrue(!client.getStack().getBlockwiseLayer().isEmpty());
		// we don't answer to the last request, @after should check is there is
		// no leak.

		printServerLog(clientInterceptor);
	}

	/**
	 * Verifies cancelled block2 exchange does not leak.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testCancelledBlock2() throws Exception {

		System.out.println("cancelled block2 transfer:");
		respPayload = generateRandomPayload(300);
		String path = "test";

		// Send GET request
		Request request = createRequest(GET, path, server);
		client.sendRequest(request);

		server.expectRequest(CON, GET, path).storeBoth("A").go();
		server.sendResponse(ACK, CONTENT).loadBoth("A").block2(0, true, 128).payload(respPayload.substring(0, 128))
				.go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 128).go();
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 128).payload(respPayload.substring(128, 256))
				.go();
		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 128).go();
		printServerLog(clientInterceptor);

		System.out.println("Cancel request " + request);
		request.cancel();
		assertAllExchangesAreCompleted(config, client.getExchangeStore(), time);
	}

	/**
	 * Verifies cancelled block1 exchange does not leak.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testCancelledBlock1() throws Exception {

		System.out.println("Cancelled  block1 transfer:");
		reqtPayload = generateRandomPayload(300);
		String path = "test";

		// Send PUT request
		Request request = createRequest(PUT, path, server);
		request.setPayload(reqtPayload);
		client.sendRequest(request);

		server.expectRequest(CON, PUT, path).storeBoth("A").block1(0, true, 128).payload(reqtPayload, 0, 128).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("A").block1(1, false, 128).go();
		server.expectRequest(CON, PUT, path).storeBoth("B").block1(1, true, 128).payload(reqtPayload, 128, 256).go();
		printServerLog(clientInterceptor);

		System.out.println("Cancel request " + request);
		request.cancel();
		assertAllExchangesAreCompleted(config, client.getExchangeStore(), time);
	}

	/**
	 * Verifies acknowledged incomplete block 2 exchange does not leak.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testIncompleteBlock2AckNoResponse() throws Exception {

		System.out.println("Incomplete Acknowledged block2 transfer:");
		respPayload = generateRandomPayload(300);
		String path = "test";

		// Send GET request
		Request request = createRequest(GET, path, server);
		client.sendRequest(request);

		server.expectRequest(CON, GET, path).storeBoth("A").go();
		server.sendResponse(ACK, CONTENT).loadBoth("A").block2(0, true, 128).payload(respPayload.substring(0, 128))
				.go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 128).go();
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 128).payload(respPayload.substring(128, 256))
				.go();
		server.expectRequest(CON, GET, path).storeBoth("C").block2(2, false, 128).go();
		server.sendEmpty(ACK).loadMID("C").go();
		// we acknowledge but never send the response, @after should check is
		// there is no leak.

		printServerLog(clientInterceptor);
	}

	/**
	 * Verifies acknowledged incomplete block 2 exchange does not leak.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testIncompleteBlock1AckNoResponse() throws Exception {

		System.out.println("Incomplete Acknowledged block1 transfer:");
		reqtPayload = generateRandomPayload(300);
		String path = "test";

		// Send PUT request
		Request request = createRequest(PUT, path, server);
		request.setPayload(reqtPayload);
		client.sendRequest(request);

		server.expectRequest(CON, PUT, path).storeBoth("A").block1(0, true, 128).payload(reqtPayload, 0, 128).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("A").block1(1, false, 128).go();
		server.expectRequest(CON, PUT, path).storeBoth("B").block1(1, true, 128).payload(reqtPayload, 128, 256).go();
		server.sendEmpty(ACK).loadMID("B").go();
		// we acknowledge but never send the response, @after should check is
		// there is no leak.

		printServerLog(clientInterceptor);
	}

	/**
	 * Verify there is no leak if we failed before to sent block1 request
	 */
	@Test
	public void testBlock1FailureBeforeToSend() throws Exception {
		System.out.println("blockwise PUT failed before to send a block1 request");
		reqtPayload = generateRandomPayload(300);
		String path = "test";

		// Start block 1 transfer
		Request request = createRequest(PUT, path, server);
		request.setPayload(reqtPayload);
		CountingMessageObserver counter = new CountingMessageObserver();
		request.addMessageObserver(counter);
		client.sendRequest(request);
		server.expectRequest(CON, PUT, path).storeBoth("A").block1(0, true, 128).size1(reqtPayload.length())
				.payload(reqtPayload.substring(0, 128)).go();
		server.sendResponse(ACK, CONTINUE).loadBoth("A").block1(0, true, 128).go();
		server.expectRequest(CON, PUT, path).storeBoth("B").block1(1, true, 128)
				.payload(reqtPayload.substring(128, 256)).go();

		// Simulate error before we send the next block1 request
		ErrorInjector errorInjector = new ErrorInjector();
		errorInjector.setErrorOnReadyToSend();
		clientInterceptor.setErrorInjector(errorInjector);
		server.sendResponse(ACK, CONTINUE).loadBoth("B").block1(1, true, 128).go();

		// Wait for error
		counter.waitForErrorCalls(1, 1000, TimeUnit.MILLISECONDS);

		// We should get a error
		assertEquals("An error is expected", 1, counter.errorCalls.get());

		// @after check there is no leak
	}

	/**
	 * Verify there is no leak if we failed before to sent block2 request
	 */
	@Test
	public void testBlock2FailureBeforeToSend() throws Exception {
		System.out.println("blockwise GET failed before to send a block2 request:");
		respPayload = generateRandomPayload(300);
		String path = "test";

		// Start block 2 transfer
		Request request = createRequest(GET, path, server);
		CountingMessageObserver counter = new CountingMessageObserver();
		request.addMessageObserver(counter);
		client.sendRequest(request);
		server.expectRequest(CON, GET, path).storeBoth("A").go();
		server.sendResponse(ACK, CONTENT).loadBoth("A").block2(0, true, 128).size2(respPayload.length())
				.payload(respPayload.substring(0, 128)).go();
		server.expectRequest(CON, GET, path).storeBoth("B").block2(1, false, 128).go();

		// Simulate error before we send the next block2 request
		ErrorInjector errorInjector = new ErrorInjector();
		errorInjector.setErrorOnReadyToSend();
		clientInterceptor.setErrorInjector(errorInjector);
		server.sendResponse(ACK, CONTENT).loadBoth("B").block2(1, true, 128).payload(respPayload.substring(128, 256))
				.go();

		// Wait for error
		counter.waitForErrorCalls(1, 1000, TimeUnit.MILLISECONDS);

		// We should get a error
		assertEquals("An error is expected", 1, counter.errorCalls.get());

		// @after check there is no leak
	}
}
