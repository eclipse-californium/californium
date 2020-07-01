/*******************************************************************************
 * Copyright (c) 2014, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Martin Lanter - creator
 *    (a lot of changes from different authors, please refer to gitlog).
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CoapNetworkRule for
 *                                                    setup of test-network
 *    Achim Kraus (Bosch Software Innovations GmbH) - use waitForCondition
 *    Achim Kraus (Bosch Software Innovations GmbH) - adjust timing for waiting
 *                                                    on notifies.
 *                                                    fix thread visibility of 
 *                                                    CoapObserverAndCanceler fields
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce lower notify rate for 
 *                                                    blockwise notifies. Reuse 
 *                                                    TestResource for all tests
 *                                                    preparing it for each test
 *                                                    by using setResponse() or 
 *                                                    setNotifies().
 *    Achim Kraus (Bosch Software Innovations GmbH) - use MessageExchangeStoreTool
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.eclipse.californium.core.test.MessageExchangeStoreTool.assertAllExchangesAreCompleted;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.InMemoryMessageExchangeStore;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.test.lockstep.ClientBlockwiseInterceptor;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.rule.TestTimeRule;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tests verifying that the {@code MessageExchangeStore} gets cleared correctly during all kinds
 * of interactions.
 *
 */
@Category(Medium.class)
public class MemoryLeakingHashMapTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	@ClassRule
	public static CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	@Rule
	public TestTimeRule time = new TestTimeRule();

	// Configuration for this test
	private static final int TEST_EXCHANGE_LIFETIME = 247; // milliseconds
	private static final int TEST_SWEEP_DEDUPLICATOR_INTERVAL = 100; // milliseconds
	private static final int TEST_BLOCK_SIZE = 16; // 16 bytes

	private static final String LONG_REQUEST = "123456789.123456789.";
	private static final String LONG_RESPONSE = LONG_REQUEST + LONG_REQUEST;

	// the interval at which the server sends notifications (200 ms)
	// may be multiplied by the number of blocks, if notify is sent blockwise
	private static final int OBS_NOTIFICATION_INTERVAL = 200; 
	private static final int HOW_MANY_NOTIFICATION_WE_WAIT_FOR = 3;
	private static final int ACK_TIMEOUT = 100; // ms

	// The name of the resource of the server
	private static final String URI = "test";

	private static final Logger LOGGER = LoggerFactory.getLogger(MemoryLeakingHashMapTest.class);
	private static Endpoint serverEndpoint;

	// The server endpoint that we test
	private static CoapEndpoint clientEndpoint;
	private static InMemoryMessageExchangeStore clientExchangeStore;
	private static InMemoryMessageExchangeStore serverExchangeStore;
	private static ClientBlockwiseInterceptor clientInterceptor = new ClientBlockwiseInterceptor();

	private static volatile String currentRequestText;
	private static TestResource resource;

	@BeforeClass
	public static void startupServer() throws Exception {
		createServerAndClientEndpoints();
	}


	@Before
	public void startExchangeStores() {
		clientExchangeStore.start();
		serverExchangeStore.start();
	}

	@After
	public void stopExchangeStores() {
		try {
			assertAllExchangesAreCompleted(network.getStandardTestConfig(), clientExchangeStore, serverExchangeStore, time);
		} finally {
			System.out.println(clientInterceptor.toString());
			clientInterceptor.clear();
			clientExchangeStore.stop();
			serverExchangeStore.stop();
		}
	}

	/**
	 * Verifies that the server cleans up all exchanges after serving a NON GET.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testSimpleNONGet() throws Exception {

		String uri = uriOf(URI);
		LOGGER.debug("Test simple NON GET to {}", uri);

		String currentResponseText = "simple NON GET";
		resource.setResponse(currentResponseText, Mode.PIGGY_BACKED_RESPONSE);

		Request request = Request.newGet();
		request.setURI(uri);
		request.setType(Type.NON);
		Response response = request.send(clientEndpoint).waitForResponse(ACK_TIMEOUT);
		assertThat("Client did not receive response to NON request in time", response, is(notNullValue()));
		LOGGER.debug("Client received response [{}] with msg type [{}]", new Object[]{response.getPayloadString(), response.getType()});
		assertThat(response.getPayloadString(), is(currentResponseText));
		assertThat(response.getType(), is(Type.NON));
	}

	/**
	 * Verifies that the client & server clean up the message exchange store after a CON GET
	 * with a piggy-backed response.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testSimpleGetUsingPiggyBacking() throws Exception {
		testSimpleGet(Mode.PIGGY_BACKED_RESPONSE);
	}

	/**
	 * Verifies that the client & server clean up the message exchange store after a CON GET
	 * with a separate CON response.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testSimpleGetUsingSeparateMessage() throws Exception {
		testSimpleGet(Mode.SEPARATE_RESPONSE);
	}

	private static void testSimpleGet(final Mode mode) throws Exception {

		String uri = uriOf(URI);
		LOGGER.debug("Test simple GET to {}", uri);

		String currentResponseText = "simple GET";
		resource.setResponse(currentResponseText, mode);

		CoapClient client = new CoapClient(uri);
		client.setEndpoint(clientEndpoint);

		CoapResponse response = client.get();
		assertThatResponseContainsValue(response, currentResponseText);
		client.shutdown();
	}

	/**
	 * Verifies that the client & server clean up the message exchange store after retrieving
	 * a resource body using a blockwise transfer with a piggy-backed response.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testBlockwiseUsingPiggyBacking() throws Exception {
		testBlockwise(Mode.PIGGY_BACKED_RESPONSE);
	}

	/**
	 * Verifies that the client & server clean up the message exchange store after retrieving
	 * a resource body using a blockwise transfer with a separate response.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testBlockwiseUsingSeparateResponse() throws Exception {
		testBlockwise(Mode.SEPARATE_RESPONSE);
	}

	/**
	 * Verifies that the client & server clean up the message exchange store after retrieving
	 * a resource body using a blockwise transfer with NON messages.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testBlockwiseUsingNONMessages() throws Exception {
		CoapClient client = new CoapClient(uriOf(URI)).useNONs();
		client.setEndpoint(clientEndpoint);
		testBlockwise(client, Mode.PIGGY_BACKED_RESPONSE);
		client.shutdown();
	}

	private static void testBlockwise(final Mode mode) throws Exception {
		CoapClient client = new CoapClient(uriOf(URI));
		client.setEndpoint(clientEndpoint);
		testBlockwise(client, mode);
		client.shutdown();
	}

	private static void testBlockwise(final CoapClient client, final Mode mode) throws ConnectorException, IOException {

		LOGGER.debug("Test blockwise POST to {}", client.getURI());

		currentRequestText = LONG_REQUEST;
		String currentResponseText = LONG_RESPONSE;
		resource.setResponse(currentResponseText, mode);

		CoapResponse response = client.post(currentRequestText, MediaTypeRegistry.TEXT_PLAIN);
		assertThatResponseContainsValue(response, currentResponseText);
	}

	private static void assertThatResponseContainsValue(CoapResponse response, String expectedValue) {
		assertThat(response, is(notNullValue()));
		LOGGER.debug("Client received response [{}]", response.getResponseText());
		assertThat(response.getResponseText(), is(expectedValue));
	}

	/**
	 * Verifies that the client & server clean up the message exchange store after the client has
	 * established an observe relation, received some notifications and then actively
	 * cancelled the observation.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testObserveProactive() throws Exception {
		LOGGER.debug("Test observe relation with a proactive cancelation");
		testObserveProactive("Hello observer");
	}

	/**
	 * Verifies that the client & server clean up the message exchange store after the client has
	 * established an observe relation, received some (blockwise) notifications and then actively
	 * cancelled the observation.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testObserveProactiveBlockwise() throws Exception {
		LOGGER.debug("Test observe relation with blockwise notifications and proactive cancelation");
		// We need a long response text (>16)
		testObserveProactive(LONG_RESPONSE);
	}

	private void testObserveProactive(final String responseText) throws Exception {

		String currentResponseText = responseText;
		int blocks = resource.setNotifies(currentResponseText, Mode.PIGGY_BACKED_RESPONSE);

		CoapClient client = new CoapClient(uriOf(URI));
		client.setEndpoint(clientEndpoint);
		CoapObserverAndCanceler handler = new CoapObserverAndCanceler(HOW_MANY_NOTIFICATION_WE_WAIT_FOR + 1, true);
		CoapObserveRelation rel = client.observe(handler);
		handler.setObserveRelation(rel);

		if (1 < blocks) {
			// wait longer, blocks may require retransmission and 
			// blockwise notifies may overlap 
			blocks <<= 2;
		}

		// Wait until all the notifications are received and
		// the relation is canceled
		handler.waitOnLoadCalls(HOW_MANY_NOTIFICATION_WE_WAIT_FOR + 1,
				calculateNotifiesTimeout(HOW_MANY_NOTIFICATION_WE_WAIT_FOR + 1) * blocks, TimeUnit.MILLISECONDS);
		assertThat("Client has not received all expected responses", handler.getOnLoadCalls(),
				is(HOW_MANY_NOTIFICATION_WE_WAIT_FOR + 1));
		assertThat("Client has errors", handler.getOnErrorCalls(), is(0));
		client.shutdown();
	}

	/**
	 * Verifies that the client & server clean up the message exchange store after the client has
	 * established an observe relation, received some notifications and then has "forgotten"
	 * about the observation.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testObserveReactive() throws Exception {

		final String uri = uriOf(URI);
		System.out.println("Test observe relation with a reactive cancelation to " + uri);

		String currentResponseText = "Hello observer";
		resource.setNotifies(currentResponseText, Mode.PIGGY_BACKED_RESPONSE);

		CoapClient client = new CoapClient(uri);
		client.setEndpoint(clientEndpoint);
		CoapObserverAndCanceler handler = new CoapObserverAndCanceler(HOW_MANY_NOTIFICATION_WE_WAIT_FOR, false);
		CoapObserveRelation rel = client.observe(handler);
		handler.setObserveRelation(rel);

		handler.waitOnLoadCalls(HOW_MANY_NOTIFICATION_WE_WAIT_FOR,
				calculateNotifiesTimeout(HOW_MANY_NOTIFICATION_WE_WAIT_FOR), TimeUnit.MILLISECONDS);
		assertThat("Client has not received all expected responses", handler.getOnLoadCalls(),
				is(HOW_MANY_NOTIFICATION_WE_WAIT_FOR));
		assertThat("Client has errors", handler.getOnErrorCalls(), is(0));
		client.shutdown();
	}

	private static long calculateNotifiesTimeout(int numberOfNotifiesToWait) {
		return (numberOfNotifiesToWait * OBS_NOTIFICATION_INTERVAL) + 1000L;
	}

	private static void createServerAndClientEndpoints() throws Exception {

		NetworkConfig config = network.getStandardTestConfig()
			// We make sure that the sweep deduplicator is used
			.setString(NetworkConfig.Keys.DEDUPLICATOR, NetworkConfig.Keys.DEDUPLICATOR_MARK_AND_SWEEP)
			.setInt(NetworkConfig.Keys.MARK_AND_SWEEP_INTERVAL, TEST_SWEEP_DEDUPLICATOR_INTERVAL)
			.setLong(NetworkConfig.Keys.EXCHANGE_LIFETIME, TEST_EXCHANGE_LIFETIME)

			// set ACK timeout to 500ms
			.setInt(NetworkConfig.Keys.ACK_TIMEOUT, ACK_TIMEOUT)
			.setInt(NetworkConfig.Keys.MAX_RETRANSMIT, 1)

			// We set the block size to 16 bytes
			.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, TEST_BLOCK_SIZE)
			.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, TEST_BLOCK_SIZE);

		// Create the endpoint for the server and create surveillant
		serverExchangeStore = new InMemoryMessageExchangeStore(config);	
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		builder.setNetworkConfig(config);
		builder.setMessageExchangeStore(serverExchangeStore);
		serverEndpoint = builder.build();
		serverEndpoint.addInterceptor(new MessageTracer());

		clientExchangeStore = new InMemoryMessageExchangeStore(config);
		builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		builder.setNetworkConfig(config);
		builder.setMessageExchangeStore(clientExchangeStore);
		clientEndpoint = builder.build();
		cleanup.add(clientEndpoint);
		clientEndpoint.addInterceptor(clientInterceptor);
		clientEndpoint.start();

		// Create a server with two resources: one that sends piggy-backed
		// responses and one that sends separate responses
		ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor();
		cleanup.add(timer);

		CoapServer server = new CoapServer(config);
		cleanup.add(server);
		server.addEndpoint(serverEndpoint);
		resource = new TestResource(timer);
		server.add(resource);
		server.start();
	}

	private static String uriOf(final String resourcePath) {
		return TestTools.getUri(serverEndpoint, resourcePath);
	}

	private enum Mode { PIGGY_BACKED_RESPONSE, SEPARATE_RESPONSE; }

	private static class TestResource extends CoapResource {

		private final ScheduledExecutorService timer;
		private ScheduledFuture<?> scheduledTimer;
		private volatile String currentResponseText;
		private volatile Mode mode;

		public TestResource(final ScheduledExecutorService timer) {
			super(URI);
			this.timer = timer;

			setObservable(true);
		}

		public int setResponse(final String responseText, final Mode mode) {
			if (null != this.scheduledTimer) {
				this.scheduledTimer.cancel(false);
				try {
					this.scheduledTimer.get();
				} catch (InterruptedException | CancellationException | ExecutionException e) {
				}
				this.scheduledTimer = null;
			}
			this.mode = mode;
			this.currentResponseText = responseText;
			int blocks = (responseText.length() + TEST_BLOCK_SIZE - 1) / TEST_BLOCK_SIZE;
			if (0 == blocks) {
				blocks = 1;
			}
			return blocks;
		}

		public int setNotifies(final String responseText, final Mode mode) {
			int blocks = setResponse(responseText, mode);
			this.scheduledTimer = this.timer.scheduleWithFixedDelay(new Runnable() {

				@Override
				public void run() {
					changed();
				}
			}, OBS_NOTIFICATION_INTERVAL * blocks, OBS_NOTIFICATION_INTERVAL * blocks, TimeUnit.MILLISECONDS);
			return blocks;
		}

		@Override
		public void handleGET(final CoapExchange exchange) {

			if (mode == Mode.SEPARATE_RESPONSE) {
				exchange.accept();
			}
			exchange.respond(currentResponseText);
		}

		@Override
		public void handlePOST(final CoapExchange exchange) {

			assertThat(exchange.getRequestText(), is(currentRequestText));
			if (mode == Mode.SEPARATE_RESPONSE) {
				exchange.accept();
			}

			LOGGER.debug("TestResource [{}] received POST message: {}", new Object[]{getName(), exchange.getRequestText()});

			exchange.respond(ResponseCode.CREATED, currentResponseText);
		}

		@Override
		public void handlePUT(final CoapExchange exchange) {

			assertThat(exchange.getRequestText(), is(currentRequestText));
			exchange.accept();
			currentResponseText = "";
			exchange.respond(ResponseCode.CHANGED);
		}

		@Override
		public void handleDELETE(CoapExchange exchange) {
			currentResponseText = "";
			exchange.respond(ResponseCode.DELETED);
		}
	}

	private class CoapObserverAndCanceler extends CountingCoapHandler {

		private CoapObserveRelation relation;
		final int expectedNotifies;
		final boolean cancelProactively;

		public CoapObserverAndCanceler(int expectedNotifies, boolean cancelProactively) {
			this.expectedNotifies = expectedNotifies;
			this.cancelProactively = cancelProactively;
		}

		public synchronized void setObserveRelation(CoapObserveRelation relation) {
			this.relation = relation;
		}

		@Override
		public void assertLoad(CoapResponse response) {
			int counter = this.loadCalls.get();

			if (null == relation) {
				LOGGER.info("Client ignore notification {}: [{}]", counter, response.getResponseText());
				return;
			}

			LOGGER.debug("Client received notification {}: [{}]", counter, response.getResponseText());

			if (cancelProactively) {
				if ((counter + 1) == expectedNotifies) {
					LOGGER.debug("Client proactively cancels observe relation");
					relation.proactiveCancel();
				}
			} else {
				if (counter == expectedNotifies) {
					LOGGER.debug("Client forgets observe relation");
					relation.reactiveCancel();
				}
			}
		}
	}
}
