package org.eclipse.californium.core.test;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
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
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Medium.class)
public class MemoryLeakingHashMapTest {

	// Configuration for this test
	public static final int TEST_EXCHANGE_LIFETIME = 247; // milliseconds
	public static final int TEST_SWEEP_DEDUPLICATOR_INTERVAL = 100; // milliseconds
	public static final int TEST_BLOCK_SIZE = 16; // 16 bytes

	public static final String LONG_REQUEST = "123456789.123456789.";
	public static final String LONG_RESPONSE = LONG_REQUEST + LONG_REQUEST;

	public static final int OBS_NOTIFICATION_INTERVAL = 50; // send one notification per 50 ms
	public static final int HOW_MANY_NOTIFICATION_WE_WAIT_FOR = 3;
	public static final int ACK_TIMEOUT = 500; // ms

	// The names of the two resources of the server
	public static final String PIGGY = "piggy";
	public static final String SEPARATE = "separate";
	
	private static final Logger LOGGER = Logger.getLogger(MemoryLeakingHashMapTest.class.getName());
	private static ScheduledExecutorService timer;
	private static CoapServer server;
	private static int serverPort;

	// The server endpoint that we test
	private static CoapEndpoint serverEndpoint;
	private static CoapEndpoint clientEndpoint;
	private static EndpointSurveillant serverSurveillant;
	private static EndpointSurveillant clientSurveillant;

	private static String currentRequestText;
	private static String currentResponseText;

	@BeforeClass
	public static void startupServer() throws Exception {
		LOGGER.log(Level.FINE, "Start {0}", MemoryLeakingHashMapTest.class.getSimpleName());
		timer = new ScheduledThreadPoolExecutor(1);
		createServerAndClientEntpoints();
	}

	@AfterClass
	public static void shutdownServer() {
		server.destroy();
		timer.shutdown();
		LOGGER.log(Level.FINE, "End {0}", MemoryLeakingHashMapTest.class.getSimpleName());
	}

	@After
	public void assertHashMapsEmpty() {
		serverSurveillant.waitUntilDeduplicatorShouldBeEmpty();
		serverSurveillant.assertHashMapsEmpty();
		clientSurveillant.assertHashMapsEmpty();
	}

	@Test
	public void testSimpleNONGet() throws Exception {
		String uri = uriOf(PIGGY);
		LOGGER.log(Level.FINE, "Test simple NON GET to {0}", uri);

		currentResponseText = "simple NON GET";

		Request request = Request.newGet();
		request.setURI(uri);
		request.setType(Type.NON);
		Response response = request.send(clientEndpoint).waitForResponse(ACK_TIMEOUT);
		assertThat(response, is(notNullValue()));
		LOGGER.log(Level.FINE, "Client received response [{0}] with msg type [{1}]", new Object[]{response.getPayloadString(), response.getType()});
		assertEquals(currentResponseText, response.getPayloadString());
		assertEquals(Type.NON, response.getType());
	}

	@Test
	public void testSimpleGetUsingPiggyBacking() throws Exception {
		testSimpleGet(uriOf(PIGGY));
	}

	@Test
	public void testSimpleGetUsingSeparateMessage() throws Exception {
		testSimpleGet(uriOf(SEPARATE));
	}

	private void testSimpleGet(String uri) throws Exception {
		LOGGER.log(Level.FINE, "Test simple GET to {0}", uri);

		currentResponseText = "simple GET";

		CoapClient client = new CoapClient(uri);
		client.setEndpoint(clientEndpoint);

		CoapResponse response = client.get();
		assertThatResponseContainsValue(response, currentResponseText);
	}

	@Test
	public void testBlockwiseUsingPiggyBacking() throws Exception {
		testBlockwise(uriOf(PIGGY));
	}

	@Test
	public void testBlockwiseUsingSeparateResponse() throws Exception {
		testBlockwise(uriOf(SEPARATE));
	}

	private void testBlockwise(String uri) throws Exception {
		CoapClient client = new CoapClient(uri);
		client.setEndpoint(clientEndpoint);
		testBlockwise(client);
	}

	@Test
	public void testBlockwiseUsingNONMessages() throws Exception {
		CoapClient client = new CoapClient(uriOf(PIGGY)).useNONs();
		client.setEndpoint(clientEndpoint);
		testBlockwise(client);
	}

	private void testBlockwise(CoapClient client) {
		LOGGER.log(Level.FINE, "Test blockwise POST to {0}", client.getURI());

		currentRequestText = LONG_REQUEST;
		currentResponseText = LONG_RESPONSE;

		CoapResponse response = client.post(currentRequestText, MediaTypeRegistry.TEXT_PLAIN);
		assertThatResponseContainsValue(response, currentResponseText);
	}

	private void assertThatResponseContainsValue(CoapResponse response, String expectedValue) {
		assertThat(response,  is(notNullValue()));
		LOGGER.log(Level.FINE, "Client received response [{0}]", response.getResponseText());
		assertThat(response.getResponseText(), is(expectedValue));
	}

	@Test
	public void testObserveProactive() throws Exception {
		String uri = uriOf(PIGGY);
		LOGGER.log(Level.FINE, "Test observe relation with a proactive cancelation to {0}", uri);

		currentResponseText = "Hello observer";

		CountDownLatch latch = new CountDownLatch(HOW_MANY_NOTIFICATION_WE_WAIT_FOR + 1);
		AtomicBoolean isOnErrorInvoked = new AtomicBoolean();

		CoapClient client = new CoapClient(uri);
		client.setEndpoint(clientEndpoint);
		CoapObserverAndCanceler handler = new CoapObserverAndCanceler(latch, isOnErrorInvoked, uri, true);
		CoapObserveRelation rel = client.observe(handler);
		handler.setObserveRelation(rel);

		assertTrue(
				"Client has not received all expected responses",
				latch.await(HOW_MANY_NOTIFICATION_WE_WAIT_FOR * OBS_NOTIFICATION_INTERVAL + 500, TimeUnit.MILLISECONDS));
		assertFalse(isOnErrorInvoked.get()); // should not happen
	}

	@Test
	public void testObserveReactive() throws Exception {
		final String uri = uriOf(PIGGY);
		System.out.println("Test observe relation with a reactive cancelation to "+uri);

		currentResponseText = "Hello observer";

		CountDownLatch latch = new CountDownLatch(HOW_MANY_NOTIFICATION_WE_WAIT_FOR);
		AtomicBoolean isOnErrorInvoked = new AtomicBoolean();

		CoapClient client = new CoapClient(uri);
		client.setEndpoint(clientEndpoint);
		CoapObserverAndCanceler handler = new CoapObserverAndCanceler(latch, isOnErrorInvoked, uri, false);
		CoapObserveRelation rel = client.observe(handler);
		handler.setObserveRelation(rel);

		assertTrue(
				"Client has not received all expected responses",
				latch.await(HOW_MANY_NOTIFICATION_WE_WAIT_FOR * OBS_NOTIFICATION_INTERVAL + 500, TimeUnit.MILLISECONDS));
		assertFalse(isOnErrorInvoked.get()); // should not happen
	}

	@Test
	public void testObserveBlockwise() throws Exception {
		final String uri = uriOf(PIGGY);
		LOGGER.log(Level.FINE, "Test observe relation with blockwise notifications {0}", uri);

		// We need a long response text (>16) 
		currentResponseText = LONG_RESPONSE;

		CountDownLatch latch = new CountDownLatch(HOW_MANY_NOTIFICATION_WE_WAIT_FOR + 1);
		AtomicBoolean isOnErrorInvoked = new AtomicBoolean();

		CoapClient client = new CoapClient(uri);
		client.setEndpoint(clientEndpoint);
		CoapObserverAndCanceler handler = new CoapObserverAndCanceler(latch, isOnErrorInvoked, uri, true);
		CoapObserveRelation rel = client.observe(handler);
		handler.setObserveRelation(rel);

		// Wait until we have received all the notifications and canceled the relation
		assertTrue(
				"Client has not received all expected responses",
				latch.await(HOW_MANY_NOTIFICATION_WE_WAIT_FOR * OBS_NOTIFICATION_INTERVAL + 500, TimeUnit.MILLISECONDS));
		assertFalse(isOnErrorInvoked.get()); // should not happen
	}

	private static void createServerAndClientEntpoints() throws Exception {

		NetworkConfig config = new NetworkConfig()
			// We make sure that the sweep deduplicator is used
			.setString(NetworkConfig.Keys.DEDUPLICATOR, NetworkConfig.Keys.DEDUPLICATOR_MARK_AND_SWEEP)
			.setInt(NetworkConfig.Keys.MARK_AND_SWEEP_INTERVAL, TEST_SWEEP_DEDUPLICATOR_INTERVAL)
			.setLong(NetworkConfig.Keys.EXCHANGE_LIFETIME, TEST_EXCHANGE_LIFETIME)

			// set ACK timeout to 500ms
			.setInt(NetworkConfig.Keys.ACK_TIMEOUT, ACK_TIMEOUT)

			// We set the block size to 16 bytes
			.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, TEST_BLOCK_SIZE)
			.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, TEST_BLOCK_SIZE);

		// Create the endpoint for the server and create surveillant
		serverEndpoint = new CoapEndpoint(new InetSocketAddress((InetAddress) null, 0), config);
		serverEndpoint.addInterceptor(new MessageTracer());
		serverSurveillant = new EndpointSurveillant("server", serverEndpoint);

		clientEndpoint = new CoapEndpoint(config);
		clientEndpoint.start();
		clientSurveillant = new EndpointSurveillant("client", clientEndpoint);

		// Create a server with two resources: one that sends piggy-backed
		// responses and one that sends separate responses

		server = new CoapServer(config);
		server.addEndpoint(serverEndpoint);
		server.add(new TestResource(PIGGY, Mode.PIGGY_BACKED_RESPONSE, timer));
		server.add(new TestResource(SEPARATE, Mode.SEPARATE_RESPONE, timer));
		server.start();
		serverPort = serverEndpoint.getAddress().getPort();
	}

	private String uriOf(String resourcePath) {
		return "coap://localhost:" + serverPort + "/" + resourcePath;
	}
	
	public enum Mode { PIGGY_BACKED_RESPONSE, SEPARATE_RESPONE; }
	
	public static class TestResource extends CoapResource {

		private Mode mode;
		
		public TestResource(final String name, final Mode mode, final ScheduledExecutorService timer) {
			super(name);
			this.mode = mode;
			
			setObservable(true);
			timer.scheduleWithFixedDelay(new Runnable() {

				@Override
				public void run() {
					changed();
				}
			}, OBS_NOTIFICATION_INTERVAL, OBS_NOTIFICATION_INTERVAL, TimeUnit.MILLISECONDS);
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			if (mode == Mode.SEPARATE_RESPONE)
				exchange.accept();
			exchange.respond(currentResponseText);
		}

		@Override
		public void handlePOST(CoapExchange exchange) {
			assertEquals(currentRequestText, exchange.getRequestText());
			if (mode == Mode.SEPARATE_RESPONE)
				exchange.accept();

			LOGGER.log(Level.FINE, "TestResource [{0}] received POST message: {1}", new Object[]{getName(), exchange.getRequestText()});

			exchange.respond(ResponseCode.CREATED, currentResponseText);
		}

		@Override
		public void handlePUT(CoapExchange exchange) {
			assertEquals(currentRequestText, exchange.getRequestText());
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

	public class CoapObserverAndCanceler implements CoapHandler {
		private CoapObserveRelation relation;
		int counter = 1;
		CountDownLatch latch;
		AtomicBoolean errorFlag;
		String uri;
		boolean cancelProactively;

		public CoapObserverAndCanceler(final CountDownLatch latch, final AtomicBoolean errorFlag, final String uri, final boolean cancelProactively) {
			this.latch = latch;
			this.errorFlag = errorFlag;
			this.uri = uri;
			this.cancelProactively = cancelProactively;
		}

		public void setObserveRelation(CoapObserveRelation relation) {
			this.relation = relation;
		}

		public void onLoad(CoapResponse response) {
			latch.countDown();
			LOGGER.log(Level.FINE, "Client received notification {0}: [{1}]", new Object[]{counter++, response.getResponseText()});

			if (latch.getCount() == 1 && cancelProactively) {
				LOGGER.log(Level.FINE, "Client proactively cancels observe relation to {0}", uri);
				relation.proactiveCancel();
			}
			if (latch.getCount() == 0 && !cancelProactively) {
				LOGGER.log(Level.FINE, "Client forgets observe relation to {0}", uri);
				relation.reactiveCancel();
			}
		}

		public void onError() {
			errorFlag.set(true);
		}
	}

}
