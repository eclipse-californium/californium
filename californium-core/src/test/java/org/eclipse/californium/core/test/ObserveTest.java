/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Achim Kraus - fixing race condition and visibility
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CoapNetworkRule for 
 *                                                    setup of test-network
 *    Achim Kraus (Bosch Software Innovations GmbH) - add test for reregister
 *                                                    issue #56. 
 *                                                    Introduce CountingHandler
 *                                                    use expected= annotation for
 *                                                    expected exceptions
 *    Achim Kraus (Bosch Software Innovations GmbH) - use MessageInterceptorAdapter
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageInterceptor;
import org.eclipse.californium.core.network.interceptors.MessageInterceptorAdapter;
import org.eclipse.californium.core.observe.Observation;
import org.eclipse.californium.core.observe.ObservationStore;
import org.eclipse.californium.core.observe.ObservationStoreException;
import org.eclipse.californium.core.observe.ObservationUtil;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.NamedThreadFactory;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/*
 * This test is valid for both drafts observe-08 and observe-09.
 */
/**
 * This test tests that a server removes all observe relations to a client if a
 * notification fails to transmit and that a new notification keeps the
 * retransmission count of the previous notification.
 * <p>
 * The server has two observable resources X and Y. The client (5683) sends a
 * request A to resource X and a request B to resource Y to observe both. Next,
 * resource X changes and tries to notify request A. However, the notification
 * goes lost (Implementation: ClientMessageInterceptor on the client cancels
 * it). The server retransmits the notification but it goes lost again. The
 * server now counts 2 failed transmissions. Next, the resource changes and
 * issues a new notification. The server cancels the old notification but keeps
 * the retransmission count (2) and the current timeout. After the forth
 * retransmission the server gives up and assumes the client 5683 is offline.
 * The server removes all relations with 5683.
 * <p>
 * In this test, retransmission is done constantly after 2 seconds (timeout does
 * not increase). It should be checked manually that the retransmission counter
 * is not reseted when a resource issues a new notification. The log should look
 * something like this:
 * 
 * <pre>
 *   19 INFO [ReliabilityLayer$RetransmissionTask]: Timeout: retransmit message, failed: 1, ...
 *   11 INFO [ReliabilityLayer$RetransmissionTask]: Timeout: retransmit message, failed: 2, ...
 *   Resource resX changed to "resX says hi for the 3 time"
 *   19 INFO [ReliabilityLayer$RetransmissionTask]: Timeout: retransmit message, failed: 3, ...
 *   11 INFO [ReliabilityLayer$RetransmissionTask]: Timeout: retransmit message, failed: 4, ...
 *   17 INFO [ReliabilityLayer$RetransmissionTask]: Timeout: retransmission limit reached, exchange failed, ...
 * </pre>
 */
@Category(Medium.class)
public class ObserveTest {

	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	static final String TARGET_X = "resX";
	static final String TARGET_Y = "resY";
	static final String RESPONSE = "hi";

	static final AtomicInteger counter = new AtomicInteger();

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private CoapEndpoint serverEndpoint;
	private MyResource resourceX;
	private MyResource resourceY;
	private MyObservationStore observations;

	private final CountDownLatch waitforit = new CountDownLatch(1);

	private String uriX;
	private String uriY;

	@Before
	public void startupServer() {
		cleanup.add(createServer());
	}

	@After
	public void shutdownServer() {
		Endpoint endpoint = EndpointManager.getEndpointManager().getDefaultEndpoint();
		for (MessageInterceptor interceptor : endpoint.getInterceptors()) {
			endpoint.removeInterceptor(interceptor);
		}
	}

	@Test
	public void testObserveLifecycle() throws Exception {

		ClientMessageInterceptor interceptor = new ClientMessageInterceptor();
		EndpointManager.getEndpointManager().getDefaultEndpoint().addInterceptor(interceptor);

		// setup observe relation to resource X and Y
		Request requestA = Request.newGet();
		requestA.setURI(uriX);
		requestA.setObserve();
		requestA.send();

		Request requestB = Request.newGet();
		requestB.setURI(uriY);
		requestB.setObserve();
		requestB.send();

		Response resp1 = requestA.waitForResponse(1000);
		// ensure relations are established
		assertNotNull("Client received no response", resp1);
		assertTrue(resp1.getOptions().hasObserve());
		assertEquals(1, resourceX.getObserverCount());
		assertEquals(resp1.getPayloadString(), resourceX.currentResponse);

		Response resp2 = requestB.waitForResponse(1000);
		assertNotNull("Client received no response", resp2);
		assertTrue(resp2.getOptions().hasObserve());
		assertEquals(1, resourceY.getObserverCount());
		assertEquals(resp2.getPayloadString(), resourceY.currentResponse);

		System.out.println(System.lineSeparator() + "Observe relation established, resource changes");

		// change resource but lose response
		Thread.sleep(50);
		// change to "resX says Lifecycle for the 2 time"
		resourceX.changed("Lifecycle");
		// => trigger notification
		// (which will go lost, see ClientMessageInterceptor)

		// wait for the server to timeout, see ClientMessageInterceptor.
		assertTrue(waitforit.await(1000, TimeUnit.MILLISECONDS));

		Thread.sleep(500);

		// the server should now have canceled all observer relations with 5683
		// - request A to resource X
		// - request B to resource Y

		// check that relations to resource X AND Y have been canceled
		assertEquals(0, resourceX.getObserverCount());
		assertEquals(0, resourceY.getObserverCount());

		observations.setStoreException(new ObservationStoreException("test"));

		Request requestC = Request.newGet();
		requestC.setURI(uriY);
		requestC.setObserve();
		requestC.send();

		Response responseC = requestC.waitForResponse(1000);
		assertNull("Client received unexpected response", responseC);
		assertNotNull("send error expected", requestC.getSendError());
	}

	@Test
	public void testObserveClient() throws Exception {

		final AtomicInteger resetCounter = new AtomicInteger(0);

		serverEndpoint.addInterceptor(new ServerMessageInterceptor(resetCounter));
		resourceX.setObserveType(Type.NON);

		int repeat = 3;

		CoapClient client = new CoapClient(uriX);
		CountingCoapHandler handler = new CountingCoapHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		// onLoad is called asynchronous to returning the response
		// therefore wait for one onLoad
		assertTrue(handler.waitOnLoadCalls(1, 1000, TimeUnit.MILLISECONDS));

		assertFalse("Response not received", rel.isCanceled());
		assertNotNull("Response not received", rel.getCurrent());
		assertEquals("\"resX says hi for the 1 time\"", rel.getCurrent().getResponseText());

		rel.reactiveCancel();
		System.out.println(uriX + " reactive canceled");

		for (int i = 0; i < repeat; ++i) {
			resourceX.changed("client");
			Thread.sleep(50);
		}

		// still only one notification (the response) is received
		assertFalse(handler.waitOnLoadCalls(2, 1000, TimeUnit.MILLISECONDS));
		assertEquals(repeat, resetCounter.get()); // repeat RST received
		// no RST delivered (interceptor)
		assertEquals(1, resourceX.getObserverCount());
		client.shutdown();
	}

	@Test
	public void testObserveClientReregister() throws Exception {
		resourceX.setObserveType(Type.NON);
		MessageObserverCounterMessageInterceptor interceptor = new MessageObserverCounterMessageInterceptor();
		EndpointManager.getEndpointManager().getDefaultEndpoint().addInterceptor(interceptor);

		CoapClient client = new CoapClient(uriX);
		CountingCoapHandler handler = new CountingCoapHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		assertTrue(handler.waitOnLoadCalls(1, 1000, TimeUnit.MILLISECONDS));

		assertFalse("Response not received", rel.isCanceled());
		assertNotNull("Response not received", rel.getCurrent());
		assertEquals("\"resX says hi for the 1 time\"", rel.getCurrent().getResponseText());
		int counter = interceptor.getMessageObserverCounter();

		resourceX.changed("client");
		// assert notify received
		assertTrue(handler.waitOnLoadCalls(2, 1000, TimeUnit.MILLISECONDS));
		assertFalse(rel.isCanceled());
		assertEquals("\"resX says client for the 2 time\"", rel.getCurrent().getResponseText());

		rel.reregister();
		assertFalse(rel.isCanceled());
		// assert reregister succeeded
		assertTrue(handler.waitOnLoadCalls(3, 1000, TimeUnit.MILLISECONDS));
		System.out.println(uriX + " reregistered");
		assertFalse(rel.isCanceled());
		// resource not changed
		assertEquals("\"resX says client for the 2 time\"", rel.getCurrent().getResponseText());

		resourceX.changed("new client");
		// assert notify received after reregister
		assertTrue(handler.waitOnLoadCalls(4, 1000, TimeUnit.MILLISECONDS));
		assertEquals("\"resX says new client for the 3 time\"", rel.getCurrent().getResponseText());
		assertEquals(1, resourceX.getObserverCount());

		assertEquals("message observer leak", counter, interceptor.getMessageObserverCounter());

		client.shutdown();
	}

	@Test(expected = IllegalStateException.class)
	public void testObserveClientReregisterAfterReject() throws Exception {
		resourceX.setObserveType(Type.NON);
		resourceX.rejectNextGet();
		CoapClient client = new CoapClient(uriX);
		try {
			CountingCoapHandler handler = new CountingCoapHandler();
			CoapObserveRelation rel = client.observeAndWait(handler);
			assertTrue("Not rejected", rel.isCanceled());
			rel.reregister();
		} finally {
			client.shutdown();
		}
	}

	@Test(expected = IllegalStateException.class)
	public void testObserveClientReregisterAfterTimeout() throws Exception {
		resourceX.setObserveType(Type.NON);
		resourceX.delayNextGet(100);
		CoapClient client = new CoapClient(uriX);
		try {
			client.setTimeout(1L);
			CountingCoapHandler handler = new CountingCoapHandler();
			CoapObserveRelation rel = client.observeAndWait(handler);
			assertTrue("No timeout", rel.isCanceled());
			client.setTimeout(null);
			rel.reregister();
		} finally {
			client.shutdown();
		}
	}

	@Test
	public void testObserveClientReregisterBeforeTimeout() throws Exception {
		resourceX.setObserveType(Type.NON);
		resourceX.delayNextGet(100);
		CoapClient client = new CoapClient(uriX);
		try {
			CountingCoapHandler handler = new CountingCoapHandler();
			CoapObserveRelation rel = client.observe(handler);
			assertFalse("Timeout", rel.isCanceled());
			assertFalse("reregister not ignored", rel.reregister()); 
			assertTrue(handler.waitOnLoadCalls(1, 1000, TimeUnit.MILLISECONDS));

			resourceX.changed("client");
			// assert notify received
			assertTrue(handler.waitOnLoadCalls(2, 1000, TimeUnit.MILLISECONDS));
			assertFalse("Response not received", rel.isCanceled());
		} finally {
			client.shutdown();
		}
	}

	@Test
	public void testObserveClientReregisterAfterReregister() throws Exception {
		resourceX.setObserveType(Type.NON);

		CoapClient client = new CoapClient(uriX);
		CountingCoapHandler handler = new CountingCoapHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);
		assertFalse("Response not received", rel.isCanceled());
		assertTrue(handler.waitOnLoadCalls(1, 1000, TimeUnit.MILLISECONDS));
		resourceX.delayNextGet(100);
		// one more onLoad call
		assertTrue("reregister not triggered", rel.reregister()); 
		// one more onLoad call
		assertFalse("reregister not ignored", rel.reregister()); 
		assertTrue(handler.waitOnLoadCalls(2, 1000, TimeUnit.MILLISECONDS));
		// one more onLoad call
		resourceX.changed("client");
		// assert notify received
		assertTrue(handler.waitOnLoadCalls(3, 1000, TimeUnit.MILLISECONDS));
		assertFalse("Response not received", rel.isCanceled());
		client.shutdown();
	}

	/**
	 * Test case for CoapClient.observeAndWait(Request request, CoapHandler
	 * handler) exception handling.
	 * 
	 * @throws Exception
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testObserveAndWaitExceptionHandling() throws Exception {
		CoapClient client = new CoapClient(uriX);
		try {
			Request request = Request.newGet().setURI(uriX);

			@SuppressWarnings("unused")
			CoapObserveRelation rel = client.observeAndWait(request, new CountingCoapHandler());
		} finally {
			client.shutdown();
		}
	}

	/**
	 * Test case for CoapClient.observe(Request request, CoapHandler handler)
	 * exception handling.
	 * 
	 * @throws Exception
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testObserveExceptionHandling() throws Exception {
		CoapClient client = new CoapClient(uriX);
		try {
			Request request = Request.newGet().setURI(uriX);

			@SuppressWarnings("unused")
			CoapObserveRelation rel = client.observe(request, new CountingCoapHandler());
		} finally {
			client.shutdown();
		}
	}

	private CoapServer createServer() {
		// retransmit constantly all 200 milliseconds
		NetworkConfig config = network.createTestConfig().setInt(NetworkConfig.Keys.ACK_TIMEOUT, 200)
				.setFloat(NetworkConfig.Keys.ACK_RANDOM_FACTOR, 1f).setFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE, 1f);

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		builder.setNetworkConfig(config);

		serverEndpoint = builder.build();
		int count = counter.incrementAndGet();
		CoapServer server = new CoapServer(config);
		server.setExecutors(ExecutorsUtil.newScheduledThreadPool(//
				config.getInt(NetworkConfig.Keys.PROTOCOL_STAGE_THREAD_COUNT),
				new NamedThreadFactory("CoapServer(main):" + count + "#")), //$NON-NLS-1$
				ExecutorsUtil.newDefaultSecondaryScheduler("CoapServer(secondary):" + count + "#"), false);
		server.addEndpoint(serverEndpoint);
		resourceX = new MyResource(TARGET_X);
		resourceY = new MyResource(TARGET_Y);
		server.add(resourceX);
		server.add(resourceY);
		server.start();

		uriX = TestTools.getUri(serverEndpoint, TARGET_X);
		uriY = TestTools.getUri(serverEndpoint, TARGET_Y);

		observations = new MyObservationStore();

		// setup the client endpoint using the special observation store
		builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		builder.setNetworkConfig(config);
		builder.setObservationStore(observations);
		CoapEndpoint coapEndpoint = builder.build();
		EndpointManager.getEndpointManager().setDefaultEndpoint(coapEndpoint);

		return server;
	}

	private class ClientMessageInterceptor extends MessageInterceptorAdapter {

		private int counter = 0; // counts the incoming responses

		@Override
		public void receiveResponse(Response response) {
			counter++;
			switch (counter) {
			case 1:
			case 2:
				// first responses for request A and B
				break;
			case 3: // lose transm. 0 of X's first notification
			case 4: // lose transm. 1 of X's first notification
				lose(response);
				break;
			case 5:
				lose(response); // lose transm. 2 of X's first notification
				resourceX.changed(); // change to "resX sais hi for the 3 time"
				break;

			// Note: The resource has changed and needs to send a second
			// notification. However, the first notification has not been
			// acknowledged yet. Therefore, the second notification keeps the
			// transmission counter of the first notification. There are no
			// transm. 0 and 1 of X's second notification.

			case 6:
				lose(response); // lose transm. 3 of X's second notification
				break;
			case 7:
				lose(response); // lose transm. 4 of X's second notification

				// Note: The server now reaches the retransmission limit and
				// cancels the response. Since it was an observe notification,
				// the server now removes all observe relations from the
				// endpoint 5683 which are request A to resource X and request B
				// to resource Y.

				waitforit.countDown();
				break;
			default:
				throw new IllegalStateException("Should not receive " + counter + " responses");
			}
		}

		private void lose(Response response) {
			System.out.println(System.lineSeparator() + "Lose response " + counter + " with MID " + response.getMID()
					+ ", payload = " + response.getPayloadString());
			response.cancel();
		}
	}

	private class ServerMessageInterceptor extends MessageInterceptorAdapter {

		private final AtomicInteger resetCounter;

		public ServerMessageInterceptor(AtomicInteger resetCounter) {
			this.resetCounter = resetCounter;
		}

		@Override
		public void receiveEmptyMessage(EmptyMessage message) {
			if (message.getType() == Type.RST) {
				int counter = resetCounter.incrementAndGet();
				System.out.println("Received " + counter + ". RST: " + message.getMID());
				// this cancel stops the message processing
				// => notifies will continue
				message.cancel();
			}
		}
	}

	private class MessageObserverCounterMessageInterceptor extends MessageInterceptorAdapter {

		private int messageObserverCounter = 0;

		private synchronized int getMessageObserverCounter() {
			return messageObserverCounter;
		}

		@Override
		public synchronized void sendRequest(Request request) {
			messageObserverCounter = request.getMessageObservers().size();
		}

	}

	private static class MyResource extends CoapResource {

		private volatile Type type = Type.CON;
		private volatile String currentLabel;
		private volatile String currentResponse;
		private AtomicBoolean reject = new AtomicBoolean();
		private AtomicInteger counter = new AtomicInteger();
		private AtomicInteger delay = new AtomicInteger();

		public MyResource(String name) {
			super(name);
			prepareResponse();
			setObservable(true);
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			int delay = this.delay.getAndSet(0);
			if (0 < delay) {
				try {
					Thread.sleep(delay);
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					return;
				}
			}
			if (reject.compareAndSet(true, false)) {
				exchange.reject();
			} else {
				Response response = new Response(ResponseCode.CONTENT);
				response.setPayload(currentResponse);
				response.setType(type);
				exchange.respond(response);
			}
		}

		@Override
		public void changed() {
			prepareResponse();
			super.changed();
		}

		public void changed(String label) {
			currentLabel = label;
			changed();
		}

		public void rejectNextGet() {
			reject.set(true);
		}

		public void delayNextGet(int delay) {
			this.delay.set(delay);
		}

		public void prepareResponse() {
			int count = counter.incrementAndGet();
			if (null == currentLabel) {
				currentResponse = String.format("\"%s says hi for the %d time\"", getName(), count);
			} else {
				currentResponse = String.format("\"%s says %s for the %d time\"", getName(), currentLabel, count);
			}
			System.out.println("Resource " + getName() + " changed to " + currentResponse);
		}

	}
	
	/**
	 * An observation store that keeps all observations in-memory.
	 */
	private static class MyObservationStore implements ObservationStore {

		private final ConcurrentMap<Token, Observation> map = new ConcurrentHashMap<>();
		private volatile AtomicReference<ObservationStoreException> exception = new AtomicReference<ObservationStoreException>();
		
		public MyObservationStore() {
		}

		public void setStoreException(ObservationStoreException exception) {
			this.exception.set(exception);
		}

		@Override
		public void setExecutor(ScheduledExecutorService executor) {
		}

		@Override
		public Observation putIfAbsent(Token key, Observation obs) {
			if (key == null) {
				throw new NullPointerException("token must not be null");
			} else if (obs == null) {
				throw new NullPointerException("observation must not be null");
			} else {
				ObservationStoreException exception = this.exception.getAndSet(null);
				if (exception != null) {
					throw exception;
				}
				return map.putIfAbsent(key, obs);
			}
		}

		@Override
		public Observation put(Token key, Observation obs) {
			if (key == null) {
				throw new NullPointerException("token must not be null");
			} else if (obs == null) {
				throw new NullPointerException("observation must not be null");
			} else {
				ObservationStoreException exception = this.exception.getAndSet(null);
				if (exception != null) {
					throw exception;
				}
				return map.put(key, obs);
			}
		}

		@Override
		public Observation get(Token token) {
			if (token == null) {
				return null;
			} else {
				Observation obs = map.get(token);
				// clone request in order to prevent accumulation of
				// message observers on original request
				return ObservationUtil.shallowClone(obs);
			}
		}

		@Override
		public void remove(Token token) {
			if (token != null) {
				map.remove(token);
			}
		}

		@Override
		public void setContext(Token token, final EndpointContext ctx) {

			if (token != null && ctx != null) {
				Observation obs = map.get(token);
				if (obs != null) {
					map.replace(token, obs, new Observation(obs.getRequest(), ctx));
				}
			}
		}

		@Override
		public void start() {
		}

		@Override
		public void stop() {
		}
	}
	

}
