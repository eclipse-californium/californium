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

import static org.eclipse.californium.TestTools.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageInterceptorAdapter;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

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
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	static final String TARGET_X = "resX";
	static final String TARGET_Y = "resY";
	static final String RESPONSE = "hi";

	private CoapServer server;
	private MyResource resourceX;
	private MyResource resourceY;
	private ClientMessageInterceptor interceptor;

	private boolean waitforit = true;

	private String uriX;
	private String uriY;

	@Before
	public void startupServer() {
		System.out.printf("%sStart %s", System.lineSeparator(), getClass().getSimpleName());
		createServer();
	}

	@After
	public void shutdownServer() {
		EndpointManager.getEndpointManager().getDefaultEndpoint().removeInterceptor(interceptor);
		server.destroy();
		System.out.printf("End %s", getClass().getSimpleName());
	}

	@Test
	public void testObserveLifecycle() throws Exception {

		interceptor = new ClientMessageInterceptor();
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
		assertTrue(resourceX.getObserverCount() == 1);
		assertEquals(resp1.getPayloadString(), resourceX.currentResponse);

		Response resp2 = requestB.waitForResponse(1000);
		assertNotNull("Client received no response", resp2);
		assertTrue(resp2.getOptions().hasObserve());
		assertTrue(resourceY.getObserverCount() == 1);
		assertEquals(resp2.getPayloadString(), resourceY.currentResponse);

		System.out.printf("%sObserve relation established, resource changes", System.lineSeparator());

		// change resource but lose response
		Thread.sleep(50);
		// change to "resX says Lifecycle for the 2 time"
		resourceX.changed("Lifecycle");
		// => trigger notification
		// (which will go lost, see ClientMessageInterceptor)

		// wait for the server to timeout, see ClientMessageInterceptor.
		while (waitforit) {
			Thread.sleep(1000);
		}

		Thread.sleep(500);

		// the server should now have canceled all observer relations with 5683
		// - request A to resource X
		// - request B to resource Y

		// check that relations to resource X AND Y have been canceled
		assertTrue(resourceX.getObserverCount() == 0);
		assertTrue(resourceY.getObserverCount() == 0);
	}

	@Test
	public void testObserveClient() throws Exception {

		final AtomicInteger resetCounter = new AtomicInteger(0);

		server.getEndpoints().get(0).addInterceptor(new ServerMessageInterceptor(resetCounter));
		resourceX.setObserveType(Type.NON);

		int repeat = 3;

		CoapClient client = new CoapClient(uriX);
		CountingHandler handler = new CountingHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		// onLoad is called asynchronous to returning the response
		// therefore wait for one onLoad
		assertTrue(handler.waitForLoadCalls(1, 1000, TimeUnit.MILLISECONDS));

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
		assertFalse(handler.waitForLoadCalls(2, 1000, TimeUnit.MILLISECONDS));
		assertEquals(repeat, resetCounter.get()); // repeat RST received
		// no RST delivered (interceptor)
		assertEquals(1, resourceX.getObserverCount());
	}

	@Test
	public void testObserveClientReregister() throws Exception {
		resourceX.setObserveType(Type.NON);

		CoapClient client = new CoapClient(uriX);
		CountingHandler handler = new CountingHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);

		assertTrue(handler.waitForLoadCalls(1, 1000, TimeUnit.MILLISECONDS));

		assertFalse("Response not received", rel.isCanceled());
		assertNotNull("Response not received", rel.getCurrent());
		assertEquals("\"resX says hi for the 1 time\"", rel.getCurrent().getResponseText());
		
		resourceX.changed("client");
		// assert notify received
		assertTrue(handler.waitForLoadCalls(2, 1000, TimeUnit.MILLISECONDS));
		assertFalse(rel.isCanceled());
		assertEquals("\"resX says client for the 2 time\"", rel.getCurrent().getResponseText());
		
		rel.reregister();
		assertFalse(rel.isCanceled());
		// assert reregister succeeded
		assertTrue(handler.waitForLoadCalls(3, 1000, TimeUnit.MILLISECONDS));
		System.out.println(uriX + " reregistered");
		assertFalse(rel.isCanceled());
		// resource not changed
		assertEquals("\"resX says client for the 2 time\"", rel.getCurrent().getResponseText());
		
		resourceX.changed("new client");
		// assert notify received after reregister
		assertTrue(handler.waitForLoadCalls(4, 1000, TimeUnit.MILLISECONDS));
		assertEquals("\"resX says new client for the 3 time\"", rel.getCurrent().getResponseText());
		assertEquals(1, resourceX.getObserverCount());
	}

	@Test(expected = IllegalStateException.class)
	public void testObserveClientReregisterAfterReject() throws Exception {
		resourceX.setObserveType(Type.NON);
		resourceX.rejectNextGet();
		CoapClient client = new CoapClient(uriX);
		CountingHandler handler = new CountingHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);
		assertTrue("Not rejected", rel.isCanceled());
		rel.reregister();
	}

	@Test(expected = IllegalStateException.class)
	public void testObserveClientReregisterAfterTimeout() throws Exception {
		resourceX.setObserveType(Type.NON);
		resourceX.delayNextGet(100);
		CoapClient client = new CoapClient(uriX);
		long timeout = client.getTimeout();
		client.setTimeout(1);
		CountingHandler handler = new CountingHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);
		assertTrue("No timeout", rel.isCanceled());
		client.setTimeout(timeout);
		rel.reregister();
	}

	@Test
	public void testObserveClientReregisterBeforeTimeout() throws Exception {
		resourceX.setObserveType(Type.NON);
		resourceX.delayNextGet(100);
		CoapClient client = new CoapClient(uriX);
		CountingHandler handler = new CountingHandler();
		CoapObserveRelation rel = client.observe(handler);
		assertFalse("Timeout", rel.isCanceled());
		assertFalse("reregister not ignored", rel.reregister()); 
		assertTrue(handler.waitForLoadCalls(1, 1000, TimeUnit.MILLISECONDS));

		resourceX.changed("client");
		// assert notify received
		assertTrue(handler.waitForLoadCalls(2, 1000, TimeUnit.MILLISECONDS));
		assertFalse("Response not received", rel.isCanceled());
	}

	@Test
	public void testObserveClientReregisterAfterReregister() throws Exception {
		resourceX.setObserveType(Type.NON);

		CoapClient client = new CoapClient(uriX);
		CountingHandler handler = new CountingHandler();
		CoapObserveRelation rel = client.observeAndWait(handler);
		assertFalse("Response not received", rel.isCanceled());
		assertTrue(handler.waitForLoadCalls(1, 1000, TimeUnit.MILLISECONDS));
		resourceX.delayNextGet(100);
		// one more onLoad call
		assertTrue("reregister not triggered", rel.reregister()); 
		// one more onLoad call
		assertFalse("reregister not ignored", rel.reregister()); 
		assertTrue(handler.waitForLoadCalls(2, 1000, TimeUnit.MILLISECONDS));
		// one more onLoad call
		resourceX.changed("client");
		// assert notify received
		assertTrue(handler.waitForLoadCalls(3, 1000, TimeUnit.MILLISECONDS));
		assertFalse("Response not received", rel.isCanceled());
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
		Request request = Request.newGet().setURI(uriX);

		@SuppressWarnings("unused")
		CoapObserveRelation rel = client.observeAndWait(request, new CoapHandler() {

			@Override
			public void onLoad(CoapResponse response) {
			}

			@Override
			public void onError() {
			}
		});
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
		Request request = Request.newGet().setURI(uriX);

		@SuppressWarnings("unused")
		CoapObserveRelation rel = client.observe(request, new CoapHandler() {

			@Override
			public void onLoad(CoapResponse response) {
			}

			@Override
			public void onError() {
			}
		});
	}

	private void createServer() {
		// retransmit constantly all 200 milliseconds
		NetworkConfig config = network.createTestConfig().setInt(NetworkConfig.Keys.ACK_TIMEOUT, 200)
				.setFloat(NetworkConfig.Keys.ACK_RANDOM_FACTOR, 1f).setFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE, 1f);

		CoapEndpoint endpoint = new CoapEndpoint(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), config);

		server = new CoapServer();
		server.addEndpoint(endpoint);
		resourceX = new MyResource(TARGET_X);
		resourceY = new MyResource(TARGET_Y);
		server.add(resourceX);
		server.add(resourceY);
		server.start();

		uriX = getUri(endpoint, TARGET_X);
		uriY = getUri(endpoint, TARGET_Y);
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

				waitforit = false;
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

	private class CountingHandler implements CoapHandler {

		public AtomicInteger loadCalls = new AtomicInteger();
		public AtomicInteger errorCalls = new AtomicInteger();

		@Override
		public void onLoad(CoapResponse response) {
			int counter;
			synchronized (this) {
				counter = loadCalls.incrementAndGet();
				notifyAll();
			}
			System.out.println("Received " + counter + ". Notification: " + response.advanced());
		}

		@Override
		public void onError() {
			int counter;
			synchronized (this) {
				counter = errorCalls.incrementAndGet();
				notifyAll();
			}
			System.out.println(counter + " Errors!");
		}

		public boolean waitForLoadCalls(final int counter, final long timeout, final TimeUnit unit)
				throws InterruptedException {
			return waitForCalls(counter, timeout, unit, loadCalls);
		}

		private synchronized boolean waitForCalls(final int counter, final long timeout, final TimeUnit unit,
				AtomicInteger calls) throws InterruptedException {
			if (0 < timeout) {
				long end = System.nanoTime() + unit.toNanos(timeout);
				while (calls.get() < counter) {
					long left = TimeUnit.NANOSECONDS.toMillis(end - System.nanoTime());
					if (0 < left) {
						wait(left);
					} else {
						break;
					}
				}
			}
			return calls.get() >= counter;
		}
	}
}
