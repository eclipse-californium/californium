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
package org.eclipse.californium.core.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageInterceptor;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.junit.After;
import org.junit.Before;
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
 *   Resource resX changed to "resX sais hi for the 3 time"
 *   19 INFO [ReliabilityLayer$RetransmissionTask]: Timeout: retransmit message, failed: 3, ...
 *   11 INFO [ReliabilityLayer$RetransmissionTask]: Timeout: retransmit message, failed: 4, ...
 *   17 INFO [ReliabilityLayer$RetransmissionTask]: Timeout: retransmission limit reached, exchange failed, ...
 * </pre>
 */
@Category(Medium.class)
public class ObserveTest {
	
	public static final String TARGET_X = "resX";
	public static final String TARGET_Y = "resY";
	public static final String RESPONSE = "hi";
	
	private CoapServer server;
	private MyResource resourceX;
	private MyResource resourceY;
	private ClientMessageInterceptor interceptor;
	
	private boolean waitforit = true;
	
	private int serverPort;
	private String uriX;
	private String uriY;
	
	private int notificationCounter = 0;
	private int resetCounter = 0;
	
	@Before
	public void startupServer() {
		System.out.println("\nStart "+getClass().getSimpleName());
		createServer();
	}
	
	@After
	public void shutdownServer() {
		EndpointManager.getEndpointManager().getDefaultEndpoint().removeInterceptor(interceptor);
		server.destroy();
		System.out.println("End "+getClass().getSimpleName());
	}
	
	@Test
	public void testObserveLifecycle() throws Exception {
		
		this.interceptor = new ClientMessageInterceptor();
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
		
		// ensure relations are established
		Response resp1 = requestA.waitForResponse(1000);
		assertNotNull("Client received no response", resp1);
		assertTrue(resp1.getOptions().hasObserve());
		assertTrue(resourceX.getObserverCount() == 1);
		assertEquals(resp1.getPayloadString(), resourceX.currentResponse);

		Response resp2 = requestB.waitForResponse(1000);
		assertNotNull("Client received no response", resp2);
		assertTrue(resp2.getOptions().hasObserve());
		assertTrue(resourceY.getObserverCount() == 1);
		assertEquals(resp2.getPayloadString(), resourceY.currentResponse);
		System.out.println("\nObserve relation established, resource changes");
		
		// change resource but lose response
		Thread.sleep(50);
		resourceX.changed(); // change to "resX sais hi for the 2 time"
		// => trigger notification (which will go lost, see ClientMessageInterceptor)
		
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
		
		server.getEndpoints().get(0).addInterceptor(new ServerMessageInterceptor());
		resourceX.setObserveType(Type.NON);
		
		notificationCounter = 0;
		resetCounter = 0;
		
		int repeat = 3;
		
		CoapClient client = new CoapClient(uriX);
		
		CoapObserveRelation rel = client.observeAndWait(new CoapHandler() {
			@Override
			public void onLoad(CoapResponse response) {
				System.out.println("Received Notification: "+response.advanced().getMID());
				++notificationCounter;
			}
			@Override
			public void onError() { }
		});
		
		rel.reactiveCancel();
		Thread.sleep(50);

		for (int i=0; i<repeat; ++i) {
			resourceX.changed();
			Thread.sleep(50);
		}
		
		assertEquals(1, notificationCounter); // only one notification received
		assertEquals(repeat, resetCounter); // repeat RST received
		assertTrue(resourceX.getObserverCount() == 1); // no RST delivered (interceptor)
		
	}
	
	private void createServer() {
		// retransmit constantly all 2 seconds
		NetworkConfig config = new NetworkConfig()
			.setInt(NetworkConfig.Keys.ACK_TIMEOUT, 200)
			.setFloat(NetworkConfig.Keys.ACK_RANDOM_FACTOR, 1f)
			.setFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE, 1f);
		
		CoapEndpoint endpoint = new CoapEndpoint(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), config);
		
		server = new CoapServer();
		server.addEndpoint(endpoint);
		resourceX = new MyResource(TARGET_X);
		resourceY = new MyResource(TARGET_Y);
		server.add(resourceX);
		server.add(resourceY);
		server.start();
		
		serverPort = endpoint.getAddress().getPort();
		uriX = "localhost:"+serverPort+"/"+TARGET_X;
		uriY = "localhost:"+serverPort+"/"+TARGET_Y;
	}
	
	private class ClientMessageInterceptor implements MessageInterceptor {

		private int counter = 0; // counts the incoming responses
		
		@Override
		public void receiveResponse(Response response) {
			counter++;
			// frist responses for request A and B
			if (counter == 1) ; // resp 1 ok
			if (counter == 2) ; // resp 2 ok
			
			// notifications:
			if (counter == 3) lose(response); // lose transm. 0 of X's first notification
			if (counter == 4) lose(response); // lose transm. 1 of X's first notification
			if (counter == 5) {
				lose(response); // lose transm. 2 of X's first notification
				resourceX.changed(); // change to "resX sais hi for the 3 time"
			}
			
			/*
			 * Note: The resource has changed and needs to send a second
			 * notification. However, the first notification has not been
			 * acknowledged yet. Therefore, the second notification keeps the
			 * transmission counter of the first notification. There are no
			 * transm. 0 and 1 of X's second notification.
			 */
			
//			if (counter == 6) lose(response); // lose transm. 2 of X's second notification
			if (counter == 6) lose(response); // lose transm. 3 of X's second notification
			if (counter == 7) {
				lose(response); // lose transm. 4 of X's second notification

				/*
				 * Note: The server now reaches the retransmission limit and
				 * cancels the response. Since it was an observe notification,
				 * the server now removes all observe relations from the
				 * endpoint 5683 which are request A to resource X and request B
				 * to resource Y.
				 */
				waitforit = false;
			}
			
			if (counter >= 8) // error
				System.exit(-1);
//				throw new RuntimeException("Should not receive "+counter+" responses");
		}
		
		private void lose(Response response) {
			System.out.println("\nLose response "+counter+" with MID "+response.getMID()+", payload = "+response.getPayloadString());
			response.cancel();
		}
		
		@Override public void sendRequest(Request request) { }
		@Override public void sendResponse(Response response) { }
		@Override public void sendEmptyMessage(EmptyMessage message) { }
		@Override public void receiveRequest(Request request) { }
		@Override public void receiveEmptyMessage(EmptyMessage message) { }
	}
	
	private class ServerMessageInterceptor implements MessageInterceptor {
		
		@Override public void receiveResponse(Response response) { }
		@Override public void sendRequest(Request request) { }
		@Override public void sendResponse(Response response) { }
		@Override public void sendEmptyMessage(EmptyMessage message) { }
		@Override public void receiveRequest(Request request) { }
		@Override public void receiveEmptyMessage(EmptyMessage message) {
			if (message.getType()==Type.RST) {
				++resetCounter;
				System.out.println("Received RST: "+message.getMID());
				message.cancel();
			}
		}
	}
	
	private static class MyResource extends CoapResource {
		
		private Type type = Type.CON;
		private int counter = 0;
		private String currentResponse;
		
		public MyResource(String name) {
			super(name);
			setObservable(true);
			changed();
		}
		
		@Override
		public void handleGET(CoapExchange exchange) {
			Response response = new Response(ResponseCode.CONTENT);
			response.setPayload(currentResponse);
			response.setType(type);
			exchange.respond(response);
		}
		
		@Override
		public void changed() {
			currentResponse = "\""+getName()+" says hi for the "+(++counter)+" time\"";
			System.out.println("Resource "+getName()+" changed to "+currentResponse);
			super.changed();
		}
	}
}
