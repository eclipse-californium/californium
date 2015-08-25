package org.eclipse.californium.core.test;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.Semaphore;

import javax.swing.Timer;

import junit.framework.Assert;

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
import org.eclipse.californium.core.network.CoAPEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class MemoryLeakingHashMapTest {

	// Configuration for this test
	public static final int TEST_EXCHANGE_LIFETIME = 247; // 0.247 seconds
	public static final int TEST_SWEEP_DEDUPLICATOR_INTERVAL = 100; // 1 second
	public static final int TEST_BLOCK_SIZE = 16; // 16 bytes

	public static final int OBS_NOTIFICATION_INTERVAL = 50; // send one notification per 500 ms
	public static final int HOW_MANY_NOTIFICATION_WE_WAIT_FOR = 3;

	// The names of the two resources of the server
	public static final String PIGGY = "piggy";
	public static final String SEPARATE = "separate";
	
	// The server endpoint that we test
	private CoAPEndpoint serverEndpoint;
	private CoAPEndpoint clientEndpoint;
	private EndpointSurveillant serverSurveillant;
	private EndpointSurveillant clientSurveillant;

	private String currentRequestText;
	private String currentResponseText;
	
	private CoapServer server;
	private int serverPort;
		
	private Timer timer;
	
	@Before
	public void startupServer() throws Exception {
		System.out.println("\nStart "+getClass().getSimpleName());
		createServerAndClientEntpoints();
	}
	
	@After
	public void shutdownServer() {
		server.destroy();
		System.out.println("End "+getClass().getSimpleName());
	}
	
	@Test
	public void testServer() throws Exception {
		testSimpleNONGet(uriOf(PIGGY));
		
		testSimpleGet(uriOf(PIGGY));
		testSimpleGet(uriOf(SEPARATE));

		testBlockwise(uriOf(PIGGY));
		testBlockwise(uriOf(SEPARATE));
		testBlockwiseNON(uriOf(PIGGY));
		
		testObserveProactive(uriOf(PIGGY));
		testObserveReactive(uriOf(PIGGY));
		testObserveBlockwise(uriOf(PIGGY));
	}
	
	private void testSimpleNONGet(String uri) throws Exception {
		System.out.println("Test simple NON GET to "+uri);
		
		currentResponseText = "simple NON GET";
		
		Request request = Request.newGet();
		request.setURI(uri);
		request.setType(Type.NON);
		Response response = request.send(clientEndpoint).waitForResponse(100);
		
		System.out.println("Client received response "+response.getPayloadString()+" with msg type "+response.getType());
		Assert.assertEquals(currentResponseText, response.getPayloadString());
		Assert.assertEquals(Type.NON, response.getType());
		
		serverSurveillant.waitUntilDeduplicatorShouldBeEmpty();
		serverSurveillant.assertHashMapsEmpty();
		clientSurveillant.assertHashMapsEmpty();
	}
	
	private void testSimpleGet(String uri) throws Exception {
		System.out.println("Test simple GET to "+uri);
		
		currentResponseText = "simple GET";
		
		CoapClient client = new CoapClient(uri);
		client.setEndpoint(clientEndpoint);
		
		CoapResponse response = client.get();
		System.out.println("Client received response "+response.getResponseText());
		Assert.assertEquals(currentResponseText, response.getResponseText());

		serverSurveillant.waitUntilDeduplicatorShouldBeEmpty();
		serverSurveillant.assertHashMapsEmpty();
		clientSurveillant.assertHashMapsEmpty();
	}
	
	private void testBlockwise(String uri) throws Exception {
		System.out.println("Test blockwise POST to "+uri);
		
		String ten = "123456789.";
		currentRequestText = ten+ten+ten;
		currentResponseText = ten+ten+ten+ten+ten;
		
		CoapClient client = new CoapClient(uri);
		client.setEndpoint(clientEndpoint);
		
		CoapResponse response = client.post(currentRequestText, MediaTypeRegistry.TEXT_PLAIN);
		System.out.println("Client received response "+response.getResponseText());
		Assert.assertEquals(currentResponseText, response.getResponseText());
		
		serverSurveillant.waitUntilDeduplicatorShouldBeEmpty();
		serverSurveillant.assertHashMapsEmpty();
		clientSurveillant.assertHashMapsEmpty();
	}
	
	private void testBlockwiseNON(String uri) throws Exception {
		System.out.println("Test blockwise POST to "+uri);

		String ten = "123456789.";
		currentRequestText = ten+ten+ten;
		currentResponseText = ten+ten+ten+ten+ten;
		
		CoapClient client = new CoapClient(uri).useNONs();
		client.setEndpoint(clientEndpoint);
		
		CoapResponse response = client.post(currentRequestText, MediaTypeRegistry.TEXT_PLAIN);
		System.out.println("Client received response "+response.getResponseText());
		Assert.assertEquals(currentResponseText, response.getResponseText());
		
		serverSurveillant.waitUntilDeduplicatorShouldBeEmpty();
		serverSurveillant.assertHashMapsEmpty();
		clientSurveillant.assertHashMapsEmpty();
	}
	
	private void testObserveProactive(final String uri) throws Exception {
		System.out.println("Test observe relation with a reactive cancelation to "+uri);
		
		currentResponseText = "Hello observer";
		
		// We use a semaphore to return after the test has completed
		final Semaphore semaphore = new Semaphore(0);

		/*
		 * This Handler counts the notification and cancels the relation when
		 * it has received HOW_MANY_NOTIFICATION_WE_WAIT_FOR.
		 */
		class CoapObserverAndCanceler implements CoapHandler {
			private CoapObserveRelation relation;
			private int notificationCounter = 0;

			public void onLoad(CoapResponse response) {
				++notificationCounter;
				System.out.println("Client received notification "+notificationCounter+": "+response.getResponseText());
				
				if (notificationCounter == HOW_MANY_NOTIFICATION_WE_WAIT_FOR) {
					System.out.println("Client cancels observe relation to "+uri);
					relation.proactiveCancel();
					
				} else if (notificationCounter == HOW_MANY_NOTIFICATION_WE_WAIT_FOR + 1) {
					// Now we received the response to the canceling GET request
					semaphore.release();
				}
				
			}
			
			public void onError() {
				Assert.assertTrue(false); // should not happen
			}
		}
		
		CoapClient client = new CoapClient(uri);
		client.setEndpoint(clientEndpoint);
		CoapObserverAndCanceler handler = new CoapObserverAndCanceler();
		CoapObserveRelation rel = client.observe(handler);
		handler.relation = rel;
		
		// Wait until we have received all the notifications and canceled the relation
		Thread.sleep(HOW_MANY_NOTIFICATION_WE_WAIT_FOR * OBS_NOTIFICATION_INTERVAL + 100);
		
		boolean success = semaphore.tryAcquire();
		Assert.assertTrue("Client has not received all expected responses", success);
		
		serverSurveillant.waitUntilDeduplicatorShouldBeEmpty();
		serverSurveillant.assertHashMapsEmpty();
		clientSurveillant.assertHashMapsEmpty();
	}
	
	private void testObserveReactive(final String uri) throws Exception {
		System.out.println("Test observe relation with a reactive cancelation to "+uri);
		
		currentResponseText = "Hello observer";
		
		// We use a semaphore to return after the test has completed
		final Semaphore semaphore = new Semaphore(0);

		/*
		 * This Handler counts the notification and forgets the relation when
		 * it has received HOW_MANY_NOTIFICATION_WE_WAIT_FOR.
		 */
		class CoapObserverAndForgetter implements CoapHandler {
			private CoapObserveRelation relation;
			private int notificationCounter = 0;

			public void onLoad(CoapResponse response) {
				++notificationCounter;
				System.out.println("Client received notification "+notificationCounter+": "+response.getResponseText());
				
				if (notificationCounter == HOW_MANY_NOTIFICATION_WE_WAIT_FOR) {
					System.out.println("Client forgets observe relation to "+uri);
					relation.reactiveCancel();
					semaphore.release();
				}
			}
			
			public void onError() {
				Assert.assertTrue(false); // should not happen
			}
		}
		
		CoapClient client = new CoapClient(uri);
		client.setEndpoint(clientEndpoint);
		CoapObserverAndForgetter handler = new CoapObserverAndForgetter();
		CoapObserveRelation rel = client.observe(handler);
		handler.relation = rel;
		
		// Wait until we have received all the notifications and canceled the relation
		Thread.sleep(HOW_MANY_NOTIFICATION_WE_WAIT_FOR * OBS_NOTIFICATION_INTERVAL + 100);
		
		boolean success = semaphore.tryAcquire();
		Assert.assertTrue("Client has not received all expected responses", success);
		
		serverSurveillant.waitUntilDeduplicatorShouldBeEmpty();
		serverSurveillant.assertHashMapsEmpty();
		clientSurveillant.assertHashMapsEmpty();
	}
	
	private void testObserveBlockwise(final String uri) throws Exception {
		System.out.println("Test observe relation with blockwise notifications "+uri);

		// We need a long response text (>16) 
		String ten = "123456789.";
		currentResponseText = ten+ten+ten;
		
		// We use a semaphore to return after the test has completed
		final Semaphore semaphore = new Semaphore(0);
		
		/*
		 * This Handler counts the notification and cancels the relation when
		 * it has received HOW_MANY_NOTIFICATION_WE_WAIT_FOR.
		 */
		class CoapObserverAndCanceler implements CoapHandler {
			private CoapObserveRelation relation;
			private int notificationCounter = 0;

			public void onLoad(CoapResponse response) {
				++notificationCounter;
				System.out.println("Client received notification "+notificationCounter+": "+response.getResponseText());
				
				if (notificationCounter == HOW_MANY_NOTIFICATION_WE_WAIT_FOR) {
					System.out.println("Client cancels observe relation to "+uri);
					relation.proactiveCancel();
					
				} else if (notificationCounter == HOW_MANY_NOTIFICATION_WE_WAIT_FOR + 1) {
					// Now we received the response to the canceling GET request
					semaphore.release();
				}
				
			}
			
			public void onError() {
				Assert.assertTrue(false); // should not happen
			}
		}
		
		CoapClient client = new CoapClient(uri);
		client.setEndpoint(clientEndpoint);
		CoapObserverAndCanceler handler = new CoapObserverAndCanceler();
		CoapObserveRelation rel = client.observe(handler);
		handler.relation = rel;
		
		// Wait until we have received all the notifications and canceled the relation
		Thread.sleep(HOW_MANY_NOTIFICATION_WE_WAIT_FOR * OBS_NOTIFICATION_INTERVAL + 100);
		
		boolean success = semaphore.tryAcquire();
		Assert.assertTrue("Client has not received all expected responses", success);
		
		serverSurveillant.waitUntilDeduplicatorShouldBeEmpty();
		serverSurveillant.assertHashMapsEmpty();
		clientSurveillant.assertHashMapsEmpty();
	}
	
	private void createServerAndClientEntpoints() throws Exception {
		timer = new Timer(OBS_NOTIFICATION_INTERVAL, null);
		
		NetworkConfig config = new NetworkConfig()
			// We make sure that the sweep deduplicator is used
			.setString(NetworkConfig.Keys.DEDUPLICATOR, NetworkConfig.Keys.DEDUPLICATOR_MARK_AND_SWEEP)
			.setInt(NetworkConfig.Keys.MARK_AND_SWEEP_INTERVAL, TEST_EXCHANGE_LIFETIME)
			.setLong(NetworkConfig.Keys.EXCHANGE_LIFETIME, TEST_SWEEP_DEDUPLICATOR_INTERVAL)
			
			// We set the block size to 16 bytes
			.setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, TEST_BLOCK_SIZE)
			.setInt(NetworkConfig.Keys.PREFERRED_BLOCK_SIZE, TEST_BLOCK_SIZE);
		
		// Create the endpoint for the server and create surveillant
		serverEndpoint = new CoAPEndpoint(new InetSocketAddress((InetAddress) null, 0), config);
		serverEndpoint.addInterceptor(new MessageTracer());
		serverSurveillant = new EndpointSurveillant("server", serverEndpoint);
		
		clientEndpoint = new CoAPEndpoint(config);
		clientEndpoint.start();
		clientSurveillant = new EndpointSurveillant("client", clientEndpoint);
		
		// Create a server with two resources: one that sends piggy-backed
		// responses and one that sends separate responses

		server = new CoapServer(config);
		server.addEndpoint(serverEndpoint);
		server.add(new TestResource(PIGGY,    Mode.PIGGY_BACKED_RESPONSE));
		server.add(new TestResource(SEPARATE, Mode.SEPARATE_RESPONE));
		server.start();
		serverPort = serverEndpoint.getAddress().getPort();
		
		timer.start();
	}
	
	private String uriOf(String resourcePath) {
		return "coap://localhost:" + serverPort + "/" + resourcePath;
	}
	
	public enum Mode { PIGGY_BACKED_RESPONSE, SEPARATE_RESPONE; }
	
	public class TestResource extends CoapResource implements ActionListener {

		private Mode mode;
		private int status;
		
		public TestResource(String name, Mode mode) {
			super(name);
			this.mode = mode;
			this.status = 0;
			
			setObservable(true);
			timer.addActionListener(this);
		}
		
		@Override public void actionPerformed(ActionEvent e) {
			++status;
			System.out.println("TestResource "+getName()+" performed "+status+" changes");
			changed();
		}
		
		@Override public void handleGET(CoapExchange exchange) {
			if (mode == Mode.SEPARATE_RESPONE)
				exchange.accept();
			exchange.respond(currentResponseText);
		}
		
		@Override public void handlePOST(CoapExchange exchange) {
			Assert.assertEquals(currentRequestText, exchange.getRequestText());
			if (mode == Mode.SEPARATE_RESPONE)
				exchange.accept();
			
			System.out.println("TestResource "+getName()+" received POST message: "+exchange.getRequestText());
			
			exchange.respond(ResponseCode.CREATED, currentResponseText);
		}
		
		@Override public void handlePUT(CoapExchange exchange) {
			Assert.assertEquals(currentRequestText, exchange.getRequestText());
			exchange.accept();
			currentResponseText = "";
			exchange.respond(ResponseCode.CHANGED);
		}
		
		@Override public void handleDELETE(CoapExchange exchange) {
			currentResponseText = "";
			exchange.respond(ResponseCode.DELETED);
		}
	}
}
