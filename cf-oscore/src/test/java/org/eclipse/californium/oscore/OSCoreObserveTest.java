/*******************************************************************************
 * Copyright (c) 2019 RISE SICS and others.
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
 * This test class is based on org.eclipse.californium.core.test.SmallServerClientTest
 * 
 * Contributors: 
 *    Rikard Höglund (RISE SICS) - testing OSCORE Observe messages
 ******************************************************************************/
package org.eclipse.californium.oscore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Random;
import java.util.Timer;
import java.util.TimerTask;

import org.eclipse.californium.category.Large;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * Performs tests of Observe message exchanges between an OSCORE server and client
 * Based on interoperability test specification created by Ericsson:
 * https://ericssonresearch.github.io/OSCOAP/test-spec5.html
 * 
 */
@Category(Large.class)
public class OSCoreObserveTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);
	
	private CoapServer server;
	private int serverPort;
	private static String serverAddress = InetAddress.getLoopbackAddress().getHostAddress();
	
	private static String clientAddress = InetAddress.getLoopbackAddress().getHostName();
	
	private static boolean withOSCORE = true;
	
	//OSCORE context information shared between server and client
	private final static HashMapCtxDB db = HashMapCtxDB.getInstance();
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] master_salt = { (byte) 0x9e, (byte) 0x7c, (byte) 0xa9, (byte) 0x22, (byte) 0x23,
			(byte) 0x78, (byte) 0x63, (byte) 0x40 };
	
	@Before
	public void initLogger() {
		System.out.println(System.lineSeparator() + "Start " + getClass().getSimpleName());
		EndpointManager.clear();
	}
	
	//Use the OSCORE stack factory
	@BeforeClass
	public static void setStackFactory() {
		OSCoreCoapStackFactory.useAsDefault();
	}

	@After
	public void after() {
		if (null != server) {
			server.destroy();
		}
		System.out.println("End " + getClass().getSimpleName());
	}
	
	/* --- Client Observe tests follow --- */ 
	
	/**
	 * Create an OSCORE request to be set from a client to the server
	 * 
	 * @param c Code of request
	 * @param resourceUri Relative URI of resource
	 * @return The request
	 */
	private Request createClientRequest(Code c, String resourceUri) {
		String serverUri = "coap://" + serverAddress + ":" + serverPort;
		
		Request r = new Request(c);
				
		r.setConfirmable(true);
		r.setURI(serverUri + resourceUri);
		
		if(withOSCORE) {
			r.getOptions().setOscore(new byte[0]); //Use OSCORE
		}
		
		return r;
	}
	
	/**
	 * Tests Observe functionality with OSCORE.
	 * First registers to a resource and listens for 2 notifications.
	 * After this the observation is cancelled.
	 * Equivalent to Test 7 in the interop test specification.
	 * 
	 * @throws InterruptedException if sleep fails
	 */
	@Test
	public void testObserve() throws InterruptedException {
		
		String resourceUri = "/oscore/observe2";
		CoapClient client = new CoapClient();

		//Handler for Observe responses
		class ObserveHandler implements CoapHandler {
			int count = 1;
			int abort = 0;
			
			//Triggered when a Observe response is received
			@Override public void onLoad(CoapResponse response) {
				abort++;
				
				String content = response.getResponseText();
				System.out.println("NOTIFICATION: " + content);		
				
				//Check the incoming responses
				assertEquals(response.getCode(), ResponseCode.CONTENT);
				assertEquals(response.getOptions().getContentFormat(), MediaTypeRegistry.TEXT_PLAIN);
				
				if(count == 1) {
					assertEquals(response.getOptions().hasObserve(), true);
					assertEquals(response.getResponseText(), "one");
				} else if(count == 2) {
					assertEquals(response.getOptions().hasObserve(), true);
					assertEquals(response.getResponseText(), "two");
				}
				
				count++;
			}
		
			@Override public void onError() {
				System.err.println("Observing failed");
			}
		}

		ObserveHandler handler = new ObserveHandler();
		
		//Create request and initiate Observe relationship
		byte[] token = new byte[8];
		new Random().nextBytes(token);
		
		Request r = createClientRequest(Code.GET, resourceUri);
		r.setToken(token);
		r.setObserve();
		CoapObserveRelation relation = client.observe(r, handler);
	
		//Wait until 2 messages have been received
		while(handler.count <= 2) {
			Thread.sleep(250);
			
			//Failsafe to abort test if needed
			if(handler.abort > 5) {
				fail("Message limit reached, failing test");
				break;
			}
		}
		
		//Now cancel the Observe and wait for the final response
		r = createClientRequest(Code.GET, resourceUri);
		r.setToken(token);
		r.getOptions().setObserve(1); //Deregister Observe
		r.send();
		
		Response resp = r.waitForResponse(1000);
		
		assertEquals(resp.getCode(), ResponseCode.CONTENT);
		assertEquals(resp.getOptions().getContentFormat(), MediaTypeRegistry.TEXT_PLAIN);
		assertEquals(resp.getOptions().hasObserve(), false);
		assertEquals(resp.getPayloadString(), "two");
		assertEquals(relation.getCurrent().getResponseText(), "two");
	}
	
	/* --- End of client Observe tests --- */

	/**
	 * Set OSCORE context information for clients
	 */
	@Before
	public void setClientContext() {
		//Set up OSCORE context information for request (client)
		byte[] sid = new byte[0];
		byte[] rid = new byte[] { 0x01 };
	
		try {
			OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, master_salt, null);
			db.addContext("coap://" + serverAddress, ctx);
		}
		catch(OSException e) {
			System.err.println("Failed to set client OSCORE Context information!");
		}
	}
	
	/* Server related code below */
	
	/**
	 * (Re)sets the OSCORE context information for the server
	 */
	@Before
	public void setServerContext() {
		//Set up OSCORE context information for response (server)
		byte[] sid = new byte[] { 0x01 };
		byte[] rid = new byte[0];
		
		try {
			OSCoreCtx ctx_B = new OSCoreCtx(master_secret, false, alg, sid, rid, kdf, 32, master_salt, null);
	
			db.addContext("coap://" + clientAddress, ctx_B);
		}
		catch (OSException e) {
			System.err.println("Failed to set server OSCORE Context information!");
		}
	}
	
	/**
	 * Creates server with resources to test OSCORE Observe functionality
	 * @throws InterruptedException if resource update task fails
	 */
	@Before
	public void createServer() throws InterruptedException {
		//Do not create server if it is already running
		if(server != null) {
			return;
		}
		
		setServerContext();

		//Create server
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		
		InetAddress serverInetAddress = null;
		try {
			serverInetAddress = InetAddress.getByName(serverAddress);
		} catch (UnknownHostException e) {
			System.err.println("Failed to find server address!");
		}
		
		builder.setInetSocketAddress(new InetSocketAddress(serverInetAddress, 0));
		CoapEndpoint endpoint = builder.build();
		server = new CoapServer();
		server.addEndpoint(endpoint);

		/** --- Resources for Observe tests follow --- **/
		
		//Base resource for OSCORE Observe test resources
		OSCoreResource oscore = new OSCoreResource("oscore", true);
		
		//Second level base resource for OSCORE Observe test resources
		OSCoreResource oscore_hello = new OSCoreResource("hello", true);

		/**
		 * The resource for testing Observe support 
		 * 
		 * Responds with "one" for the first request and "two" for later updates.
		 *
		 */
		class ObserveResource extends CoapResource {
			
			public String value = "one";
			private boolean firstRequestReceived = false;

			public ObserveResource(String name, boolean visible) {
				super(name, visible);
				
				this.setObservable(true); 
				this.setObserveType(Type.NON);
				this.getAttributes().setObservable();
				
				Timer timer = new Timer();
				timer.schedule(new UpdateTask(), 0, 750);
			}

			@Override
			public void handleGET(CoapExchange exchange) {
				firstRequestReceived  = true;

				exchange.respond(value);
			}
			
			//Update the resource value when timer triggers (if 1st request is received)
			class UpdateTask extends TimerTask {
				@Override
				public void run() {
					if(firstRequestReceived) {
						value = "two";
						changed(); // notify all observers
					}
				}
			}
		}
		
		//observe2 resource for OSCORE Observe tests
		ObserveResource oscore_observe2 = new ObserveResource("observe2", true);
		
		//Creating resource hierarchy	
		oscore.add(oscore_hello);
		oscore.add(oscore_observe2);
		
		server.add(oscore);
		
		/** --- End of resources for Observe tests **/
		
		//Start server
		server.start();
		serverPort = endpoint.getAddress().getPort();
	}
}
