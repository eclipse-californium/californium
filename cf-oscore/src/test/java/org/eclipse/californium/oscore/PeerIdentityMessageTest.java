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
 * This test class is based on org.eclipse.californium.core.test.SmallServerClientTest
 *
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CoapNetworkRule for
 *                                                    setup of test-network
 *    Achim Kraus (Bosch Software Innovations GmbH) - destroy server after test
 *    Rikard Höglund (RISE SICS) - testing OSCORE peer identity
 ******************************************************************************/
package org.eclipse.californium.oscore;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import org.eclipse.californium.TestTools;
import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.auth.OSCorePeerIdentity;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * Tests setting and checking of OSCORE peer identity during communication.
 *
 */
@Category(Medium.class)
public class PeerIdentityMessageTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	private static String SERVER_RESPONSE = "server responds hi";

	private CoapServer server;

	private Endpoint serverEndpoint;

	//OSCORE context information shared between server and client
	//private final static HashMapCtxDB dbServer = new HashMapCtxDB();
	//private final static HashMapCtxDB dbClient = new HashMapCtxDB();
	private final static HashMapCtxDB db = HashMapCtxDB.getInstance();
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };

	@Before
	public void initLogger() {
		System.out.println(System.lineSeparator() + "Start " + getClass().getSimpleName());
		EndpointManager.clear();
	}

	//Use the OSCORE stack factory
	@BeforeClass
	public static void setStackFactory() {
		//OSCoreCoapStackFactory.useAsDefault(dbClient);
		OSCoreCoapStackFactory.useAsDefault();
	}

	@After
	public void after() {
		if (null != server) {
			server.destroy();
		}
		System.out.println("End " + getClass().getSimpleName());
	}

	/**
	 * Sends two requests and checks that an appropriate OSCORE peer identity has
	 * been set on the destination/source endpoint context for both request and response
	 * on both the server and client side.
	 *
	 * @throws Exception if message processing or creating the OSCORE context fails
	 */
	@Test
	public void testPeerIdentity() throws Exception {
		createSimpleServer();

		//Set up OSCORE context information for request (client)
		byte[] sid = new byte[0];
		byte[] rid = new byte[] { 0x01 };
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, null, null);
		db.addContext("coap://" + serverEndpoint.getAddress().getAddress().getHostAddress(), ctx);

		//Send request
		Request request = new Request(CoAP.Code.GET);
		request.getOptions().setOscore(Bytes.EMPTY); //Use OSCORE
		request.setDestinationContext(new AddressEndpointContext(serverEndpoint.getAddress()));
		request.send();
		System.out.println("client sent request");

		//Receive response and check its content
		Response response = request.waitForResponse(1000);
		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals(response.getPayloadString(), SERVER_RESPONSE);

		//Check response source context peer identity
		assertNotNull(response.getSourceContext());
		assertNotNull(response.getSourceContext().getPeerIdentity());
		assertEquals(response.getSourceContext().getPeerIdentity().getClass(), OSCorePeerIdentity.class); 
		OSCorePeerIdentity srcPeerIdentity = (OSCorePeerIdentity) response.getSourceContext().getPeerIdentity();
		assertArrayEquals(srcPeerIdentity.getContextId(), ctx.getIdContext());
		assertArrayEquals(srcPeerIdentity.getRecipientId(), ctx.getSenderId());
		assertArrayEquals(srcPeerIdentity.getSenderId(), ctx.getRecipientId());
		assertEquals(srcPeerIdentity.getHost(), ctx.getUri());

		//Check request destination context peer identity
		assertNotNull(request.getDestinationContext());
		assertNotNull(request.getDestinationContext().getPeerIdentity());
		assertEquals(request.getDestinationContext().getPeerIdentity().getClass(), OSCorePeerIdentity.class);
		OSCorePeerIdentity dstPeerIdentity = (OSCorePeerIdentity) request.getDestinationContext().getPeerIdentity();
		assertArrayEquals(dstPeerIdentity.getContextId(), ctx.getIdContext());
		assertArrayEquals(dstPeerIdentity.getRecipientId(), ctx.getSenderId());
		assertArrayEquals(dstPeerIdentity.getSenderId(), ctx.getRecipientId());
		assertEquals(dstPeerIdentity.getHost(), ctx.getUri());

		//Send second request
		//This makes sure the server did not fail any of its checks on the first request.
		request.send();
		System.out.println("client sent second request");

		//Receive response
		response = request.waitForResponse(1000);
		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals(response.getPayloadString(), SERVER_RESPONSE);
	}

	/**
	 * Creates a simple server for testing.
	 *
	 * It will check that an appropriate OSCORE peer identity has been set
	 * for the incoming request and the outgoing response.
	 *
	 * @throws OSException if creating the OSCORE context fails
	 *
	 */
	private void createSimpleServer() throws OSException {
		//Set up OSCORE context information for response (server)
		byte[] sid = new byte[] { 0x01 };
		byte[] rid = new byte[0];
		final OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sid, rid, kdf, 32, null, null);
		db.addContext("coap://" + TestTools.LOCALHOST_EPHEMERAL.getAddress().getHostName(), ctx);

		//Create server
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		//builder.setCustomCoapStackArgument(dbServer);
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		serverEndpoint = builder.build();
		server = new CoapServer();
		server.addEndpoint(serverEndpoint);
		server.setMessageDeliverer(new MessageDeliverer() {
			@Override
			public void deliverRequest(Exchange exchange) {
				System.out.println("server received request");

				//Check request source context peer identity
				assertNotNull(exchange.getRequest().getSourceContext());
				assertNotNull(exchange.getRequest().getSourceContext().getPeerIdentity());
				assertEquals(exchange.getRequest().getSourceContext().getPeerIdentity().getClass(), OSCorePeerIdentity.class);
				OSCorePeerIdentity srcPeerIdentity = (OSCorePeerIdentity) exchange.getRequest().getSourceContext().getPeerIdentity();
				assertArrayEquals(srcPeerIdentity.getContextId(), ctx.getIdContext());
				assertArrayEquals(srcPeerIdentity.getRecipientId(), ctx.getSenderId());
				assertArrayEquals(srcPeerIdentity.getSenderId(), ctx.getRecipientId());
				assertEquals(srcPeerIdentity.getHost(), ctx.getUri());

				//Prepare and send response
				Response response = new Response(ResponseCode.CONTENT);
				response.setPayload(SERVER_RESPONSE);
				exchange.sendResponse(response);

				//Check response destination context peer identity (destroy server if these checks fail)
				try {
					assertNotNull(response.getDestinationContext());
					assertNotNull(response.getDestinationContext().getPeerIdentity());
					assertEquals(response.getDestinationContext().getPeerIdentity().getClass(), OSCorePeerIdentity.class);
					OSCorePeerIdentity dstPeerIdentity = (OSCorePeerIdentity) response.getDestinationContext().getPeerIdentity();
					assertArrayEquals(dstPeerIdentity.getContextId(), ctx.getIdContext());
					assertArrayEquals(dstPeerIdentity.getRecipientId(), ctx.getSenderId());
					assertArrayEquals(dstPeerIdentity.getSenderId(), ctx.getRecipientId());
					assertEquals(dstPeerIdentity.getHost(), ctx.getUri());
				} catch (AssertionError e) {
					System.out.println("checking properties of outgoing response on server failed");
					System.out.println(e.getMessage());
					server.destroy();
				}

			}
			@Override
			public void deliverResponse(Exchange exchange, Response response) { }
		});
		server.start();
	}
}
