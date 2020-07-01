/*******************************************************************************
 * Copyright (c) 2015, 2019 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Rikard Höglund (RISE SICS) - testing OSCORE info in endpoint context
 ******************************************************************************/
package org.eclipse.californium.oscore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.cose.AlgorithmID;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Tests setting and checking of OSCORE information in the source/destination
 * endpoint context during communication.
 *
 */
@Category(Medium.class)
public class EndpointContextInfoTest {

	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	private static String SERVER_RESPONSE = "server responds hi";

	private CoapServer server;

	private Endpoint serverEndpoint;

	// OSCORE context information for server and client
	private final static HashMapCtxDB dbServer = new HashMapCtxDB();
	private final static HashMapCtxDB dbClient = new HashMapCtxDB();
	private final static AlgorithmID alg = AlgorithmID.AES_CCM_16_64_128;
	private final static AlgorithmID kdf = AlgorithmID.HKDF_HMAC_SHA_256;
	private final static byte[] master_secret = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
			0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
	private final static byte[] context_id = { 0x74, 0x65, 0x73, 0x74 };

	// Keys used in the endpoint context map of strings
	private final static String OSCORE_SENDER_ID = OSCoreEndpointContextInfo.OSCORE_SENDER_ID;
	private final static String OSCORE_RECIPIENT_ID = OSCoreEndpointContextInfo.OSCORE_RECIPIENT_ID;
	private final static String OSCORE_CONTEXT_ID = OSCoreEndpointContextInfo.OSCORE_CONTEXT_ID;
	private final static String OSCORE_URI = OSCoreEndpointContextInfo.OSCORE_URI;

	@Before
	public void initLogger() {
		System.out.println(System.lineSeparator() + "Start " + getClass().getSimpleName());
		EndpointManager.clear();
	}

	// Use the OSCORE stack factory
	@BeforeClass
	public static void setStackFactory() {
		OSCoreCoapStackFactory.useAsDefault(dbClient);
	}

	@After
	public void after() {
		if (null != server) {
			server.destroy();
		}
		System.out.println("End " + getClass().getSimpleName());
	}

	/**
	 * Sends two requests and checks that appropriate OSCORE information has
	 * been set in the following: Server: Request source context & Response
	 * destination context Client: Response source context
	 *
	 * @throws Exception if message processing or creating the OSCORE context
	 *             fails
	 */
	@Test
	public void testEndpointContextInfo() throws Exception {
		createSimpleServer();

		// Set up OSCORE context information for request (client)
		byte[] sidClient = new byte[] { 0x77, 0x66, 0x55, 0x44 };
		byte[] ridClient = new byte[] { 0x01, 0x02, 0x03, 0x04 };
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sidClient, ridClient, kdf, 32, null, context_id);
		String serverUri = serverEndpoint.getUri().toASCIIString();
		dbClient.addContext(serverUri, ctx);

		// Create string versions of rid, sid and context ID for client
		String sidClientString = StringUtil.byteArray2Hex(sidClient);
		String ridClientString = StringUtil.byteArray2Hex(ridClient);
		String contextIdString = StringUtil.byteArray2Hex(context_id);

		String ctxUri = ctx.getUri();
		assertNotNull(ctxUri);

		// Send request
		Request request = new Request(CoAP.Code.GET);
		request.getOptions().setOscore(Bytes.EMPTY); // Use OSCORE
		request.setURI(serverUri);
		request.send();
		System.out.println("client sent request");

		// Check original request destination context after transmission
		// This is a special case as it should be handled using a callback,
		// see testEndpointContextInfoSendingRequest
		assertNull(request.getSourceContext());
		EndpointContext requestDestinationContext = request.getDestinationContext();
		System.out.println("Client: Request destination context type: " + requestDestinationContext.getClass());
		assertNull(requestDestinationContext.get(OSCORE_URI));

		// Receive response and check its content
		Response response = request.waitForResponse(1000);
		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals(response.getPayloadString(), SERVER_RESPONSE);

		// Check response source context after reception
		assertNull(response.getDestinationContext());
		EndpointContext responseSourceContext = response.getSourceContext();

		System.out.println("Client: Response source context type: " + responseSourceContext.getClass());
		assertNotNull(responseSourceContext);

		assertEquals(sidClientString, responseSourceContext.get(OSCORE_SENDER_ID));
		assertEquals(ridClientString, responseSourceContext.get(OSCORE_RECIPIENT_ID));
		assertEquals(contextIdString, responseSourceContext.get(OSCORE_CONTEXT_ID));
		assertEquals(ctxUri, responseSourceContext.get(OSCORE_URI));

		// Send second request
		// This makes sure the server did not fail any of its checks on the
		// first request.
		request.send();
		System.out.println("client sent second request");

		// Receive response
		response = request.waitForResponse(1000);
		assertNotNull("Client received no response", response);
		System.out.println("client received response");
		assertEquals(response.getPayloadString(), SERVER_RESPONSE);
	}

	/**
	 * Sends one request and checks that appropriate OSCORE information has been
	 * set in the following: Client: Request destination context
	 *
	 * Special case as this is handled via a callback using
	 * MessageObserver.onContextEstablished(EndpointContext).
	 *
	 * @throws Exception if message processing or creating the OSCORE context
	 *             fails
	 */
	@Test
	public void testEndpointContextInfoSendingRequest() throws Exception {
		createSimpleServer();

		// Set up OSCORE context information for request (client)
		byte[] sidClient = new byte[] { 0x77, 0x66, 0x55, 0x44 };
		byte[] ridClient = new byte[] { 0x01, 0x02, 0x03, 0x04 };
		OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sidClient, ridClient, kdf, 32, null, context_id);
		String serverUri = serverEndpoint.getUri().toASCIIString();
		dbClient.addContext(serverUri, ctx);

		// Create string versions of rid, sid and context ID for client
		String sidClientString = StringUtil.byteArray2Hex(sidClient);
		String ridClientString = StringUtil.byteArray2Hex(ridClient);
		String contextIdString = StringUtil.byteArray2Hex(context_id);
		String ctxUri = ctx.getUri();

		// Create request
		Request request = new Request(CoAP.Code.GET);
		request.getOptions().setOscore(Bytes.EMPTY); // Use OSCORE
		request.setURI(serverUri);

		// Add message observer to request. It will function as a callback
		// when the new endpoint context has been established for the request.
		CheckContextObserver checkContextObserver = new CheckContextObserver(sidClientString, ridClientString,
				contextIdString, ctxUri);
		request.addMessageObserver(checkContextObserver);

		// Send the request
		request.send();
		System.out.println("client sent request");

		// Receive response and check its content
		Response response = request.waitForResponse(1000);
		System.out.println("client received response");
		assertEquals(response.getPayloadString(), SERVER_RESPONSE);

		// Control if checks in the message observer passed
		assertEquals("passed", checkContextObserver.getStatus());
		assertTrue(checkContextObserver.isPassed());
	}

	/**
	 * Message observer that will implement the onContextEstablished method to
	 * receive the new endpoint context created after a request has been sent.
	 *
	 * On construction this class takes parameters to compare the new endpoint
	 * context with.
	 *
	 */
	private static class CheckContextObserver extends MessageObserverAdapter {

		private String sidString;
		private String ridString;
		private String contextIdString;
		private String ctxUri;
		private boolean passed = true;
		private String status = "passed";

		/**
		 * Constructor taking parameters the established endpoint context will
		 * be compared to.
		 *
		 * @param sidString OSCORE Sender ID this endpoint context should
		 *            contain
		 * @param ridString OSCORE Recipient ID this endpoint context should
		 *            contain
		 * @param contextIdString OSCORE Context ID this endpoint context should
		 *            contain
		 * @param ctxUri OSCORE URI this endpoint context should contain
		 */
		public CheckContextObserver(String sidString, String ridString, String contextIdString, String ctxUri) {
			this.sidString = sidString;
			this.ridString = ridString;
			this.contextIdString = contextIdString;
			this.ctxUri = ctxUri;
		}

		/**
		 * Method that will be called when a endpoint context has been
		 * established for a request that has been sent.
		 *
		 * Will check if the endpoint context matches the expected parameters.
		 *
		 * @param endpointContext the newly established endpoint context
		 */
		@Override
		public void onContextEstablished(EndpointContext endpointContext) {
			System.out.println("Client: Request endpoint context type: " + endpointContext.getClass());

			try {
				assertNotNull(endpointContext);

				assertEquals(sidString, endpointContext.get(OSCORE_SENDER_ID));
				assertEquals(ridString, endpointContext.get(OSCORE_RECIPIENT_ID));
				assertEquals(contextIdString, endpointContext.get(OSCORE_CONTEXT_ID));
				assertEquals(ctxUri, endpointContext.get(OSCORE_URI));
			} catch (AssertionError e) {
				System.err.println(e.getMessage());
				status = e.getMessage();
				passed = false;
			}

		}

		/**
		 * @return the passed
		 */
		public boolean isPassed() {
			return passed;
		}

		/**
		 * @return the status
		 */
		public String getStatus() {
			return status;
		}

	}

	/**
	 * Creates a simple server for testing.
	 *
	 * It will check that appropriate OSCORE information has been set for the
	 * incoming request and the outgoing response.
	 *
	 * @throws OSException if creating the OSCORE context fails
	 *
	 */
	private void createSimpleServer() throws OSException {
		// Set up OSCORE context information for response (server)
		byte[] sidServer = new byte[] { 0x01, 0x02, 0x03, 0x04 };
		byte[] ridServer = new byte[] { 0x77, 0x66, 0x55, 0x44 };
		final OSCoreCtx ctx = new OSCoreCtx(master_secret, true, alg, sidServer, ridServer, kdf, 32, null, context_id);
		String clientUri = "coap://" + TestTools.LOCALHOST_EPHEMERAL.getAddress().getHostAddress();
		dbServer.addContext(clientUri, ctx);

		// Create string versions of rid, sid and context ID for server
		final String sidServerString = StringUtil.byteArray2Hex(sidServer);
		final String ridServerString = StringUtil.byteArray2Hex(ridServer);
		final String contextIdString = StringUtil.byteArray2Hex(context_id);

		final String ctxUri = ctx.getUri();
		assertNotNull(ctxUri);

		// Create server
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setCustomCoapStackArgument(dbServer);
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		serverEndpoint = builder.build();
		server = new CoapServer();
		server.addEndpoint(serverEndpoint);
		server.setMessageDeliverer(new MessageDeliverer() {

			@Override
			public void deliverRequest(Exchange exchange) {
				System.out.println("server received request");

				// Check request source context after reception
				assertNull(exchange.getRequest().getDestinationContext());
				EndpointContext requestSourceContext = exchange.getRequest().getSourceContext();

				System.out.println("Server: Request source context type: " + requestSourceContext.getClass());
				assertNotNull(requestSourceContext);

				assertEquals(sidServerString, requestSourceContext.get(OSCORE_SENDER_ID));
				assertEquals(ridServerString, requestSourceContext.get(OSCORE_RECIPIENT_ID));
				assertEquals(contextIdString, requestSourceContext.get(OSCORE_CONTEXT_ID));
				assertEquals(ctxUri, requestSourceContext.get(OSCORE_URI));

				// Prepare and send response
				Response response = new Response(ResponseCode.CONTENT);
				response.setPayload(SERVER_RESPONSE);
				exchange.sendResponse(response);

				// Check response destination context after transmission
				try {
					assertNull(response.getSourceContext());
					EndpointContext responseDestinationContext = response.getDestinationContext();

					System.out.println(
							"Server: Response destination context type: " + responseDestinationContext.getClass());
					assertNotNull(responseDestinationContext);

					assertEquals(sidServerString, responseDestinationContext.get(OSCORE_SENDER_ID));
					assertEquals(ridServerString, responseDestinationContext.get(OSCORE_RECIPIENT_ID));
					assertEquals(contextIdString, responseDestinationContext.get(OSCORE_CONTEXT_ID));
					assertEquals(ctxUri, responseDestinationContext.get(OSCORE_URI));
				} catch (AssertionError e) {
					String error = "Error: Server failed asserts: " + e.getMessage();
					System.err.println(error);
					SERVER_RESPONSE = error;
				}

			}

			@Override
			public void deliverResponse(Exchange exchange, Response response) {
			}
		});
		server.start();
	}
}
