/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.eclipse.californium.TestTools.generateRandomPayload;
import static org.eclipse.californium.TestTools.getUri;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.util.Arrays;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

@Category(Medium.class)
@RunWith(Parameterized.class)
public class RandomAccessBlockTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);
	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();
	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static final String TARGET = "test";
	private static final String RESP_PAYLOAD = generateRandomPayload(87);

	@Parameter
	public int maxBodySize;
	private Endpoint clientEndpoint;
	private Endpoint serverEndpoint;

	@Parameters(name = "MAX_RESOURCE_BODY_SIZE = {0}")
	public static Iterable<Integer> maxBodySizeParams() {
		return Arrays.asList(2048, 0);
	}

	@Before
	public void startupServer() throws Exception {
		NetworkConfig config = network.getStandardTestConfig()
			.setInt(Keys.PREFERRED_BLOCK_SIZE, 16)
			.setInt(Keys.MAX_MESSAGE_SIZE, 32)
			.setInt(Keys.MAX_RESOURCE_BODY_SIZE, maxBodySize);

		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		builder.setNetworkConfig(config);

		serverEndpoint = builder.build();
		CoapServer server = new CoapServer(config);
		cleanup.add(server);
		server.addEndpoint(serverEndpoint);
		server.add(new BlockwiseResource(TARGET, RESP_PAYLOAD));
		server.start();

		builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		builder.setNetworkConfig(config);

		clientEndpoint = builder.build();
		cleanup.add(clientEndpoint);
	}

	@Test
	public void testServerReturnsBadOptionForNonExistingBlock() throws Exception {

		int szx = BlockOption.size2Szx(16);
		Request request = Request.newGet();
		request.setURI(getUri(serverEndpoint, TARGET));
		request.getOptions().setBlock2(szx, false, 6); // 6 * 16 = 96 is out of bounds

		Response response = request.send().waitForResponse(1000);
		assertThat("Client received no response", response, is(notNullValue()));
		assertThat(response.getCode(), is(ResponseCode.BAD_OPTION));
	}

	@Test
	public void testServerReturnsIndividualBlocks() throws Exception {
		// We do not test for block 0 because the client is currently unable to
		// know if the user attempts to just retrieve block 0 or if he wants to
		// do early block negotiation with a specific size but actually wants to
		// retrieve all blocks.

		int[] blockOrder = {2,1,5,3};
		String[] expectations = {
				RESP_PAYLOAD.substring(32, 48),
				RESP_PAYLOAD.substring(16, 32),
				RESP_PAYLOAD.substring(80 /* until the end */),
				RESP_PAYLOAD.substring(48, 64)
		};

		String uri = getUri(serverEndpoint, TARGET);
		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);
		client.setTimeout(1000L);

		for (int i = 0; i < blockOrder.length; i++) {
			int num = blockOrder[i];

			int szx = BlockOption.size2Szx(16);
			Request request = Request.newGet();
			request.setURI(uri);
			request.getOptions().setBlock2(szx, false, num);

			CoapResponse response = client.advanced(request);
			assertNotNull("Client received no response", response);
			assertThat(response.getCode(), is(ResponseCode.CONTENT));
			assertThat(response.getResponseText(), is(expectations[i]));
			assertTrue(response.getOptions().hasBlock2());
			assertThat(response.getOptions().getBlock2().getOffset(), is(num * 16));
			assertThat(response.getOptions().getBlock2().getSzx(), is(szx));
		}
		client.shutdown();
	}

	@Test
	public void testServerReturnsSmallerIndividualBlocks() throws Exception {

		int[] blockOrder = {2,1};
		int blocksize = 32;
		int expectedBlocksize = 16;
		String[] expectations = {
				RESP_PAYLOAD.substring(64, 80),
				RESP_PAYLOAD.substring(32, 48)
		};

		if (maxBodySize == 0) {
			expectedBlocksize = blocksize;
			expectations = new String[] {
					RESP_PAYLOAD.substring(64),
					RESP_PAYLOAD.substring(32, 64)
			};
		}

		String uri = getUri(serverEndpoint, TARGET);
		CoapClient client = new CoapClient();
		client.setEndpoint(clientEndpoint);
		client.setTimeout(1000L);

		for (int i = 0; i < blockOrder.length; i++) {
			int num = blockOrder[i];

			// 32 is larger than the server's preference 16
			// server will respond with smaller blockSxz
			// https://mailarchive.ietf.org/arch/browse/core/?gbt=1&index=fYy61XmXaaDvu2sk_6hg4aP83Yw
			int szx = BlockOption.size2Szx(blocksize);
			Request request = Request.newGet();
			request.setURI(uri);
			request.getOptions().setBlock2(szx, false, num);

			CoapResponse response = client.advanced(request);
			assertNotNull("Client received no response", response);
			assertThat(response.getCode(), is(ResponseCode.CONTENT));
			assertThat(response.getResponseText(), is(expectations[i]));
			assertTrue(response.getOptions().hasBlock2());
			assertThat(response.getOptions().getBlock2().getOffset(), is(num * blocksize));
			assertThat(response.getOptions().getBlock2().getSize(), is(expectedBlocksize));
		}
		client.shutdown();
	}

	private static class BlockwiseResource extends CoapResource {

		private ByteBuffer buf;
		private String responsePayload;
		/**
		 * @param name
		 */
		private BlockwiseResource(String name, String responsePayload) {
			super(name);
			this.responsePayload = responsePayload;
			buf = ByteBuffer.wrap(responsePayload.getBytes(CoAP.UTF8_CHARSET));
		}

		@Override
		public void handleGET(final CoapExchange exchange) {

			BlockOption block2 = exchange.getRequestOptions().getBlock2();
			Response response = null;

			if (block2 != null) {

				int offset = block2.getOffset();
				int to = Math.min(offset + block2.getSize(), buf.capacity());
				int length = to - offset;

				if (offset < buf.capacity() && length > 0) {
					byte[] payload = new byte[length];
					((Buffer)buf).position(offset);
					buf.get(payload, 0, length);
					response = new Response(ResponseCode.CONTENT);
					response.setPayload(payload);
				} else {
					response = new Response(ResponseCode.BAD_OPTION);
				}
				response.getOptions().setBlock2(block2);
				exchange.respond(response);

			} else {
				exchange.respond(responsePayload);
			}
		}
	}
}
