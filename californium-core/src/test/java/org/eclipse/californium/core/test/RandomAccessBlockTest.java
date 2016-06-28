package org.eclipse.californium.core.test;

import org.junit.Assert;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Medium.class)
public class RandomAccessBlockTest {

	public static String TARGET = "test";
	public static String RESPONSE_PAYLOAD = "123456789_123456789_123456789_1234567890";

	private InetSocketAddress serverAddress;
	private CoapServer server;

	@Before
	public void startupServer() throws Exception {
		System.out.println(System.lineSeparator() + "Start " + getClass().getSimpleName());
		CoapEndpoint endpoint = new CoapEndpoint(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
		server = new CoapServer();
		server.addEndpoint(endpoint);
		server.add(new TestResource(TARGET));
		server.start();
		serverAddress = endpoint.getAddress();
	}

	@After
	public void shutdownServer() {
		server.destroy();
		System.out.println("End " + getClass().getSimpleName());
	}

	@Test
	public void testServer() throws Exception {
		// We do not test for block 0 because the client is currently unable to
		// know if the user attempts to just retrieve block 0 or if he wants to
		// do early block negotiation with a specific size but actually wants to
		// retrieve all blocks.
		
		int[] blockOrder = {2,1,3};
		String[] expectations = {
				RESPONSE_PAYLOAD.substring(32 /* until the end */),
				RESPONSE_PAYLOAD.substring(16, 32),
				"" // block is out of bounds
		};

		String uri = String.format("coap://%s:%d/%s", serverAddress.getAddress().getHostAddress(), serverAddress.getPort(), TARGET);
		for (int i = 0; i < blockOrder.length; i++) {
			int num = blockOrder[i];
			System.out.println("Request block number " + num);

			int szx = BlockOption.size2Szx(16);
			Request request = Request.newGet();
			request.setURI(uri);
			request.getOptions().setBlock2(szx, false, num);

			Response response = request.send().waitForResponse(1000);
			Assert.assertNotNull("Client received no response", response);
			Assert.assertEquals(expectations[i], response.getPayloadString());
			Assert.assertTrue(response.getOptions().hasBlock2());
			Assert.assertEquals(num, response.getOptions().getBlock2().getNum());
			Assert.assertEquals(szx, response.getOptions().getBlock2().getSzx());
		}
	}

	private class TestResource extends CoapResource {

		public TestResource(String name) {
			super(name);
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			exchange.respond(RESPONSE_PAYLOAD);
		}
	}
}
