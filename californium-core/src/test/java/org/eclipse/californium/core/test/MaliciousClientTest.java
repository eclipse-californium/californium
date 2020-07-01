/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.OptionNumberRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.serialization.DataParser;
import org.eclipse.californium.core.network.serialization.DataSerializer;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.core.network.serialization.UdpDataSerializer;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class MaliciousClientTest {

	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	@ClassRule
	public static CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private static Endpoint serverEndpoint;
	private static Connector clientConnector;
	private static LinkedBlockingQueue<RawData> incoming = new LinkedBlockingQueue<RawData>();
	private static int mid = 1;

	@BeforeClass
	public static void startupServer() throws IOException {
		network.getStandardTestConfig().setLong(NetworkConfig.Keys.MAX_TRANSMIT_WAIT, 100);
		CoapServer server = createServer();
		cleanup.add(server);
		cleanup.add(clientConnector);
	}

	@After
	public void cleanup() throws IOException {
		incoming.clear();
	}

	@Test
	public void testConRequestWithTooLongUri() throws Exception {
		Request get = newGet();
		get.getOptions().addOtherOption(newOption(OptionNumberRegistry.URI_PATH, 256));

		DataSerializer serializer = new UdpDataSerializer();
		RawData rawData = serializer.serializeRequest(get);
		clientConnector.send(rawData);

		Response response = waitForResponse(1000);
		assertThat("expected response", response, is(notNullValue()));
		assertThat(response.getCode(), is(ResponseCode.BAD_OPTION));
	}

	@Test
	public void testNonRequestWithTooLongUri() throws Exception {
		Request get = newGet();
		get.setConfirmable(false);
		get.getOptions().addOtherOption(newOption(OptionNumberRegistry.URI_PATH, 256));

		DataSerializer serializer = new UdpDataSerializer();
		RawData rawData = serializer.serializeRequest(get);
		clientConnector.send(rawData);

		Message reject = waitForMessage(1000);
		assertThat("malicous NON not ignored", reject, is(nullValue()));
	}

	@Test
	public void testConResponseWithTooLongLocation() throws Exception {
		Response response = newResponse(ResponseCode.CONTENT);
		response.setConfirmable(true);
		response.getOptions().addOtherOption(newOption(OptionNumberRegistry.LOCATION_PATH, 256));

		DataSerializer serializer = new UdpDataSerializer();
		RawData rawData = serializer.serializeResponse(response);
		clientConnector.send(rawData);

		Message reject = waitForMessage(1000);
		assertThat("expected RST", reject, is(notNullValue()));
		assertThat(reject.getType(), is(Type.RST));
	}

	@Test
	public void testNonResponseWithTooLongLocation() throws Exception {
		Response response = newResponse(ResponseCode.CONTENT);
		response.setConfirmable(false);
		response.getOptions().addOtherOption(newOption(OptionNumberRegistry.LOCATION_PATH, 256));

		DataSerializer serializer = new UdpDataSerializer();
		RawData rawData = serializer.serializeResponse(response);
		clientConnector.send(rawData);

		Message reject = waitForMessage(1000);
		assertThat("malicous NON response not ignored", reject, is(nullValue()));
	}

	@Test
	public void testPiggyBackedResponseWithTooLongLocation() throws Exception {
		Response response = newResponse(ResponseCode.CONTENT);
		response.setType(Type.ACK);
		response.getOptions().addOtherOption(newOption(OptionNumberRegistry.LOCATION_PATH, 256));

		DataSerializer serializer = new UdpDataSerializer();
		RawData rawData = serializer.serializeResponse(response);
		clientConnector.send(rawData);

		Message reject = waitForMessage(1000);
		assertThat("malicous piggybacked response not ignored", reject, is(nullValue()));
	}

	private static Option newOption(int number, int length) {
		byte[] value = new byte[length];
		Arrays.fill(value, (byte) 'p');
		return new Option(number, value);
	}

	private static Response newResponse(ResponseCode code) {
		Response response = new Response(code);
		response.setDestinationContext(new AddressEndpointContext(serverEndpoint.getAddress()));
		response.setMID(mid++);
		response.setToken(Bytes.EMPTY);
		return response;
	}

	private static Request newGet() {
		String uri = TestTools.getUri(serverEndpoint, "");
		Request get = Request.newGet();
		get.setURI(uri);
		get.setMID(mid++);
		get.setToken(Bytes.EMPTY);
		return get;
	}

	private static Response waitForResponse(long timeoutMillis) throws InterruptedException {
		Message message = waitForMessage(timeoutMillis);
		if (message instanceof Response) {
			return (Response) message;
		} else {
			return null;
		}
	}

	private static Message waitForMessage(long timeoutMillis) throws InterruptedException {
		RawData data = incoming.poll(timeoutMillis, TimeUnit.MILLISECONDS);
		if (data != null) {
			DataParser parser = new UdpDataParser();
			return parser.parseMessage(data);
		} else {
			return null;
		}
	}

	private static CoapServer createServer() throws IOException {
		NetworkConfig config = network.getStandardTestConfig();
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setNetworkConfig(config);
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		serverEndpoint = builder.build();

		CoapServer server = new CoapServer(config);

		server.addEndpoint(serverEndpoint);
		server.start();

		clientConnector = new UDPConnector(TestTools.LOCALHOST_EPHEMERAL);
		clientConnector.setRawDataReceiver(new RawDataChannel() {

			@Override
			public void receiveData(RawData raw) {
				incoming.offer(raw);
			}
		});
		clientConnector.start();

		return server;
	}
}
