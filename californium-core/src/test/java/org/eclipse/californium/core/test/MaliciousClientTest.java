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

import static org.eclipse.californium.core.coap.TestOption.newOption;
import static org.eclipse.californium.elements.util.TestConditionTools.assertStatisticCounter;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.io.IOException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.CoAPOptionException;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.TestOption;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.interceptors.HealthStatisticLogger;
import org.eclipse.californium.core.network.serialization.DataParser;
import org.eclipse.californium.core.network.serialization.DataParserTest.CustomDataParser;
import org.eclipse.californium.core.network.serialization.DataParserTest.CustomUdpDataParser;
import org.eclipse.californium.core.network.serialization.DataSerializer;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.core.network.serialization.UdpDataSerializer;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.CounterStatisticManager;
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
	private static CounterStatisticManager healthStatistic;
	private static Connector clientConnector;
	private static CustomDataParser serverParser;
	private static LinkedBlockingQueue<RawData> incoming = new LinkedBlockingQueue<RawData>();
	private static int mid = 1;

	@BeforeClass
	public static void startupServer() throws IOException {
		CoapServer server = createServer();
		cleanup.add(server);
		cleanup.add(clientConnector);
	}

	@After
	public void cleanup() throws IOException {
		serverParser.setIgnoreOptionError(false);
		serverParser.setOptionException(null);
		incoming.clear();
		healthStatistic.reset();
	}

	/**
	 * Malformed CON request.
	 * 
	 * Standard processing, responds with BAD_OPTION.
	 * 
	 * @throws Exception if an error occurs
	 */
	@Test
	public void testConRequestWithTooLongUri() throws Exception {
		Request get = newGet();
		get.getOptions().addOtherOption(newOption(StandardOptionRegistry.URI_PATH, 256));

		DataSerializer serializer = new UdpDataSerializer();
		RawData rawData = serializer.serializeRequest(get);
		clientConnector.send(rawData);

		assertStatisticCounter(healthStatistic, "recv-malformed", is(1L), 1000, TimeUnit.MILLISECONDS);
		Response response = waitForResponse(1000);
		assertThat("expected response", response, is(notNullValue()));
		assertThat(response.getCode(), is(ResponseCode.BAD_OPTION));
	}

	/**
	 * Malformed CON request.
	 * 
	 * Ignore malformed option, responds with CONTENT.
	 * 
	 * @throws Exception if an error occurs
	 */
	@Test
	public void testConRequestWithTooLongUriIgnored() throws Exception {
		serverParser.setIgnoreOptionError(true);
		Request get = newGet();
		get.getOptions().addOtherOption(newOption(StandardOptionRegistry.URI_PATH, 256));

		DataSerializer serializer = new UdpDataSerializer();
		RawData rawData = serializer.serializeRequest(get);
		clientConnector.send(rawData);

		Response response = waitForResponse(1000);
		assertThat("expected response", response, is(notNullValue()));
		assertThat(response.getCode(), is(ResponseCode.CONTENT));
		assertStatisticCounter(healthStatistic, "recv-malformed", is(0L));
	}

	/**
	 * Malformed CON request.
	 * 
	 * Response with custom response code.
	 * 
	 * @throws Exception if an error occurs
	 */
	@Test
	public void testConRequestWithTooLongUriNotFound() throws Exception {
		serverParser.setOptionException(new CoAPOptionException("too long uri", ResponseCode.NOT_FOUND));
		Request get = newGet();
		get.getOptions().addOtherOption(newOption(StandardOptionRegistry.URI_PATH, 256));

		DataSerializer serializer = new UdpDataSerializer();
		RawData rawData = serializer.serializeRequest(get);
		clientConnector.send(rawData);

		assertStatisticCounter(healthStatistic, "recv-malformed", is(1L), 1000, TimeUnit.MILLISECONDS);
		Response response = waitForResponse(1000);
		assertThat("expected response", response, is(notNullValue()));
		assertThat(response.getCode(), is(ResponseCode.NOT_FOUND));
	}

	/**
	 * Malformed CON request.
	 * 
	 * Reject request.
	 * 
	 * @throws Exception if an error occurs
	 */
	@Test
	public void testConRequestWithTooLongUriRejected() throws Exception {
		serverParser.setOptionException(new CoAPOptionException("too long uri, reject", null));
		Request get = newGet();
		get.getOptions().addOtherOption(newOption(StandardOptionRegistry.URI_PATH, 256));

		DataSerializer serializer = new UdpDataSerializer();
		RawData rawData = serializer.serializeRequest(get);
		clientConnector.send(rawData);

		assertStatisticCounter(healthStatistic, "recv-malformed", is(1L), 1000, TimeUnit.MILLISECONDS);
		Message reject = waitForMessage(1000);
		assertThat("expected reject", reject, is(notNullValue()));
		assertThat(reject.getType(), is(Type.RST));
	}

	/**
	 * Malformed NON request.
	 * 
	 * Standard processing, ignored.
	 * 
	 * @throws Exception if an error occurs
	 */
	@Test
	public void testNonRequestWithTooLongUri() throws Exception {
		Request get = newGet();
		get.setConfirmable(false);
		get.getOptions().addOtherOption(newOption(StandardOptionRegistry.URI_PATH, 256));

		DataSerializer serializer = new UdpDataSerializer();
		RawData rawData = serializer.serializeRequest(get);
		clientConnector.send(rawData);

		assertStatisticCounter(healthStatistic, "recv-malformed", is(1L), 1000, TimeUnit.MILLISECONDS);
		Message reject = waitForMessage(1000);
		assertThat("malicous NON not ignored", reject, is(nullValue()));
	}

	/**
	 * Malformed NON request.
	 * 
	 * Ignore malformed option, responds with CONTENT.
	 * 
	 * @throws Exception if an error occurs
	 */
	@Test
	public void testNonRequestWithTooLongUriIgnored() throws Exception {
		serverParser.setIgnoreOptionError(true);
		Request get = newGet();
		get.setConfirmable(false);
		get.getOptions().addOtherOption(newOption(StandardOptionRegistry.URI_PATH, 256));

		DataSerializer serializer = new UdpDataSerializer();
		RawData rawData = serializer.serializeRequest(get);
		clientConnector.send(rawData);

		Response response = waitForResponse(1000);
		assertThat("expected response", response, is(notNullValue()));
		assertThat(response.getCode(), is(ResponseCode.CONTENT));
		assertStatisticCounter(healthStatistic, "recv-malformed", is(0L));
	}

	/**
	 * Malformed NON request.
	 * 
	 * Custom error code, but NON is ignored anyway.
	 * 
	 * @throws Exception if an error occurs
	 */
	@Test
	public void testNonRequestWithTooLongUriNotFoundDiscarded() throws Exception {
		serverParser.setOptionException(new CoAPOptionException("too long uri", ResponseCode.NOT_FOUND));
		Request get = newGet();
		get.setConfirmable(false);
		get.getOptions().addOtherOption(newOption(StandardOptionRegistry.URI_PATH, 256));

		DataSerializer serializer = new UdpDataSerializer();
		RawData rawData = serializer.serializeRequest(get);
		clientConnector.send(rawData);

		assertStatisticCounter(healthStatistic, "recv-malformed", is(1L), 1000, TimeUnit.MILLISECONDS);
		Message reject = waitForMessage(1000);
		assertThat("malicous NON not ignored", reject, is(nullValue()));
	}

	/**
	 * Malformed NON request.
	 * 
	 * Reject, but NON is ignored anyway.
	 * 
	 * @throws Exception if an error occurs
	 */
	@Test
	public void testNonRequestWithTooLongUriRejectDiscarded() throws Exception {
		serverParser.setOptionException(new CoAPOptionException("too long uri", null));
		Request get = newGet();
		get.setConfirmable(false);
		get.getOptions().addOtherOption(newOption(StandardOptionRegistry.URI_PATH, 256));

		DataSerializer serializer = new UdpDataSerializer();
		RawData rawData = serializer.serializeRequest(get);
		clientConnector.send(rawData);

		assertStatisticCounter(healthStatistic, "recv-malformed", is(1L), 1000, TimeUnit.MILLISECONDS);
		Message reject = waitForMessage(1000);
		assertThat("malicous NON not ignored", reject, is(nullValue()));
	}


	/**
	 * BERT request with UDP (malformed request).
	 * 
	 * Standard processing, responds with BAD_REQUEST.
	 * 
	 * @throws Exception if an error occurs
	 */
	@Test
	public void testBertRequest() throws Exception {
		BlockOption block = new BlockOption(BlockOption.BERT_SZX, false, 0);
		Request get = newGet();
		get.setConfirmable(true);
		get.getOptions().setBlock2(block);
		DataSerializer serializer = new TestOption.TestDataSerializer();
		RawData rawData = serializer.serializeRequest(get);
		clientConnector.send(rawData);

		assertStatisticCounter(healthStatistic, "recv-malformed", is(1L), 1000, TimeUnit.MILLISECONDS);
		Response response = waitForResponse(1000);
		assertThat("Response missing", response, is(notNullValue()));
		assertThat("No BAD_REREQUEST response", response.getCode(), is(ResponseCode.BAD_REQUEST));
	}

	/**
	 * Malformed CON response.
	 * 
	 * Standard processing, reject.
	 * 
	 * @throws Exception if an error occurs
	 */
	@Test
	public void testConResponseWithTooLongLocation() throws Exception {
		Response response = newResponse(ResponseCode.CONTENT);
		response.setConfirmable(true);
		response.getOptions().addOtherOption(newOption(StandardOptionRegistry.LOCATION_PATH, 256));

		DataSerializer serializer = new UdpDataSerializer();
		RawData rawData = serializer.serializeResponse(response);
		clientConnector.send(rawData);

		assertStatisticCounter(healthStatistic, "recv-malformed", is(1L), 1000, TimeUnit.MILLISECONDS);
		Message reject = waitForMessage(1000);
		assertThat("expected RST", reject, is(notNullValue()));
		assertThat(reject.getType(), is(Type.RST));
	}

	/**
	 * Malformed NON response.
	 * 
	 * Standard processing, ignore.
	 * 
	 * @throws Exception if an error occurs
	 */
	@Test
	public void testNonResponseWithTooLongLocation() throws Exception {
		Response response = newResponse(ResponseCode.CONTENT);
		response.setConfirmable(false);
		response.getOptions().addOtherOption(newOption(StandardOptionRegistry.LOCATION_PATH, 256));

		DataSerializer serializer = new UdpDataSerializer();
		RawData rawData = serializer.serializeResponse(response);
		clientConnector.send(rawData);

		assertStatisticCounter(healthStatistic, "recv-malformed", is(1L), 1000, TimeUnit.MILLISECONDS);
		Message reject = waitForMessage(1000);
		assertThat("malicous NON response not ignored", reject, is(nullValue()));
	}

	/**
	 * Malformed piggy-backed response.
	 * 
	 * Standard processing, ignore.
	 * 
	 * @throws Exception if an error occurs
	 */
	@Test
	public void testPiggyBackedResponseWithTooLongLocation() throws Exception {
		Response response = newResponse(ResponseCode.CONTENT);
		response.setType(Type.ACK);
		response.getOptions().addOtherOption(newOption(StandardOptionRegistry.LOCATION_PATH, 256));

		DataSerializer serializer = new UdpDataSerializer();
		RawData rawData = serializer.serializeResponse(response);
		clientConnector.send(rawData);

		assertStatisticCounter(healthStatistic, "recv-malformed", is(1L), 1000, TimeUnit.MILLISECONDS);
		Message reject = waitForMessage(1000);
		assertThat("malicous piggybacked response not ignored", reject, is(nullValue()));
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
		Configuration config = network.getStandardTestConfig();

		CustomUdpDataParser parser = new CustomUdpDataParser(true);
		serverParser = parser;

		
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConfiguration(config);
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		builder.setDataSerializerAndParser(new UdpDataSerializer(), parser);
		serverEndpoint = builder.build();

		HealthStatisticLogger health = new HealthStatisticLogger("server", true);
		healthStatistic = health;
		serverEndpoint.addPostProcessInterceptor(health);

		CoapServer server = new CoapServer(config);


		server.addEndpoint(serverEndpoint);
		server.start();

		clientConnector = new UDPConnector(TestTools.LOCALHOST_EPHEMERAL, config);
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
