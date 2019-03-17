/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.integration.test;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.eclipse.californium.category.Large;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointContextMatcherFactory.MatcherMode;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.examples.NatUtil;
import org.eclipse.californium.integration.test.util.CoapsNetworkRule;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.ConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.DebugConnectionStore;
import org.eclipse.californium.scandium.dtls.ResumptionSupportingConnectionStore;
import org.eclipse.californium.scandium.dtls.SingleNodeConnectionIdGenerator;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Large.class)
public class SecureNatTest {

	@ClassRule
	public static CoapsNetworkRule network = new CoapsNetworkRule(CoapsNetworkRule.Mode.DIRECT,
			CoapsNetworkRule.Mode.NATIVE);

	static final long RESPONSE_TIMEOUT = 10000L;
	static final int NUM_OF_CLIENTS = 20;
	static final int NUM_OF_LOOPS = 50;

	static final String TARGET = "resource";
	static final String IDENITITY = "client1";
	static final String KEY = "key1";

	private NatUtil nat;
	private DebugConnectionStore connections;
	private CoapServer server;
	private TestUtilPskStore pskStore;
	private NetworkConfig config;
	private DTLSConnector serverConnector;
	private CoapEndpoint serverEndpoint;
	private CoapEndpoint clientEndpoint;
	private List<CoapEndpoint> clientEndpoints = new ArrayList<>();
	private MyResource resource;

	private String uri;

	@Before
	public void startupServer() {
		pskStore = new TestUtilPskStore(IDENITITY, KEY.getBytes());
		System.out.println(System.lineSeparator() + "Start " + getClass().getSimpleName());
	}

	@After
	public void shutdownServer() {
		if (nat != null) {
			nat.stop();
		}
		server.destroy();
		EndpointManager.reset();
		for (CoapEndpoint endpoint : clientEndpoints) {
			endpoint.destroy();
		}
		System.out.println("End " + getClass().getSimpleName());
	}

	@Test
	public void testSecureGet() throws Exception {

		createSecureServer(MatcherMode.STRICT, null);
		createNat();

		CoapClient client = new CoapClient(uri);
		CoapResponse coapResponse = client.get();

		assertNotNull("Response not received", coapResponse);

		nat.reassignNewLocalAddresses();

		coapResponse = client.get();

		assertThat("Response still received", coapResponse, is(nullValue()));
	}

	@Test
	public void testSecureGetWithCID() throws Exception {

		createSecureServer(MatcherMode.STRICT, new SingleNodeConnectionIdGenerator(4));
		createNat();

		CoapClient client = new CoapClient(uri);
		CoapResponse coapResponse = client.get();

		assertNotNull("Response not received", coapResponse);

		nat.reassignNewLocalAddresses();

		coapResponse = client.get();

		assertNotNull("Response not received", coapResponse);
	}

	@Test
	public void testMultipleSecureGetWithCID() throws Exception {
		createSecureServer(MatcherMode.STRICT, new SingleNodeConnectionIdGenerator(4));
		createNat();

		CoapClient client = new CoapClient(uri);
		CoapResponse coapResponse = client.get();

		assertNotNull("Response not received", coapResponse);

		for (int count = 0; count < NUM_OF_CLIENTS; ++count) {
			createClientEndpoint(MatcherMode.STRICT, new SingleNodeConnectionIdGenerator(4));
		}
		testMultipleSecureGet(0, 0, null);

		for (int count = 1; count < NUM_OF_LOOPS; ++count) {
			nat.reassignNewLocalAddresses();

			coapResponse = client.get();
			assertNotNull("Response not received", coapResponse);
			testMultipleSecureGet(count, 0, null);
		}
	}

	@Test
	public void testMultipleSecureGetWithCIDAndResumption() throws Exception {
		createSecureServer(MatcherMode.STRICT, new SingleNodeConnectionIdGenerator(4));
		createNat();

		int overallResumes = 0;
		List<Integer> resumeEndpoints = new ArrayList<>();

		CoapClient client = new CoapClient(uri);
		CoapResponse coapResponse = client.get();

		assertNotNull("Response not received", coapResponse);

		for (int count = 0; count < NUM_OF_CLIENTS; ++count) {
			createClientEndpoint(MatcherMode.STRICT, new SingleNodeConnectionIdGenerator(4));
		}
		testMultipleSecureGet(0, overallResumes, resumeEndpoints);

		for (int count = 1; count < NUM_OF_LOOPS; ++count) {
			nat.reassignNewLocalAddresses();

			coapResponse = client.get();
			assertNotNull("Response not received", coapResponse);
			testMultipleSecureGet(count, overallResumes, resumeEndpoints);
			forceResumption(resumeEndpoints);
			overallResumes += resumeEndpoints.size();
		}
	}

	@Test
	public void testSecureGetWithMixedAddressesAndCID() throws Exception {
		createSecureServer(MatcherMode.STRICT, new SingleNodeConnectionIdGenerator(4));
		createNat();

		CoapClient client = new CoapClient(uri);
		CoapResponse coapResponse = client.get();

		assertNotNull("Response not received", coapResponse);

		for (int count = 0; count < NUM_OF_CLIENTS; ++count) {
			createClientEndpoint(MatcherMode.STRICT, new SingleNodeConnectionIdGenerator(4));
		}
		testMultipleSecureGet(0, 0, null);

		for (int count = 1; count < NUM_OF_LOOPS; ++count) {
			nat.mixLocalAddresses();

			coapResponse = client.get();
			assertNotNull("Response not received", coapResponse);
			testMultipleSecureGet(count, 0, null);
		}
	}

	@Test
	public void testSecureGetWithMixedAddressesCIDAndResumption() throws Exception {
		createSecureServer(MatcherMode.STRICT, new SingleNodeConnectionIdGenerator(4));
		createNat();

		int overallResumes = 0;
		List<Integer> resumeEndpoints = new ArrayList<>();

		CoapClient client = new CoapClient(uri);
		CoapResponse coapResponse = client.get();

		assertNotNull("Response not received", coapResponse);

		for (int count = 0; count < NUM_OF_CLIENTS; ++count) {
			createClientEndpoint(MatcherMode.STRICT, new SingleNodeConnectionIdGenerator(4));
		}
		testMultipleSecureGet(0, overallResumes, resumeEndpoints);

		for (int count = 1; count < NUM_OF_LOOPS; ++count) {
			nat.mixLocalAddresses();

			coapResponse = client.get();
			assertNotNull("Response not received", coapResponse);
			testMultipleSecureGet(count, overallResumes, resumeEndpoints);
			forceResumption(resumeEndpoints);
			overallResumes += resumeEndpoints.size();
		}
	}

	private void testMultipleSecureGet(int loop, int overallResumes, List<Integer> resumeEndpoints) throws InterruptedException {
		int num = clientEndpoints.size();
		List<Request> requests = new ArrayList<>();
		for (int count = 1; count < num; ++count) {
			CoapEndpoint endpoint = clientEndpoints.get(count);
			Request request = Request.newGet();
			request.setURI(uri);
			endpoint.sendRequest(request);
			requests.add(request);
			if (count % 8 == 0) {
				connections.validate();
			}
		}
		for (int count = 0; count < requests.size(); ++count) {
			int id = count + 1;
			Request request = requests.get(count);
			Response response = request.waitForResponse(RESPONSE_TIMEOUT);
			if (response == null) {
				connections.validate();
				System.out.println(resumeEndpoints.size() + " resumptions, " + overallResumes + " at all.");
				for (Integer resume : resumeEndpoints) {
					if (id == resume) {
						System.err.println("resume: " + resume + " failed!");
					} else {
						System.out.println("resume: " + resume);
					}
				}
				CoapEndpoint endpoint = clientEndpoints.get(id);
				int port = nat.getLocalPortForAddress(endpoint.getAddress());
				System.err.println("endpoint " + endpoint.getUri() + " via " + port + " failed!");

				if (request.getSendError() != null) {
					fail("Received error " + loop + "/" + id + ": " + request.getSendError());
				} else if (request.isCanceled()) {
					fail("Request canceled " + loop + "/" + id + ": " + request);
				} else if (request.isRejected()) {
					fail("Request rejected " + loop + "/" + id + ": " + request);
				} else if (request.isTimedOut()) {
					fail("Request timedout " + loop + "/" + id + ": " + request);
				}
				fail("Request failed " + loop + "/" + id + ": " + request);
			}
		}
		connections.validate();
	}

	private void forceResumption(List<Integer> resumeEndpoints) throws InterruptedException {
		resumeEndpoints.clear();
		Random rand = new Random(System.currentTimeMillis());
		int num = clientEndpoints.size();
		for (int i = 0; i < num; ++i) {
			if (rand.nextInt(100) > 90) {
				CoapEndpoint endpoint = clientEndpoints.get(i);
				Connector connector = endpoint.getConnector();
				if (connector instanceof DTLSConnector) {
					((DTLSConnector) connector).forceResumeAllSessions();
					resumeEndpoints.add(i);
				}
			}
		}
	}

	private void setupNetworkConfig(MatcherMode mode) {
		if (config == null) {
			config = network.getStandardTestConfig()
					// retransmit constantly all 200 milliseconds
					.setInt(Keys.ACK_TIMEOUT, 200)
					.setFloat(Keys.ACK_RANDOM_FACTOR, 1.5f)
					.setFloat(Keys.ACK_TIMEOUT_SCALE, 1.5f)
					.setLong(Keys.EXCHANGE_LIFETIME, RESPONSE_TIMEOUT)
					.setString(Keys.RESPONSE_MATCHING, mode.name());
		}
	}

	private void createSecureServer(MatcherMode mode, ConnectionIdGenerator cidGenerator) throws IOException {
		setupNetworkConfig(mode);

		DtlsConnectorConfig dtlsConfig = new DtlsConnectorConfig.Builder()
				.setAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
				.setLoggingTag("server")
				.setServerOnly(true)
				.setReceiverThreadCount(2)
				.setConnectionThreadCount(2)
				.setConnectionIdGenerator(cidGenerator)
				.setPskStore(pskStore).build();

		connections = new DebugConnectionStore(
				dtlsConfig.getMaxConnections(),
				dtlsConfig.getStaleConnectionThreshold(),
				null);
		connections.setTag(dtlsConfig.getLoggingTag());

		serverConnector = new MyDtlsConnector(dtlsConfig, connections);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConnector(serverConnector);
		builder.setNetworkConfig(config);
		serverEndpoint = builder.build();

		server = new CoapServer();
		server.addEndpoint(serverEndpoint);
		resource = new MyResource(TARGET);
		server.add(resource);
		server.start();

		uri = serverEndpoint.getUri() + "/" + TARGET;

		// prepare secure client endpoint
		clientEndpoint = createClientEndpoint(mode, cidGenerator);
		EndpointManager.getEndpointManager().setDefaultEndpoint(clientEndpoint);
		System.out.println("coap-server " + uri);
		System.out.println("coap-client " + clientEndpoint.getUri());
	}

	private CoapEndpoint createClientEndpoint(MatcherMode mode, ConnectionIdGenerator cidGenerator) throws IOException {
		setupNetworkConfig(mode);

		String tag = "client";
		int size = clientEndpoints.size();
		if (size > 0) {
			tag += "." + size;
		}

		// prepare secure client endpoint
		DtlsConnectorConfig clientdtlsConfig = new DtlsConnectorConfig.Builder()
				.setAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
				.setLoggingTag(tag)
				.setReceiverThreadCount(2)
				.setConnectionThreadCount(2)
				.setConnectionIdGenerator(cidGenerator)
				.setPskStore(pskStore).build();

		DTLSConnector clientConnector = new DTLSConnector(clientdtlsConfig);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConnector(clientConnector);
		builder.setNetworkConfig(config);
		CoapEndpoint clientEndpoint = builder.build();
		clientEndpoint.start();
		clientEndpoints.add(clientEndpoint);
		return clientEndpoint;
	}

	private void createNat() throws Exception {
		nat = new NatUtil(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), serverEndpoint.getAddress());
		int port = nat.getProxySocketAddress().getPort();
		String natURI = uri.replace(":" + serverEndpoint.getAddress().getPort() + "/", ":" + port + "/");
		System.out.println("URI: change " + uri + " to " + natURI);
		uri = natURI;
	}

	private static class MyResource extends CoapResource {

		public MyResource(String name) {
			super(name);
		}

		@Override
		public void handleGET(CoapExchange exchange) {
			Response response = new Response(ResponseCode.CONTENT);
			response.setPayload("Hello");
			exchange.respond(response);
		}
	}

	private static class MyDtlsConnector extends DTLSConnector {

		public MyDtlsConnector(DtlsConnectorConfig configuration, ResumptionSupportingConnectionStore connectionStore) {
			super(configuration, connectionStore);

		}
	}
}
