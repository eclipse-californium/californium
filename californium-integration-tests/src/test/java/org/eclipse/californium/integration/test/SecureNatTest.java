/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation.
 ******************************************************************************/
package org.eclipse.californium.integration.test;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.category.Large;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointContextMatcherFactory.MatcherMode;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfig.Keys;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.PrincipalEndpointContextMatcher;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.examples.NatUtil;
import org.eclipse.californium.integration.test.util.CoapsNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.ConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.DebugConnectionStore;
import org.eclipse.californium.scandium.dtls.ResumptionSupportingConnectionStore;
import org.eclipse.californium.scandium.dtls.SingleNodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Large.class)
public class SecureNatTest {

	@ClassRule
	public static CoapsNetworkRule network = new CoapsNetworkRule(CoapsNetworkRule.Mode.DIRECT,
			CoapsNetworkRule.Mode.NATIVE);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	static final long RESPONSE_TIMEOUT = 10000L;
	static final int NUM_OF_CLIENTS = 20;
	static final int NUM_OF_LOOPS = 50;

	static final String TARGET = "resource";
	static final String IDENITITY = "client1";
	static final String KEY = "key1";

	private NatUtil nat;
	private DebugConnectionStore serverConnections;
	private List<DebugConnectionStore> clientConnections = new ArrayList<DebugConnectionStore>();
	private TestUtilPskStore pskStore;
	private MatcherMode mode;
	private NetworkConfig config;
	private CoapEndpoint serverEndpoint;
	private List<CoapEndpoint> clientEndpoints = new ArrayList<>();
	private MyResource resource;

	private String uri;

	@Before
	public void setupPSK() {
		pskStore = new TestUtilPskStore(IDENITITY, KEY.getBytes());
	}

	@After
	public void shutdownServer() {
		if (nat != null) {
			nat.stop();
		}
		for (CoapEndpoint endpoint : clientEndpoints) {
			endpoint.destroy();
		}
	}

	@Test
	public void testSecureGet() throws Exception {
		setupNetworkConfig(MatcherMode.STRICT);
		createSecureServer(null);
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
		setupNetworkConfig(MatcherMode.STRICT);
		createSecureServer(new SingleNodeConnectionIdGenerator(4));
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
		setupNetworkConfig(MatcherMode.STRICT);
		createSecureServer(new SingleNodeConnectionIdGenerator(4));
		createNat();

		CoapClient client = new CoapClient(uri);
		CoapResponse coapResponse = client.get();

		assertNotNull("Response not received", coapResponse);

		for (int count = 0; count < NUM_OF_CLIENTS; ++count) {
			createClientEndpoint(new SingleNodeConnectionIdGenerator(4));
		}
		testMultipleSecureGet(0, 0, null);

		for (int count = 1; count < NUM_OF_LOOPS; ++count) {
			nat.reassignNewLocalAddresses();

			coapResponse = client.get();
			assertNotNull("Response not received", coapResponse);
			testMultipleSecureGet(count, 0, null);
		}
		client.shutdown();
	}

	@Test
	public void testMultipleSecureGetWithCIDAndResumption() throws Exception {
		setupNetworkConfig(MatcherMode.STRICT);
		createSecureServer(new SingleNodeConnectionIdGenerator(4));
		createNat();

		int overallResumes = 0;
		List<Integer> resumeEndpoints = new ArrayList<>();

		CoapClient client = new CoapClient(uri);
		CoapResponse coapResponse = client.get();

		assertNotNull("Response not received", coapResponse);

		for (int count = 0; count < NUM_OF_CLIENTS; ++count) {
			createClientEndpoint(new SingleNodeConnectionIdGenerator(4));
		}
		testMultipleSecureGet(0, overallResumes, resumeEndpoints);

		for (int count = 1; count < NUM_OF_LOOPS; ++count) {
			nat.reassignNewLocalAddresses();

			coapResponse = client.get();
			assertNotNull("Response not received", coapResponse);
			testMultipleSecureGet(count, overallResumes, resumeEndpoints);
			forceResumption(resumeEndpoints, 20);
			overallResumes += resumeEndpoints.size();
		}
		client.shutdown();
	}

	@Test
	public void testSecureGetWithMixedAddressesAndCID() throws Exception {
		setupNetworkConfig(MatcherMode.STRICT);
		createSecureServer(new SingleNodeConnectionIdGenerator(4));
		createNat();

		CoapClient client = new CoapClient(uri);
		CoapResponse coapResponse = client.get();

		assertNotNull("Response not received", coapResponse);

		for (int count = 0; count < NUM_OF_CLIENTS; ++count) {
			createClientEndpoint(new SingleNodeConnectionIdGenerator(4));
		}
		testMultipleSecureGet(0, 0, null);

		for (int count = 1; count < NUM_OF_LOOPS; ++count) {
			nat.mixLocalAddresses();

			coapResponse = client.get();
			assertNotNull("Response not received", coapResponse);
			testMultipleSecureGet(count, 0, null);
		}
		client.shutdown();
	}

	@Test
	public void testSecureGetWithMixedAddressesCIDAndResumption() throws Exception {
		setupNetworkConfig(MatcherMode.STRICT);
		createSecureServer(new SingleNodeConnectionIdGenerator(4));
		createNat();

		int overallResumes = 0;
		List<Integer> resumeEndpoints = new ArrayList<>();

		CoapClient client = new CoapClient(uri);
		CoapResponse coapResponse = client.get();

		assertNotNull("Response not received", coapResponse);

		for (int count = 0; count < NUM_OF_CLIENTS; ++count) {
			createClientEndpoint(new SingleNodeConnectionIdGenerator(4));
		}
		testMultipleSecureGet(0, overallResumes, resumeEndpoints);

		for (int count = 1; count < NUM_OF_LOOPS; ++count) {
			nat.mixLocalAddresses();

			coapResponse = client.get();
			assertNotNull("Response not received", coapResponse);
			testMultipleSecureGet(count, overallResumes, resumeEndpoints);
			forceResumption(resumeEndpoints, 20);
			overallResumes += resumeEndpoints.size();
		}
		client.shutdown();
	}

	/**
	 * This test fails, what demonstrates, that resent CLIENT_HELLOs are not proper processed.
	 * @throws Exception
	 */
	@Test
	public void testSecureGetWithMixedAddressesCIDReordered() throws Exception {
		setupNetworkConfig(MatcherMode.STRICT);
		createSecureServer(new SingleNodeConnectionIdGenerator(4));
		createNat();
		nat.setMessageReordering(10, 500, 500);

		int overallResumes = 0;
		List<Integer> resumeEndpoints = new ArrayList<>();

		CoapClient client = new CoapClient(uri);
		CoapResponse coapResponse = client.get();

		assertNotNull("Response not received", coapResponse);

		for (int count = 0; count < NUM_OF_CLIENTS; ++count) {
			createClientEndpoint(new SingleNodeConnectionIdGenerator(4));
		}
		testMultipleSecureGet(0, overallResumes, resumeEndpoints);

		for (int count = 1; count < NUM_OF_LOOPS; ++count) {
			nat.mixLocalAddresses();

			coapResponse = client.get();
			assertNotNull("Response not received", coapResponse);
			testMultipleSecureGet(count, overallResumes, resumeEndpoints);
			nat.setMessageReordering(10, 500, 500);
			forceResumption(resumeEndpoints, 20);
			overallResumes += resumeEndpoints.size();
		}
		client.shutdown();
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
				serverConnections.validate();
			}
		}
		List<Integer> idOfErrors = new ArrayList<Integer>();
		long responseTimeout = config.getLong(Keys.EXCHANGE_LIFETIME) + 1000;
		for (int count = 0; count < requests.size(); ++count) {
			int id = count + 1;
			Request request = requests.get(count);
			Response response = request.waitForResponse(responseTimeout);
			if (response == null) {
				idOfErrors.add(id);
			}
		}
		if (!idOfErrors.isEmpty()) {
			serverConnections.validate();
			System.out.println(resumeEndpoints.size() + " resumptions, " + overallResumes + " at all.");
			for (Integer resume : resumeEndpoints) {
				CoapEndpoint endpoint = clientEndpoints.get(resume);
				int port = nat.getLocalPortForAddress(endpoint.getAddress());
				String message ="resume: " + resume + ", " + endpoint.getUri() + " via " + port;
				if (idOfErrors.contains(resume)) {
					message += " may have failed!";
				}
				System.out.println(message);
			}
			boolean dump = false;
			StringBuilder failure = new StringBuilder();
			for (Integer id : idOfErrors) {
				Request request = requests.get(id - 1);
				CoapEndpoint endpoint = clientEndpoints.get(id);
				int port = nat.getLocalPortForAddress(endpoint.getAddress());
				System.out.flush();
				System.err.println("client: " + id + ", endpoint " + endpoint.getUri() + " via " + port + " failed!");
				if (!dumpClientConnections(id)) {
					dump = true;
				}
				if (request.getSendError() != null) {
					failure.append("Received error ").append(loop).append("/").append(id).append(": ")
							.append(request.getSendError());
				} else if (request.isCanceled()) {
					failure.append("Request canceled ").append(loop).append("/").append(id).append(": ")
							.append(request);
				} else if (request.isRejected()) {
					failure.append("Request rejected ").append(loop).append("/").append(id).append(": ")
							.append(request);
				} else if (request.isTimedOut()) {
					failure.append("Request timedout ").append(loop).append("/").append(id).append(": ")
							.append(request);
				} else {
					failure.append("Request failed ").append(loop).append("/").append(id).append(": ").append(request);
				}
				failure.append(StringUtil.lineSeparator());
			}
			if (dump) {
				serverConnections.dump();
			}
			fail(failure.toString());
		}
		serverConnections.validate();
	}

	private void forceResumption(List<Integer> resumeEndpoints, int percent) throws InterruptedException {
		resumeEndpoints.clear();
		Random rand = new Random(System.currentTimeMillis());
		int num = clientEndpoints.size();
		for (int i = 0; i < num; ++i) {
			if (rand.nextInt(100) < percent) {
				CoapEndpoint endpoint = clientEndpoints.get(i);
				Connector connector = endpoint.getConnector();
				if (connector instanceof DTLSConnector) {
					((DTLSConnector) connector).forceResumeAllSessions();
					resumeEndpoints.add(i);
				}
			}
		}
	}

	private boolean dumpClientConnections(int id) throws InterruptedException {
		DebugConnectionStore connections = clientConnections.get(id);
		connections.dump();
		CoapEndpoint endpoint = clientEndpoints.get(id);
		InetSocketAddress address = endpoint.getAddress();
		InetSocketAddress via = nat.getLocalAddressForAddress(address);
		return serverConnections.dump(via);
	}

	private void setupNetworkConfig(MatcherMode mode) {
		this.mode = mode;
		config = network.getStandardTestConfig()
				// retransmit starting with 200 milliseconds
				.setInt(Keys.ACK_TIMEOUT, 200)
				.setFloat(Keys.ACK_RANDOM_FACTOR, 1.5f)
				.setFloat(Keys.ACK_TIMEOUT_SCALE, 1.5f)
				.setLong(Keys.EXCHANGE_LIFETIME, RESPONSE_TIMEOUT)
				.setString(Keys.RESPONSE_MATCHING, mode.name());
	}

	private void createSecureServer(ConnectionIdGenerator cidGenerator) throws IOException {

		DtlsConnectorConfig dtlsConfig = new DtlsConnectorConfig.Builder()
				.setAddress(TestTools.LOCALHOST_EPHEMERAL)
				.setLoggingTag("server")
				.setServerOnly(true)
				.setReceiverThreadCount(2)
				.setMaxConnections(10000)
				.setConnectionThreadCount(4)
				.setConnectionIdGenerator(cidGenerator)
				.setMaxRetransmissions(4)
				.setRetransmissionTimeout(200)
				.setVerifyPeersOnResumptionThreshold(100)
				.setPskStore(pskStore).build();

		serverConnections = new DebugConnectionStore(
				dtlsConfig.getMaxConnections(),
				dtlsConfig.getStaleConnectionThreshold(),
				null);
		serverConnections.setTag(dtlsConfig.getLoggingTag());

		Connector serverConnector = new MyDtlsConnector(dtlsConfig, serverConnections);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConnector(serverConnector);
		if (mode == MatcherMode.PRINCIPAL) {
			builder.setEndpointContextMatcher(new PrincipalEndpointContextMatcher(true));
		}
		builder.setNetworkConfig(config);
		serverEndpoint = builder.build();

		CoapServer server = new CoapServer();
		server.addEndpoint(serverEndpoint);
		resource = new MyResource(TARGET);
		server.add(resource);
		server.start();
		cleanup.add(server);

		uri = TestTools.getUri(serverEndpoint, TARGET);

		// prepare secure client endpoint
		Endpoint clientEndpoint = createClientEndpoint(cidGenerator);
		EndpointManager.getEndpointManager().setDefaultEndpoint(clientEndpoint);
		System.out.println("coap-server " + uri);
		System.out.println("coap-client " + clientEndpoint.getUri());
	}

	private CoapEndpoint createClientEndpoint(ConnectionIdGenerator cidGenerator) throws IOException {

		String tag = "client";
		int size = clientEndpoints.size();
		if (size > 0) {
			tag += "." + size;
		}

		// prepare secure client endpoint
		DtlsConnectorConfig clientdtlsConfig = new DtlsConnectorConfig.Builder()
				.setAddress(TestTools.LOCALHOST_EPHEMERAL)
				.setLoggingTag(tag)
				.setReceiverThreadCount(2)
				.setMaxConnections(20)
				.setConnectionThreadCount(2)
				.setConnectionIdGenerator(cidGenerator)
				.setMaxRetransmissions(4)
				.setRetransmissionTimeout(200)
				.setSupportedCipherSuites(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8)
				.setPskStore(pskStore).build();

		DebugConnectionStore connections = new DebugConnectionStore(
				clientdtlsConfig.getMaxConnections(),
				clientdtlsConfig.getStaleConnectionThreshold(),
				null);
		connections.setTag(clientdtlsConfig.getLoggingTag());

		DTLSConnector clientConnector = new MyDtlsConnector(clientdtlsConfig, connections);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setConnector(clientConnector);
		builder.setNetworkConfig(config);
		CoapEndpoint clientEndpoint = builder.build();
		clientEndpoint.start();
		clientConnections.add(connections);
		clientEndpoints.add(clientEndpoint);
		return clientEndpoint;
	}

	private void createNat() throws Exception {
		nat = new NatUtil(TestTools.LOCALHOST_EPHEMERAL, serverEndpoint.getAddress());
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
