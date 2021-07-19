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

import static org.eclipse.californium.integration.test.NatTestHelper.USE_CID_4;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.config.CoapConfig.MatcherMode;
import org.eclipse.californium.elements.category.NativeDatagramSocketImplRequired;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.TestScope;
import org.eclipse.californium.integration.test.util.CoapsNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.eclipse.californium.scandium.dtls.ConnectionIdGenerator;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(NativeDatagramSocketImplRequired.class)
public class SecureNatTest {

	@ClassRule
	public static CoapsNetworkRule network = new CoapsNetworkRule(CoapsNetworkRule.Mode.NATIVE);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	static final int ACK_TIMEOUT = 200;
	static final int NUM_OF_CLIENTS = 20;
	static final int NUM_OF_LOOPS = 50;

	private NatTestHelper helper;

	@Before
	public void init() {
		helper = new NatTestHelper(network);
	}

	@After
	public void shutdown() {
		if (helper != null) {
			helper.shutdown();
			helper = null;
		}
	}

	@Test
	public void testSecureGet() throws Exception {
		helper.setupNetworkConfig(MatcherMode.STRICT, ACK_TIMEOUT);
		helper.createSecureServer((ConnectionIdGenerator) null);
		helper.createDefaultClientEndpoint(null);

		CoapClient client = new CoapClient(helper.uri);
		CoapResponse coapResponse = client.get();

		assertNotNull("Response not received", coapResponse);

		helper.nat.reassignNewLocalAddresses();

		coapResponse = client.get();

		assertNull("Response still received", coapResponse);
	}

	@Test
	public void testSecureGetWithCID() throws Exception {
		helper.setupNetworkConfig(MatcherMode.STRICT, ACK_TIMEOUT);
		helper.createSecureServer(USE_CID_4);
		helper.createDefaultClientEndpoint(USE_CID_4);

		CoapClient client = new CoapClient(helper.uri);
		CoapResponse coapResponse = client.get();

		assertNotNull("Response not received", coapResponse);

		helper.nat.reassignNewLocalAddresses();

		coapResponse = client.get();

		assertNotNull("Response not received", coapResponse);
	}

	@Test
	public void testMultipleSecureGetWithCID() throws Exception {
		helper.setupNetworkConfig(MatcherMode.STRICT, ACK_TIMEOUT);
		helper.createSecureServer(USE_CID_4);
		helper.createDefaultClientEndpoint(USE_CID_4);

		CoapClient client = new CoapClient(helper.uri);
		CoapResponse coapResponse = client.get();

		assertNotNull("Response not received", coapResponse);

		for (int count = 0; count < NUM_OF_CLIENTS; ++count) {
			helper.createClientEndpoint(USE_CID_4);
		}
		helper.testMultipleSecureGet(0, 0, null);

		for (int count = 1; count < NUM_OF_LOOPS; ++count) {
			helper.nat.reassignNewLocalAddresses();

			coapResponse = client.get();
			assertNotNull("Response not received", coapResponse);
			helper.testMultipleSecureGet(count, 0, null);
		}
		client.shutdown();
	}

	@Test
	public void testMultipleSecureGetWithCIDAndResumption() throws Exception {
		helper.setupNetworkConfig(MatcherMode.STRICT, ACK_TIMEOUT);
		helper.createSecureServer(USE_CID_4);
		helper.createDefaultClientEndpoint(USE_CID_4);

		int overallResumes = 0;
		List<Integer> resumeEndpoints = new ArrayList<>();

		CoapClient client = new CoapClient(helper.uri);
		CoapResponse coapResponse = client.get();

		assertNotNull("Response not received", coapResponse);

		for (int count = 0; count < NUM_OF_CLIENTS; ++count) {
			helper.createClientEndpoint(USE_CID_4);
		}
		helper.testMultipleSecureGet(0, overallResumes, resumeEndpoints);

		for (int count = 1; count < NUM_OF_LOOPS; ++count) {
			helper.nat.reassignNewLocalAddresses();

			coapResponse = client.get();
			assertNotNull("Response not received", coapResponse);
			helper.testMultipleSecureGet(count, overallResumes, resumeEndpoints);
			helper.forceResumption(resumeEndpoints, 20);
			overallResumes += resumeEndpoints.size();
		}
		client.shutdown();
	}

	@Test
	public void testSecureGetWithMixedAddressesAndCID() throws Exception {
		helper.setupNetworkConfig(MatcherMode.STRICT, ACK_TIMEOUT);
		helper.createSecureServer(USE_CID_4);
		helper.createDefaultClientEndpoint(USE_CID_4);

		CoapClient client = new CoapClient(helper.uri);
		CoapResponse coapResponse = client.get();

		assertNotNull("Response not received", coapResponse);

		for (int count = 0; count < NUM_OF_CLIENTS; ++count) {
			helper.createClientEndpoint(USE_CID_4);
		}
		helper.testMultipleSecureGet(0, 0, null);

		for (int count = 1; count < NUM_OF_LOOPS; ++count) {
			helper.nat.mixLocalAddresses();

			coapResponse = client.get();
			assertNotNull("Response not received", coapResponse);
			helper.testMultipleSecureGet(count, 0, null);
		}
		client.shutdown();
	}

	@Test
	public void testSecureGetWithMixedAddressesCIDAndResumption() throws Exception {
		helper.setupNetworkConfig(MatcherMode.STRICT, ACK_TIMEOUT);
		helper.createSecureServer(USE_CID_4);
		helper.createDefaultClientEndpoint(USE_CID_4);

		int overallResumes = 0;
		List<Integer> resumeEndpoints = new ArrayList<>();

		CoapClient client = new CoapClient(helper.uri);
		CoapResponse coapResponse = client.get();

		assertNotNull("Response not received", coapResponse);

		for (int count = 0; count < NUM_OF_CLIENTS; ++count) {
			helper.createClientEndpoint(USE_CID_4);
		}
		helper.testMultipleSecureGet(0, overallResumes, resumeEndpoints);

		for (int count = 1; count < NUM_OF_LOOPS; ++count) {
			helper.nat.mixLocalAddresses();

			coapResponse = client.get();
			assertNotNull("Response not received", coapResponse);
			helper.testMultipleSecureGet(count, overallResumes, resumeEndpoints);
			helper.forceResumption(resumeEndpoints, 20);
			overallResumes += resumeEndpoints.size();
		}
		client.shutdown();
	}

	/**
	 * This test fails, what demonstrates, that resent CLIENT_HELLOs are not proper
	 * processed.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testSecureGetWithMixedAddressesCIDReordered() throws Exception {
		helper.setupNetworkConfig(MatcherMode.STRICT, ACK_TIMEOUT);
		helper.createSecureServer(USE_CID_4);
		helper.createDefaultClientEndpoint(USE_CID_4);
		helper.nat.setMessageReordering(10, 500, 500);

		int overallResumes = 0;
		List<Integer> resumeEndpoints = new ArrayList<>();

		CoapClient client = new CoapClient(helper.uri);
		CoapResponse coapResponse = client.get();

		assertNotNull("Response not received", coapResponse);

		int clients = TestScope.enableIntensiveTests() ? 50 : NUM_OF_CLIENTS;

		for (int count = 0; count < clients; ++count) {
			helper.createClientEndpoint(USE_CID_4);
		}
		helper.testMultipleSecureGet(0, overallResumes, resumeEndpoints);

		int loops = TestScope.enableIntensiveTests() ? NUM_OF_LOOPS : 10;

		for (int count = 1; count < loops; ++count) {
			helper.nat.mixLocalAddresses();

			coapResponse = client.get();
			assertNotNull("Response not received", coapResponse);
			helper.testMultipleSecureGet(count, overallResumes, resumeEndpoints);
			// stop previous reordered messages
			helper.nat.setMessageReordering(10, 500, 500);
			helper.forceResumption(resumeEndpoints, 20);
			overallResumes += resumeEndpoints.size();
		}
		client.shutdown();
	}
}
