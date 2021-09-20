/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH
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
 *    Bosch Software Innovations GmbH - refactor common functionality for integration
 *                                      tests into separate utility class
 *    Achim Kraus (Bosch Software Innovations GmbH) - use waitForCondition
 *    Achim Kraus (Bosch Software Innovations GmbH) - move waitUntilDeduplicatorShouldBeEmpty
 *                                                    to MessageExchangeStoreTool
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertNotNull;

import java.net.InetSocketAddress;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.elements.config.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Common functionality for integration tests.
 *
 */
public final class IntegrationTestTools {

	private static final Logger LOGGER = LoggerFactory.getLogger(IntegrationTestTools.class);

	private static int currentToken = 10;

	private IntegrationTestTools() {
		// empty
	}

	/**
	 * Creates an endpoint that can be used to <em>record</em> and <em>play back</em> expected behavior
	 * when receiving certain messages.
	 * 
	 * @param destination The address to send messages to.
	 * @param config The configuration for the endpoint.
	 * @return The created endpoint.
	 */
	public static LockstepEndpoint createLockstepEndpoint(InetSocketAddress destination, Configuration config) {
		return new LockstepEndpoint(destination, config);
	}

	public static LockstepEndpoint createChangedLockstepEndpoint(LockstepEndpoint previous) {
		LockstepEndpoint endpoint = new LockstepEndpoint(previous);
		previous.destroy();
		return endpoint;
	}

	public static Request createRequest(Code code, String path, LockstepEndpoint server) throws Exception {
		Request request = new Request(code);
		String uri = TestTools.getUri(server.getAddress(), server.getPort(), path);
		request.setURI(uri);
		return request;
	}

	public static void assertNumberOfReceivedNotifications(final SynchronousNotificationListener listener,
			final int expectedNotifications, final boolean resetListener) {
		assertThat(listener.getNotificationCount(), is(expectedNotifications));
		if (resetListener) {
			listener.resetNotificationCount();
		}
	}

	public static void assertResponseContainsExpectedPayload(Response response, String expectedPayload) {
		assertResponseContainsExpectedPayload(response, CONTENT, expectedPayload);
	}

	public static void assertResponseContainsExpectedPayload(Response response, ResponseCode expectedResponseCode,
			String expectedPayload) {
		assertNotNull("Client received no notification", response);
		assertThat("Client received wrong response code:", response.getCode(), is(expectedResponseCode));
		assertThat("Client received wrong payload:", response.getPayloadString(), is(expectedPayload));
	}

	public static void printServerLog(BlockwiseInterceptor interceptor) {
		if (LOGGER.isInfoEnabled()) {
			System.out.println(interceptor.toString());
		}
		interceptor.clear();
	}

	public static Token generateNextToken() {
		return Token.fromProvider(b(++currentToken));
	}

	private static byte[] b(int... is) {
		byte[] bytes = new byte[is.length];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) is[i];
		}
		return bytes;
	}

}
