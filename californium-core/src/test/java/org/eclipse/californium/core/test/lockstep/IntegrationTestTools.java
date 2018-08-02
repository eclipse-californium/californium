/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH
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
 *    Bosch Software Innovations GmbH - refactor common functionality for integration
 *                                      tests into separate utility class
 *    Achim Kraus (Bosch Software Innovations GmbH) - use waitForCondition
 *    Achim Kraus (Bosch Software Innovations GmbH) - move waitUntilDeduplicatorShouldBeEmpty
 *                                                    to MessageExchangeStoreTool
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.net.InetSocketAddress;

import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;

/**
 * Common functionality for integration tests.
 *
 */
public final class IntegrationTestTools {

	private static int currentToken = 10;

	private IntegrationTestTools() {
		// empty
	}

	/**
	 * Creates an endpoint that can be used to <em>record</em> and <em>play back</em> expected behavior
	 * when receiving certain messages.
	 * 
	 * @param destination The address to send messages to.
	 * @return The created endpoint.
	 */
	public static LockstepEndpoint createLockstepEndpoint(final InetSocketAddress destination) {
		LockstepEndpoint endpoint = new LockstepEndpoint();
		endpoint.setDestination(destination);
		return endpoint;
	}

	public static LockstepEndpoint createChangedLockstepEndpoint(final LockstepEndpoint previous) {
		LockstepEndpoint endpoint = new LockstepEndpoint(previous);
		previous.destroy();
		return endpoint;
	}

	public static Request createRequest(Code code, String path, LockstepEndpoint server) throws Exception {
		Request request = new Request(code);
		String uri = String.format("coap://%s:%d/%s", server.getAddress().getHostAddress(), server.getPort(), path);
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

	public static void printServerLog(ClientBlockwiseInterceptor interceptor) {
		System.out.println(interceptor.toString());
		System.out.println();
		interceptor.clear();
	}

	public static void printServerLog(BlockwiseInterceptor interceptor) {
		System.out.println(interceptor.toString());
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
