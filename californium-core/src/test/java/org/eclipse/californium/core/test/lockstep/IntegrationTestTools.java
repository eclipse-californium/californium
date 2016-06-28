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
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.net.InetSocketAddress;
import java.util.Random;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.test.BlockwiseTransferTest.ServerBlockwiseInterceptor;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;

/**
 * Common functionality for integration tests.
 *
 */
public final class IntegrationTestTools {

	private static final Random RAND = new Random();
	private static int currentToken = 10;

	private IntegrationTestTools() {
		// empty
	}

	public static LockstepEndpoint createLockstepEndpoint(InetSocketAddress destination) throws Exception {
		LockstepEndpoint endpoint = new LockstepEndpoint();
		endpoint.setDestination(destination);
		return endpoint;
	}

	public static Request createRequest(Code code, String path, LockstepEndpoint server) throws Exception {
		Request request = new Request(code);
		String uri = String.format("coap://%s:%d/%s", server.getAddress().getHostAddress(), server.getPort(), path);
		request.setURI(uri);
		return request; 
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
		interceptor.clear();
	}

	public static void printServerLog(ServerBlockwiseInterceptor interceptor) {
		System.out.println(interceptor.toString());
		interceptor.clear();
	}

	public static String generateRandomPayload(int length) {
		StringBuffer buffer = new StringBuffer();
		while(buffer.length() < length) {
			buffer.append(RAND.nextInt());
		}
		return buffer.substring(0, length);
	}

	public static String generatePayload(int length) {
		StringBuffer buffer = new StringBuffer();
		int n = 1;
		while(buffer.length() < length) {
			buffer.append(n++);
		}
		return buffer.substring(0, length);
	}

	public static byte[] generateNextToken() {
		return b(++currentToken);
	}

	private static byte[] b(int... is) {
		byte[] bytes = new byte[is.length];
		for (int i=0; i < bytes.length; i++) {
			bytes[i] = (byte) is[i];
		}
		return bytes;
	}

	public static void waitUntilDeduplicatorShouldBeEmpty(final int exchangeLifetime, final int sweepInterval) {
		try {
			int timeToWait = exchangeLifetime + sweepInterval + 100; // milliseconds
			System.out.println("Wait until deduplicator should be empty (" + timeToWait/1000f + " seconds)");
			Thread.sleep(timeToWait);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

}
