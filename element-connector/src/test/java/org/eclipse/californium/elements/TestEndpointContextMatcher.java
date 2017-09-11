/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Key set based correlation context matcher.
 */
public class TestEndpointContextMatcher implements EndpointContextMatcher {

	public final AtomicInteger callsIsResponseRelatedToRequest = new AtomicInteger();

	public final AtomicInteger callsIsToBeSent = new AtomicInteger();

	private final CountDownLatch latch;

	private final List<EndpointContext> requestContexts = new ArrayList<EndpointContext>();

	private final List<EndpointContext> responseContexts = new ArrayList<EndpointContext>();

	private final List<EndpointContext> messageContexts = new ArrayList<EndpointContext>();

	private final List<EndpointContext> connectionContexts = new ArrayList<EndpointContext>();

	private final boolean[] returnsIsResponseRelatedToRequest;

	private final boolean[] returnsIsToBeSent;

	public TestEndpointContextMatcher(int countIsResponseRelatedToRequest, int countIsToBeSent) {
		this.returnsIsResponseRelatedToRequest = new boolean[countIsResponseRelatedToRequest];
		this.returnsIsToBeSent = new boolean[countIsToBeSent];
		Arrays.fill(returnsIsResponseRelatedToRequest, true);
		Arrays.fill(returnsIsToBeSent, true);
		latch = new CountDownLatch(countIsResponseRelatedToRequest + countIsToBeSent);
	}
	
	public TestEndpointContextMatcher(boolean[] returnsIsResponseRelatedToRequest, boolean[] returnsIsToBeSent) {
		this.returnsIsResponseRelatedToRequest = returnsIsResponseRelatedToRequest;
		this.returnsIsToBeSent = returnsIsToBeSent;
		latch = new CountDownLatch(returnsIsResponseRelatedToRequest.length + returnsIsToBeSent.length);
	}

	@Override
	public String getName() {
		return "test only";
	}

	@Override
	public synchronized boolean isResponseRelatedToRequest(EndpointContext requestContext, EndpointContext responseContext) {
		requestContexts.add(requestContext);
		responseContexts.add(responseContext);
		return returns(returnsIsResponseRelatedToRequest, callsIsResponseRelatedToRequest.getAndIncrement());
	}

	@Override
	public synchronized boolean isToBeSent(EndpointContext messageContext, EndpointContext connectionContext) {
		messageContexts.add(messageContext);
		connectionContexts.add(connectionContext);
		return returns(returnsIsToBeSent, callsIsToBeSent.getAndIncrement());
	}

	public synchronized EndpointContext getRequestEndpointContext(final int index) {
		return getEndpointContext(requestContexts, index);
	}

	public synchronized EndpointContext getResponseEndpointContext(final int index) {
		return getEndpointContext(responseContexts, index);
	}

	public synchronized EndpointContext getMessageEndpointContext(final int index) {
		return getEndpointContext(messageContexts, index);
	}

	public synchronized EndpointContext getConnectionEndpointContext(final int index) {
		return getEndpointContext(connectionContexts, index);
	}

	public boolean await(long timeout, TimeUnit unit) throws InterruptedException {
		return latch.await(timeout, unit);
	}

	private boolean returns(boolean[] values, int index) {
		if (values == null || values.length == 0) {
			return false;
		} else {
			if (values.length <= index) {
				index = values.length - 1;
			} else {
				latch.countDown();
			}
			return values[index];
		}
	}

	private synchronized EndpointContext getEndpointContext(List<EndpointContext> contexts, final int index) {
		if (index >= contexts.size()) {
			throw new IllegalArgumentException("Index  " + index + " is not reached! Current " + (contexts.size() -1 ));
		}
		return contexts.get(index);
	}
}
