/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add shallow clone test
 *    Achim Kraus (Bosch Software Innovations GmbH) - use MessageObserverAdapter
 *                                                    instead of own empty
 *                                                    implementation
 ******************************************************************************/
package org.eclipse.californium.core.observe;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsSame.sameInstance;
import static org.hamcrest.core.IsSame.theInstance;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.elements.category.Small;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verifies behavior of {@code Observation}.
 *
 */
@Category(Small.class)
public class ObservationTest {

	/**
	 * Verifies that a request with its observe option set to a value != 0 is
	 * rejected.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testConstructorRejectsRequestWithNonZeroObserveOption() {
		Request req = Request.newGet();
		req.getOptions().setObserve(4);
		new Observation(req, null);
	}

	/**
	 * Verifies that a request with no observe option rejected.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testConstructorRejectsRequestWithoutObserveOption() {
		Request req = Request.newGet();
		new Observation(req, null);
	}

	@Test
	public void testShallowClone() {
		Map<String,String> userContext = new HashMap<String,String>();
		userContext.put("test", "only");
		Request request = Request.newGet();
		request.setURI("coap://localhost/this");
		request.setObserve();
		request.setToken(new byte[] { 1, 2, 3 });
		request.setUserContext(userContext);
		request.addMessageObserver(new MessageObserverAdapter() {
		});
		Observation observation = new Observation(request, null);
		request.cancel();

		Observation cloned = ObservationUtil.shallowClone(observation);
		Request clonedRequest = cloned.getRequest();
		assertThat(clonedRequest, is(not(theInstance(request))));
		assertThat(clonedRequest.getCode(), is(Code.GET));
		assertThat(clonedRequest.getURI(), is(request.getURI()));
		assertThat(clonedRequest.getOptions().hasObserve(), is(true));
		assertThat(clonedRequest.getOptions().getObserve(), is(0));
		assertThat(clonedRequest.getToken(), is(sameInstance(request.getToken())));
		assertThat(clonedRequest.getUserContext(), is(request.getUserContext()));
		assertThat(clonedRequest.isCanceled(), is(false));
		assertThat(clonedRequest.getMessageObservers().isEmpty(), is(true));

		assertThat(request.isCanceled(), is(true));
		assertThat(request.getMessageObservers().isEmpty(), is(false));

	}

	@Test
	public void testShallowCloneIntendedPayload() {
		Map<String,String> userContext = new HashMap<String,String>();
		userContext.put("test", "only");
		Request request = Request.newFetch();
		request.setURI("coap://localhost/this");
		request.setObserve();
		request.setToken(new byte[] { 1, 2, 3 });
		request.setUserContext(userContext);
		request.setPayload("Hi!");
		request.addMessageObserver(new MessageObserverAdapter() {
		});
		Observation observation = new Observation(request, null);
		request.cancel();

		Observation cloned = ObservationUtil.shallowClone(observation);
		Request clonedRequest = cloned.getRequest();
		assertThat(clonedRequest, is(not(theInstance(request))));
		assertThat(clonedRequest.getCode(), is(Code.FETCH));
		assertThat(clonedRequest.getURI(), is(request.getURI()));
		assertThat(clonedRequest.getOptions().hasObserve(), is(true));
		assertThat(clonedRequest.getOptions().getObserve(), is(0));
		assertThat(clonedRequest.getToken(), is(sameInstance(request.getToken())));
		assertThat(clonedRequest.getUserContext(), is(request.getUserContext()));
		assertThat(clonedRequest.isCanceled(), is(false));
		assertThat(clonedRequest.isUnintendedPayload(), is(false));
		assertThat(clonedRequest.getPayloadString(), is("Hi!"));
		assertThat(clonedRequest.getMessageObservers().isEmpty(), is(true));

		assertThat(request.isCanceled(), is(true));
		assertThat(request.getMessageObservers().isEmpty(), is(false));

	}

	@Test
	public void testShallowCloneUnintendedPayload() {
		Map<String,String> userContext = new HashMap<String,String>();
		userContext.put("test", "only");
		Request request = Request.newGet();
		request.setURI("coap://localhost/this");
		request.setObserve();
		request.setToken(new byte[] { 1, 2, 3 });
		request.setUserContext(userContext);
		request.setUnintendedPayload();
		request.setPayload("Hi!");
		request.addMessageObserver(new MessageObserverAdapter() {
		});
		Observation observation = new Observation(request, null);
		request.cancel();

		Observation cloned = ObservationUtil.shallowClone(observation);
		Request clonedRequest = cloned.getRequest();
		assertThat(clonedRequest, is(not(theInstance(request))));
		assertThat(clonedRequest.getCode(), is(Code.GET));
		assertThat(clonedRequest.getURI(), is(request.getURI()));
		assertThat(clonedRequest.getOptions().hasObserve(), is(true));
		assertThat(clonedRequest.getOptions().getObserve(), is(0));
		assertThat(clonedRequest.getToken(), is(sameInstance(request.getToken())));
		assertThat(clonedRequest.getUserContext(), is(request.getUserContext()));
		assertThat(clonedRequest.isCanceled(), is(false));
		assertThat(clonedRequest.isUnintendedPayload(), is(true));
		assertThat(clonedRequest.getPayloadString(), is("Hi!"));
		assertThat(clonedRequest.getMessageObservers().isEmpty(), is(true));

		assertThat(request.isCanceled(), is(true));
		assertThat(request.getMessageObservers().isEmpty(), is(false));

	}
}
