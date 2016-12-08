/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.observe;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.Request;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * Verifies behavior of {@code Observation}.
 *
 */
@Category(Small.class)
public class ObservationTest {

	/**
	 * Verifies that a request with its observe option set to a value != 0 is rejected.
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
}
