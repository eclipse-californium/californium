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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.auth;

import static org.junit.Assert.*;

import org.junit.Test;


/**
 * Verifies behavior of {@link PreSharedKeyIdentity}.
 *
 */
public class PreSharedKeyIdentityTest {

	/**
	 * Verifies that the constructor rejects a host name containing
	 * a colon character.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void testConstructorRejectsIllegalHostName() {
		new PreSharedKeyIdentity("illegal.host:name", "acme");
	}

	/**
	 * Verifies that two instances with the same identity but different
	 * virtual host names are not considered equal.
	 */
	@Test
	public void testEqualsDetectsNonMatchingVirtualHost() {
		PreSharedKeyIdentity idOne = new PreSharedKeyIdentity("iot.eclipse.org", "device-1");
		PreSharedKeyIdentity idTwo = new PreSharedKeyIdentity("coap.eclipse.org", "device-1");
		assertFalse(idOne.equals(idTwo));
	}

	/**
	 * Verifies that two instances with the same identity and virtual host
	 * are considered equal.
	 */
	@Test
	public void testEqualsSucceeds() {
		PreSharedKeyIdentity idOne = new PreSharedKeyIdentity("iot.eclipse.org", "device-1");
		PreSharedKeyIdentity idTwo = new PreSharedKeyIdentity("iot.eclipse.org", "device-1");
		assertTrue(idOne.equals(idTwo));
	}
}
