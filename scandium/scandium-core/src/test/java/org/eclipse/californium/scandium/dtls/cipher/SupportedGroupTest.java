/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography.SupportedGroup;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class SupportedGroupTest {

	@Test
	public void testGetUsableGroupsReturnsOnlyGroupsWithKnownDomainParams() {
		SupportedGroup[] usablegroups = SupportedGroup.getUsableGroups();
		assertTrue(usablegroups.length > 0);
		for (SupportedGroup group : usablegroups) {
			assertThat(
					"Elliptic curve [" + group.name() + "] is reported to be usable on current JRE " +
					"but domain params are unknown, this should have been detected. Please file " +
					"a bug report indicating your JRE and the name of the elliptic curve",
					group.getEcParams(),
					notNullValue());
		}
	}

}
