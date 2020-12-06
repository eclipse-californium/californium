/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.cipher;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.List;

import javax.crypto.SecretKey;

import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Medium.class)
public class SupportedGroupTest {

	private static final int LOOPS = 10;

	@Test
	public void testGetSupportedGroupFromPublicKey() {
		for (SupportedGroup group : SupportedGroup.getUsableGroups()) {
				try {
					XECDHECryptography ecdhe = new XECDHECryptography(group);
					PublicKey publicKey = ecdhe.getPublicKey();
					SupportedGroup groupFromPublicKey = SupportedGroup.fromPublicKey(publicKey);
					assertThat(groupFromPublicKey, is(group));
				} catch (GeneralSecurityException e) {
					fail(e.getMessage());
				}
		}
	}

	@Test
	public void testDheKeyExchange() {
		for (SupportedGroup group : SupportedGroup.getUsableGroups()) {
			for (int loop = 0; loop < LOOPS; ++loop) {
				try {
					XECDHECryptography ecdhe1 = new XECDHECryptography(group);
					byte[] point1 = ecdhe1.getEncodedPoint();
					assertThat(point1, is(notNullValue()));
					byte[] asn1 = ecdhe1.getPublicKey().getEncoded();
					check(group, point1, asn1);

					XECDHECryptography ecdhe2 = new XECDHECryptography(group);
					byte[] point2 = ecdhe2.getEncodedPoint();
					assertThat(point2, is(notNullValue()));
					byte[] asn2 = ecdhe2.getPublicKey().getEncoded();
					check(group, point2, asn2);

					SecretKey secret1 = ecdhe1.generateSecret(point2);
					assertThat(secret1, is(notNullValue()));
					SecretKey secret2 = ecdhe2.generateSecret(point1);
					assertThat(secret2, is(notNullValue()));
					assertThat("edhe failed!", secret1, is(secret2));
				} catch (GeneralSecurityException e) {
					fail(e.getMessage());
				}
			}
		}
	}

	private static void check(SupportedGroup group, byte[] point, byte[] asn1) {
		for (int index = 0; index < point.length; ++index) {
			if (point[point.length - index - 1] != asn1[asn1.length - index - 1]) {
				String s1 = StringUtil.byteArray2Hex(asn1);
				String s2 = StringUtil.byteArray2Hex(point);
				if (s2.length() < s1.length()) {
					s2 = String.format("%" + s1.length() + "s", s2);
				}
				System.err.println("ASN encoded '" + s1 + "'");
				System.err.println("DHE encoded '" + s2 + "'");
				fail("DHE: failed to encoded point! " + group.name() + ", position: " + index);
			}
		}
	}

	@Test
	public void testGetUsableGroupsReturnsOnlyGroupsWithKnownDomainParams() {
		int length = SupportedGroup.values().length;
		List<SupportedGroup> usablegroups = SupportedGroup.getUsableGroups();
		List<SupportedGroup> preferredgroups = SupportedGroup.getPreferredGroups();
		assertTrue(usablegroups.size() > 0);
		assertTrue(length >= usablegroups.size());
		assertTrue(preferredgroups.size() > 0);
		assertTrue(usablegroups.size() >= preferredgroups.size());
		System.out.println(
				"groups: " + length + ", usable: " + usablegroups.size() + ", preferred: " + preferredgroups.size());
	}

}
