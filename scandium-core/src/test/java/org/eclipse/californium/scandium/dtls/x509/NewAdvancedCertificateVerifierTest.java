/*******************************************************************************
 * Copyright (c) 2022 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.x509;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assume.assumeThat;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class NewAdvancedCertificateVerifierTest {

	private static X509Certificate[] trusts;
	private static Set<X500Principal> issuers;

	@BeforeClass
	public static void setUp() throws Exception {
		trusts = DtlsTestTools.getTrustedCertificates();
		issuers = new HashSet<>();
		for (X509Certificate trust : trusts) {
			issuers.add(trust.getSubjectX500Principal());
		}
		assumeThat(issuers.isEmpty(), is(false));
	}

	@Test
	public void testUseEmptyAcceptedIssuers() {
		NewAdvancedCertificateVerifier certificateVerifier = StaticNewAdvancedCertificateVerifier.builder()
				.setTrustedCertificates(trusts).setUseEmptyAcceptedIssuers(true).build();
		assertThat(certificateVerifier.getAcceptedIssuers().isEmpty(), is(true));
	}

	@Test
	public void testAcceptedIssuers() {
		NewAdvancedCertificateVerifier certificateVerifier = StaticNewAdvancedCertificateVerifier.builder()
				.setTrustedCertificates(trusts).build();
		assertThat(certificateVerifier.getAcceptedIssuers().size(), is(issuers.size()));
	}

}
