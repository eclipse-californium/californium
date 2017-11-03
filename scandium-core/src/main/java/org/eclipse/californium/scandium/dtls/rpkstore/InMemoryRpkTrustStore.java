/*******************************************************************************
 * Copyright (c) 2017 RISE SICS.
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
 *    Ludwig Seitz (RISE SICS) - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.rpkstore;

import java.util.HashSet;
import java.util.Set;

import org.eclipse.californium.scandium.auth.RawPublicKeyIdentity;

/**
 * A raw public key store that stores the trusted keys in memory.
 * 
 * @author Ludwig Seitz
 *
 */
public class InMemoryRpkTrustStore implements TrustedRpkStore {

	private final Set<RawPublicKeyIdentity> trustedRPKs;

	/**
	 * Constructor.
	 * 
	 * @param trustedRPKS the list of raw public key identities that are trusted
	 */
	public InMemoryRpkTrustStore(Set<RawPublicKeyIdentity> trustedRPKS) {
		this.trustedRPKs = new HashSet<>();
		this.trustedRPKs.addAll(trustedRPKS);
	}

	@Override
	public boolean isTrusted(RawPublicKeyIdentity id) {
		return this.trustedRPKs.contains(id);
	}

}
